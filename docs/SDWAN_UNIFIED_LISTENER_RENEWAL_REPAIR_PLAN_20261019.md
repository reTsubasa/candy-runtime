# SD-WAN Unified Listener and Renewal Repair Plan

Date: 2026-10-19

Status: implementation plan, based on the user's decision that there are no
active users and old-version compatibility is not required. The new runtime,
Core, signed configuration and deployment may adopt one coordinated contract.

## Goal

Make every SD-WAN renewal and worker replacement follow one Nginx-style path:

1. Keep the stable Transport Listener Master and TUN infrastructure running.
2. Validate and start the successor worker without replacing the active worker.
3. Prove the successor is ready to receive authenticated traffic.
4. Atomically route new sessions/lanes to the successor.
5. Drain existing sessions and flows on the predecessor.
6. Reap only the exact predecessor worker after drain completion or a bounded
   drain deadline.

No Core or Runtime compatibility fallback to stop-old/start-new is required.
The service must preserve the last valid worker and TUN path when preparation,
reservation or commit is rejected or has an unknown result.

## Findings and Root Cause

### Confirmed

- The old renewal path rejected an active dedicated outbound worker because it
  could not establish local overlap. The preserved `renewal-order-fix-smoke-v2`
  log records `renewal_make_before_break_required` with
  `dedicated_outbound_worker_has_no_authenticated_overlap`.
- Runtime was changed to route any active owner through negotiated MBB, and to
  activate the successor before asking the predecessor to drain. Runtime Agent
  tests pass 111/111. This verifies the local branch and helper behavior only.
- Core's candidate reservation code requires the signed peer activation to
  declare `shared_listener = true`. This check is intentional: the peer must
  have a listener capable of accepting and routing the staged successor.
- The renewal test harness uses a plain signed server helper and a client peer
  configuration without `shared_listener = true`. It does not start/register a
  listener master and its worker. Thus the present fixture cannot validate the
  negotiated listener protocol.
- The first `renewal-mbb-fix-smoke-v1` did not start: its build directory lacked
  `binary-hashes.json`. The v2 smoke ran traffic, and its `client-agent.log`
  directly records repeated `candidate_shared_listener_required` failures
  during renewal reconciliation, followed by `signed renewal commit/readiness
  timeout`; the later `control socket has closed unexpectedly` occurred during
  runner cleanup. Thus v2 did hit the Core guard, but it still does not exercise
  candidate readiness, activation or drain.
- The Core guard must not simply be removed. Without a registered candidate
  receiver, removing it would move the failure later and could misrepresent an
  unsupported peer as MBB-capable.

### Root cause

The system has two incompatible assumptions. Runtime now requires negotiated
MBB for every active-owner replacement, while the Core candidate protocol only
supports a peer that advertises and actually runs the shared-listener candidate
service. The test topology still uses the old plain server helper. As a result,
the code path that should prove end-to-end renewal has no valid remote candidate
receiver. The old stop/start behavior was removed from the active-owner path,
but the required unified listener architecture is not yet wired end to end.

The product defect is an incomplete architecture transition. The harness gap
prevents acceptance, and does not by itself prove a separate data-plane defect.

## Target Architecture

```text
procd/systemd
  +-- Runtime Agent: signed config, renewal transaction, worker registry,
  |                  readiness/commit/drain/reap coordinator
  +-- Transport Listener Master: stable UDP/QUIC/TLS endpoint, admission,
  |                              authenticated connection ownership,
  |                              worker routing and drain notifications
  |     +-- SD-WAN worker pool: N horizontally scalable workers
  |     +-- Proxy worker pool: separate role and resource budget
  +-- netd + TUNIO: stable SD-WAN infrastructure, independent of worker life
```

The Listener Master is the only public transport listener. All SD-WAN server
attachments participating in renewal are registered behind it. A worker never
binds the public endpoint itself. Candidate registration, routing selectors,
worker identity and signed activation metadata must all name the same master
incarnation and listener pool.

Runtime Agent owns SD-WAN worker lifecycle and coordinates the durable renewal
transaction. The Listener Master owns transport connections and routes new
sessions to the committed worker generation. It does not own Cloud sync or
renewal policy. Proxy and SD-WAN remain separate worker roles. netd/TUNIO own
the TUN fd, interface, base routes and PacketPort fencing; they are not restarted
or duplicated when SD-WAN workers scale or renew.

## New Contract

Because old-version compatibility is not a requirement, implement one strict
configuration and deployment contract:

- Every serving SD-WAN endpoint starts under the Listener Master. Standalone
  public server workers are invalid configuration.
- Every signed peer eligible for negotiated renewal advertises the candidate
  shared-listener capability. The declaration is backed by a registered,
  live master/worker service, not just a TOML boolean.
- Runtime startup preflight verifies the Core/Runtime protocol versions,
  listener registration, candidate capability, worker limits, and stable
  TUNIO/netd identity before accepting the plan.
- Missing or inconsistent capability is a hard preflight rejection before
  changing forwarding or stopping any process. There is no legacy fallback.
- Signed config is versioned as a single release contract. If its required
  listener capability is absent, report an actionable error and keep the
  existing valid service state; do not infer support.

## Renewal Transaction

Persist the original signed snapshot/hash, transaction ID, authority revision,
old and candidate worker identities, exact peer selectors, original monotonic
authorization/drain deadlines, TUNIO binding, listener master incarnation and
all participant receipts before the first operation that may become effective.

1. **Validate:** verify signed policy, fresh Grant, peer listener capability,
   listener incarnation, worker/resource quotas, and unchanged TUN infrastructure.
2. **Reserve:** ask the remote registered listener to reserve the exact
   successor selector on the authenticated peer. Reservation is idempotent and
   bound to the old lane, new generation and original fixed deadline.
3. **Prepare:** start successor workers and candidate lanes. Keep old workers,
   old PacketPort owner and old session routing active. Candidate may perform
   authenticated readiness probes but cannot receive ordinary new sessions.
4. **Ready:** require exact process identity, master registration ACK, peer
   Installed receipt, bidirectional probe and TUNIO Prepare receipt. Files,
   timestamps or process liveness alone are not readiness proof.
5. **Commit:** fsync a single immutable commit intent. Commit the TUNIO owner
   and listener routing snapshot with the same generation/fence. New sessions
   go to the successor only after exact commit receipts are confirmed.
6. **Drain:** send explicit drain/GOAWAY to the predecessor. Reject new
   sessions on its existing QUIC connection while allowing established streams
   and flows to complete. Require bilateral exact drain receipts.
7. **Reap:** after drain completion, or the original bounded deadline, stop the
   exact predecessor PID/start_ticks/epoch and retire only its domain owner.
   Preserve the Listener Master, other workers, TUNIO and netd.
8. **Finalize:** persist terminal outcome (`drained` or `failed_drain_preserved`),
   release reservations/credits and publish the committed generation.

Commit timeout or lost acknowledgement is UNKNOWN. Query and retry only the
same transaction; do not abort, increment the fence, start a replacement
transaction, or retire either owner based on timeout alone. Before commit,
candidate failure removes only the candidate. After commit, failure recovery
retains the committed successor and performs bounded peer redial; it never
reinstates the predecessor by stale receipt.

## Required Implementation Work

### P0: Make listener registration authoritative

- Define one versioned registration/receipt containing master incarnation,
  role, domain, listener/pool ID, candidate selector, worker ID/epoch,
  PID/start_ticks, plan hash and capability set.
- Make registration ACK come from the live master after atomic in-memory
  registry activation. A file write is only pending intent, not activation.
- Reject stale master incarnation, duplicate ownership, missing candidate
  service, mismatched peer selector and old protocol version during preflight.
- Add a negative test proving a plain standalone server is rejected before
  the current worker or forwarding owner changes.

### P0: Complete Runtime-to-Core MBB wiring

- Keep the active-owner renewal branch on negotiated MBB; remove any
  stop-old/start-new fallback from active-owner replacement.
- Pass the exact candidate selector from signed policy through Runtime,
  Listener Master and Core; use the existing Core reservation guard as an
  enforced contract.
- Ensure Core stages the successor without replacing the predecessor lane.
- Persist receipts and commit intent through restart; resolve uncertain replies
  by querying exact transaction state.
- Keep successor activation before predecessor drain. The ordering change is
  not accepted until the live integration test reaches and proves both steps.

### P0: Add an actual signed-renewal E2E topology

- Build a clean artifact freeze with six binaries, hashes, source revisions and
  harness hashes. The harness must fail before test start if any artifact is
  absent or mismatched.
- Start a real server Listener Master and registered SD-WAN worker using the
  signed inbound config. Configure the client peer with the matching signed
  shared-listener capability and selector.
- Run continuous bidirectional TCP and UDP traffic through a real Runtime Agent,
  Core, TUNIO, netd and the signed fixture. Trigger renewal through the same
  signed authority path used by Runtime.
- Assert exact event ordering: reserve, candidate registered, peer installed,
  TUNIO prepared, commit intent, owner commit, listener route commit, successor
  receives new sessions, predecessor drain, predecessor reap, terminal journal.
- Assert TUNIO PID/start_ticks, TUN ifindex, infra ID/generation and listener
  master incarnation do not change. Assert no missing/duplicate payloads for
  the uninterrupted test stream and report bounded loss/retry separately for
  injected failures.

### P1: Self-recovery and resource isolation

- Add bounded exponential retry with jitter for precommit transient failures;
  stop retrying the same permanent capability mismatch and publish a stable
  terminal error until config changes.
- Deduplicate repeated error logs by transaction and phase while retaining
  counters and the last detailed cause.
- Inject listener restart, candidate death, lost Prepare/Commit ACK, peer loss,
  full worker quota and drain deadline expiry. Verify no stale generation
  steals ownership and only the affected worker/domain is contained.
- Verify Proxy continues service while SD-WAN retries, and TUNIO/netd continue
  while all SD-WAN business workers are replaced. No supervisor may compete to
  restart another layer's process.

## Test and Release Gates

| Gate | Required evidence | Pass condition |
| --- | --- | --- |
| Contract/config | valid unified config; missing capability; stale master; protocol mismatch | Valid config passes; invalid cases reject before changing active owner |
| MBB renewal | real signed Runtime renewal with registered listener master/worker | exact protocol receipts and expected event order; no TUN/master restart |
| Traffic continuity | bidirectional long-lived TCP, UDP request/response and new-session probes during renewal | no permanent stall; existing flows drain; new flows select successor |
| Failure recovery | candidate crash, listener restart, lost ACK, peer outage, drain timeout | old owner survives precommit; committed owner remains authoritative; recovery is bounded |
| Isolation | concurrent Proxy traffic and unaffected SD-WAN domain | unrelated role/domain remains healthy; TUN infra identity unchanged |
| Scale | same domain worker pool 1/2/4/2/1 with traffic and renewal | exact ownership, no duplicate TUN reader, all transitions have receipts and no unexplained loss |
| Stability | 20-minute run with repeated signed renewals; two-hour test remains excluded by user decision | no unbounded resource/log growth, no stale worker, no renewal deadline miss |
| Build/release | clean source freeze, target architecture builds, tests, signed central release | exact tested hashes are the released hashes; deployment preflight passes |

Do not use throughput as the blocker for this reliability repair. Capture
goodput, CPU and latency as diagnostics, but first require correct payload,
bounded recovery, no ownership ambiguity and no infrastructure restart. The
two-hour soak remains explicitly out of scope for this plan.

## Expected Effect

- Active SD-WAN traffic no longer depends on whether a worker can bind a
  dedicated endpoint. The stable Listener Master handles public connections;
  workers can overlap safely behind it.
- A valid renewal starts and proves its successor before switching new work.
  Existing sessions keep their predecessor until drain or the fixed timeout.
- A bad candidate, stale peer, lost ACK or full quota does not stop the current
  forwarding owner, Proxy role, Listener Master, TUNIO or netd.
- Configuration and deployment become simpler: one Core/Runtime contract and
  one listener topology, with no legacy stop/start branch or ambiguous support
  mode.
- The current smoke can become a real acceptance gate rather than timing out
  before candidate readiness. The present 111/111 unit-test result remains
  useful but is not represented as end-to-end MBB acceptance.

## Current State and Exit Criteria

### Implemented in the current working tree

- Runtime still routes active-owner replacement through negotiated MBB and
  activates the candidate before requesting predecessor drain.
- Runtime retry classification now treats stable signed/deployment contract
  errors (`candidate_shared_listener_required`, mismatched candidate grant,
  stale listener master/activation) as non-retryable for the unchanged plan.
  It preserves the current owner and waits for a new plan fingerprint instead
  of repeatedly reconciling the same impossible transaction. A regression test
  covers the wrapped `ManagedProofPending` case.
- Runtime Agent feature suite passes 111/111.

### Still required

The latest ARM64 renewal smoke transferred traffic but did not complete
renewal. Its test topology lacks the registered listener service required by
Core's reservation protocol. Building the real Listener Master + registered
SD-WAN worker topology and wiring the signed renewal E2E remain the P0 blockers.
The stable-error change above is containment, not MBB acceptance. No commit,
release or production deployment has been performed for this work.

This repair is complete only when P0 gates pass on one coherent frozen build,
the P1 failure gates show bounded recovery and isolation, and the release
contains those exact tested binaries. The prior smoke failure must remain in
the evidence history and must not be relabeled as a pass.
