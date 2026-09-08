# Reliability repair plan, 2026-09-08

This is an implementation checklist, not a production acceptance report.
Priority describes user impact: P0 traffic interruption; P1 recovery/control
correctness; P2 diagnostics and delivery gates; P3 documentation/maintenance.
Items are checked only after the corresponding focused regression passes.

## Completed preparation

- [x] Verify no active builds and no tracked files in the cleanup targets.
- [x] Remove only Core `target`, Core `fuzz/target`, Runtime `target`, and
  Cloud `target`: approximately 38.9 GiB of reproducible build caches.
  Source, vendor, toolchains, release artifacts, databases and credentials remain.
- [x] Recheck review assertions against current source before changing behavior.

## Repair and acceptance checklist

| ID | Priority | Observed problem / scope | Repair and acceptance |
| --- | --- | --- | --- |
| R01 | P0 | Core fail-open latch survives partial route-owner recovery | **Done:** failed-owner coverage is tracked; regression covers healthy alternate owner, recovery and re-failure. |
| R02 | P0 | Policy replacement closes old Peer streams before new streams are usable | **Partially implemented:** production inbound/outbound handoff now completes both packet-stream halves before registration/replacement. Failed or cancelled preparation closes the candidate. Core regression proves old-lane traffic during preparation and usable new lane at commit. Cross-node commit coordination and old-lane drain remain open. |
| R03 | P0 | Runtime suspends old forwarding before policy replacement | **Locally staged:** Core Prepare/Commit/Abort now separates candidate negotiation from local cutover. Runtime keeps local steering during preparation, renews leases while waiting, rechecks immutable candidate binding and reconciles lost Commit replies. Fault injection passes. Cross-node commit, dual-generation netd steering and existing NAT/TCP flow migration remain open. |
| R04 | P1 | Partial route readiness can trigger global Runtime fallback | **Improved:** committed all-peer loss is now recoverable even while Core reports `lifecycle=active`; Runtime suspends SD-WAN steering, preserves Core dialers, records counters/error detail, and retries reconnect. Per-route partial coverage and fatal Core/TUN errors still require separate handling tests. |
| R05 | P1 | Cloud status reader rejects persisted `PREPARED` receipt | **Done:** API accepts all three persisted states; DB-backed regression is present (requires `DATABASE_URL`). |
| R06 | P1 | Segment aggregate failure/update colors unrelated links | **Done:** link state uses peer endpoints/attachments; three-site isolation tests pass. |
| R07 | P1 | Offline rejected nodes/sites remain red | **Done:** freshness/online classification precedes faults; stale rejected node/site/link tests pass. |
| R08 | P1 | Path presence can falsely imply Stream readiness | **Done:** stream paths require ready streams; legacy reports use conservative route readiness. |
| R09 | P2 | Core packet/stream failure causes are lost or cleared too early | **Implemented:** bounded drop/error and retired-path history telemetry; transport integration still required. |
| R10 | P2 | Runtime clears all path diagnostics while steering is suspended | **Done:** path evidence is preserved with explicit `forwarding_active`; Cloud distinguishes inactive forwarding. |
| R11 | P2 | Runtime preflight greps private Core source and fails on valid formatting | **Done:** structured manifest contract and isolated checkout/malformed JSON tests integrated into verification. |
| R12 | P2 | Core manifest test hardcodes an obsolete package version | **Done:** compile-time package version assertion passes. |
| R13 | P2 | Local DB tests may silently skip and socket tests fail under sandbox | **Socket suite verified:** Runtime agent tests pass 39/39 and Core SD-WAN real loopback tests pass 22/22 with scoped socket permission. Actual MySQL-backed receipt validation remains open; do not treat an omitted database test as passed. |
| R14 | P2 | Runtime test fixture writes into real `/etc/candy` | **Done:** lifecycle fixture paths are redirected into temporary state roots. |
| R15 | P2 | Core Action can build production Core; Cloud release pins duplicate versions | **Done:** Core build workflow removed; Cloud x86/ARM64 inputs reference published `core-v0.3.42`. |
| R16 | P3 | Release/platform docs contradict actual targets and signing ownership | **Done:** Core/Cloud docs and matrix describe current five-target and signing boundary. |
| R17 | P3 | Design docs imply unimplemented multi-stream/telemetry behavior | Record current implementation limits and remaining dynamic multi-stream/observability work; do not call default counters or plans completed features. |

## Verification and rollout gates

- [x] Core focused routing/manifest tests; Core workspace check passes. Real
  loopback transport tests remain environment-gated and were not claimed.
- [x] Runtime manifest, isolated preflight/init and cloud-sync telemetry tests;
  Runtime workspace check passes. The aggregate upgrade script remains
  environment-sensitive on this host and is not treated as a product failure.
- [x] Cloud state/topology tests (47/47), typecheck/build and Cloud workspace
  check pass. Actual MySQL receipt execution remains a separate deployment gate.
- [x] Release-contract tests, formatting and `git diff --check` pass in all
  modified repositories.
- [x] Re-review the combined Core/Runtime hot-switch contract and record the
  remaining cross-node zero-loss and multi-stream risks below.
- [ ] Separately authorized commit, local Core candidate build, release signing,
  Cloud/Runtime Actions and node update. None has been performed by this checklist.

Use `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`
for local regression builds to limit cache growth. Build outputs must not be
removed while any verification or packaging process is using them.

## Non-findings and limits

- A loopback socket denied by the sandbox is not proof of a production bug.
- A database test returning early without `DATABASE_URL` is not a passed DB test.
- The multi-Peer Core translates low-level Stream failures to recognized recovery
  codes; indiscriminately extending a Runtime error whitelist is unsafe.
- No live-node load test, remote release inspection or deployment is implied by
  a passing source test. A fixed 30-minute traffic gate is not required here.
- Multi-Segment runtime support and multiple independently scaled streams per
  Peer need contract evidence before any compatibility/schema expansion.

## Runtime follow-up findings (2026-09-08)

- **P1 fixed:** `candy-sdwan-agent` previously treated an `active` Core status
  with `fail_open_required=true`, zero ready route owners, and a known
  all-peer-loss code as fatal. Under sustained traffic this caused repeated
  Core teardown and the observed `all_peer_lanes_unavailable` recovery loop.
  It is now classified as `RecoverablePeerLoss`; Core remains alive while
  steering is suspended and reconnect evidence is logged.
- **P2 fixed:** Broken netd IPC (`BrokenPipe`, `ConnectionReset`, or
  `UnexpectedEof`) now has the explicit `netd_reconfigure_peer_closed` code so
  Cloud does not display the generic/unknown error. The transaction layer still
  reconciles status before retrying the signed generation.
- **P2 open:** The LuCI process helper uses a bounded pipe capture and closes
  descriptors correctly; no reproducible Broken pipe remains in Runtime code.
  A real-device repro is still needed to validate the external `candy-client`
  helper and netd daemon restart race.
- **P0 open:** Hot replacement still suspends old steering before replacement
  readiness; true make-before-break/NAT-preserving migration needs a Core/netd
  protocol change and cross-node traffic evidence.

## Remaining P0-P2 execution list

| Priority | Remaining work | Next implementation gate |
| --- | --- | --- |
| P0 | Make-before-break policy cutover with old/new stream overlap and bounded drain | Core staged lane transaction, netd dual-generation owner, fault-injection test proving old lane remains usable until replacement `stream_ready`; then real two-node traffic test |
| P0 | Preserve established TCP/NAT state across egress switch | netd connection/NAT ownership design and packet-flow test; cannot be inferred from process hot reload |
| P1 | Handle clean EOF, task panic and cancellation as typed peer events | Core loopback EOF/dialer-wakeup and task identity/panic/cancel tests pass; events retire only the matching connection. Live Cloud/Runtime fault-injection remains separate. |
| P1 | Scope partial route loss to affected prefix/peer | per-route readiness and fallback tests with one healthy unrelated route |
| P1 | End-to-end Cloud/Core/Runtime event convergence | signed generation plus event-id/sequence contract and integration test |
| P2 | Multiple independently recoverable Streams per Peer | stream slot lifecycle contract, bounded scheduler, per-stream telemetry and backpressure tests |
| P2 | Actual MySQL receipt regression and loopback QUIC suite | CI database job and permissioned network runner; local skip must remain visible |
| P2 | OpenWrt helper/netd restart race | device reproduction with netd restart during reconfigure; verify retry code and no stale owner |

## Follow-up verification and corrections

- **P0 fixed in source:** policy replacement recreated the packet pump with TX
  sequence 1 even when the authenticated QUIC connection remained installed.
  An unchanged receiver could therefore reject fresh traffic as replay. The new
  pump inherits TX sequence (including exhaustion) for the same local attachment
  epoch. Retained connections keep RX replay windows; newly authenticated
  connections get fresh RX windows. Changed identity or incompatible replay
  limits reject the replacement before mutating the live supervisor.
- **P1 fixed in source:** duplicate delivery of the same Peer connection no
  longer closes that connection or resets its replay state.
- **P1 corrected:** the previous `peer_stream_task_failed` implementation set a
  transient global status without retiring the failed connection. JoinSet now
  carries attachment and stable connection identity into the existing failure
  handler, which records path evidence and closes only the matching connection
  to wake the dialer. Shutdown cancellation is explicitly drained. EOF uses a
  typed `UnexpectedEof` error, including partial-frame context.
- **Validation:** 21 SD-WAN tests passed with real local QUIC sockets, including
  4096 frames in each direction, backpressure, final-peer reconnection, EOF and
  panic/cancellation, same-generation reuse and unready candidate rejection.
  The transport truncated-frame regression and the complete
  `candy-tun` suite passed; its 15 routing tests include reload sequence/replay
  continuity and failed-replacement isolation. Cloud error/audit/topology tests
  passed 30/30. Core and Runtime workspace checks passed.
- Earlier sandbox failures were environment restrictions; once socket access
  was allowed, several old fixtures also needed correction: they waited for
  readiness before negotiating streams, or treated `stream_ready` as data.
  The corrected tests pass; they were not merely waived as environment failures.
- Runtime commit `21edaa2` did **not** implement per-prefix fallback: retaining
  netd steering without withdrawing failed prefixes could blackhole traffic.
  `368df06` restored safe existing fallback. R04's per-prefix work stays open.
- **Still open:** R02/R03 make-before-break, bounded old-lane drain and netd
  staged ownership; established flow handling across different public egress
  addresses; end-to-end live fault-event convergence. None of these is proven
  by the local replay fix or a successful compile. No node update was performed.

## Candidate preparation and netd rollback follow-up

- The production `open_sdwan_peer` path and inbound accepted-tunnel handler
  now negotiate both IP Packet Stream halves before handing the candidate to
  the live supervisor. A prepared candidate binds its stream to the exact
  QUIC connection and tunnel ID; a closed or mismatched candidate is rejected
  before live policy mutation. Replacing an existing lane without a prepared
  stream is rejected even when partial topology is otherwise allowed.
- A cancellation guard closes abandoned candidates, including during timeout
  or stream identity failure. The old routing actor continues processing packets
  while preparation runs in the caller's asynchronous task.
- Real QUIC regression: SD-WAN tests pass 22/22, including old-lane traffic while
  withholding the new peer's header, successful immediate traffic after commit,
  cancellation and mismatched identity. These are local packet-loop assertions,
  not proof that Runtime currently keeps host steering active during preparation.
  Core process entry/configuration tests pass 18/18; Core and Runtime workspace
  checks pass. Preparation start/success/rejection logs identify the attachment,
  tunnel, connection, duration and failure code.
- netd's old-rule removal was outside its restore-on-error block. A partially
  failing firewall/route removal could leave the old declaration in the journal
  but not installed in the kernel. Removal now participates in the same rollback
  path as candidate installation. Network transaction tests pass 10/10, including
  both removal failure points, restoration ordering and retained owner/journal.
- **Remaining P0 boundary:** Runtime still suspends steering before requesting
  Core replacement. netd dual-generation ownership, coordinated two-peer commit,
  old queued packet drain and established NAT/TCP flow handling are not completed
  by this patch. Reconfiguration rollback failure itself still needs durable
  recovery intent to prevent a premature resume. No release or node update.

## Local two-phase Core policy transaction

- Core accepts `prepare`, `commit` and `abort` with a random 32-byte hex
  transaction ID. Preparation is bounded to 20 seconds and the prepared
  candidate expires after 30 seconds. An unrelated ID cannot consume or abort
  another candidate; a changed base generation or expired candidate cannot
  commit. Both successful and failed commit outcomes are cached until the next
  commit, so a lost reply cannot apply a policy twice.
- Runtime negotiates the candidate before suspending local steering. Candidate
  files, descriptor hashes and publication pointer are checked after preparation,
  after netd reconfiguration and before resuming traffic. Preparation failure
  does not suspend or reconfigure netd. Pre-commit rollback restores only netd;
  it does not redial the still-installed old Core policy. An unresolved Commit
  keeps the candidate eligible for confirmation/recovery rather than publishing
  a false rejection or attempting a lower-generation Core reload.
- IPC response reads are bounded and preserve partial replies while allowing
  lease-renewal callbacks. Preparation, commit, suspend/resume and readiness
  waits renew netd ownership. The agent's main recovery loop renews before any
  early-continue branch, avoiding lease starvation during transient failures.
  Abandoned preparation is cancelled best-effort without another blocking wait.
- Cloud describes `core_policy_prepare_failed`, `core_policy_commit_unresolved`
  and `netd_lease_renewal_failed` explicitly. Core transaction events carry the
  transaction ID and preparation/commit result; Runtime logs the local steering
  state and concrete failure detail.
- Verification: Core process tests 22/22, real QUIC SD-WAN tests 22/22, Runtime
  agent tests 39/39 and Cloud error descriptor tests 5/5 pass. Core/Runtime
  workspace checks and Cloud TypeScript checking pass. The new fault tests
  cover preparation failure, changed candidate, lost/unknown commit reply,
  partial response reads, wrong transaction IDs and expired candidates.
- **Boundary:** preparation is local, not a two-node commit protocol. Remote
  inbound registration may still replace its old lane before the caller commits;
  signed inbound expectations may still need post-commit convergence. Old-lane
  drain, dual-generation routing and existing-flow NAT ownership are unfinished.
  These remain P0 work. New Runtime requires a Core with this API for hot updates;
  older Core rejects Prepare safely rather than silently reverting to destructive
  Replace. No release upload, remote push or node update was performed here.

## Durable netd recovery and latest-activation retry

- Before mutating kernel rules, netd persists a `RollingBack` record with both
  the old declaration and the candidate requiring cleanup. Only a fully restored
  old configuration may return to `Suspended`. An incomplete rollback cannot
  Resume and is recovered even while its former owner is alive.
- Crash recovery removes both sets of routes/firewall rules. Candidate cleanup
  failure retains its journal intent even when every old cleanup step is already
  complete. Existing v1 journals remain readable; transient recovery records use
  v2. A downgrade must complete recovery with the new netd first, since an older
  binary cannot decode the new recovery record.
- Reconfiguration rejects changes to table ID, overlay address, MTU or firewall
  ownership parameters whose link effects cannot be undone by this in-place
  transaction. These require a fresh network session; this is not support for
  hot migration of link identity.
- Runtime treats an incomplete netd rollback as cleanup/retry of the desired
  activation, not a permanent rejection. Retryable failures now carry the latest
  activation from `run_once`; the outer loop previously used its original launch
  configuration and could stop retrying after a successful hot update.
- Validation: the full netd suite passes 27/27, including 14 transaction, 2
  file-journal, 3 service and 4 socket-security tests. Tests verify poisoned
  session rejection, crash recovery of both declarations, repeated cleanup
  failure and successful restoration. Linux-only backend tests run zero cases
  on this macOS host; actual nft/netlink fault injection remains unverified.
