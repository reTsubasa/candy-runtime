# Short Reliability Gates, 2026-10-16

The user selected short gates and blocking fixes before the two-hour renewal
soak. All operations in this iteration use isolated Linux containers. No
production node, listener, release, signature, or deployment is changed.
Throughput optimization and physical-platform acceptance remain separate.

## Blocking Fixes

| Commit | Defect and correction | Evidence boundary |
| --- | --- | --- |
| Runtime `a69c047` | Shared business control wrapped typed EAGAIN in an opaque IO error, causing `retry=false`. Preserve the original error chain and inspect typed nested IO causes. | Native focused tests; frozen Linux Agent serial suite 138/138, including actual socket timeout. |
| Runtime `b6ab287`, `b75d6f5` | Initial or active proof timeout reached unconditional Core/TUNIO cleanup. Bound retries to the original owner and authorization, preserve uncertain valid ownership for reconciliation; confirmed exit and expired authorization retain their distinct recovery paths. | Focused tests 3/3; frozen Linux Agent serial suite 138/138. Strict scaling acceptance still required. |
| Runtime `1320ac1` | Fixture treated a bootstrap recovery epoch as evidence of an MBB transaction. Require exact bilateral drain for an actual owner change relative to the previous scale snapshot. | Focused helper test; final scale assertions remain required. |
| Runtime `9bac61e` | Expired terminal transactions and proven-dead committed owners could prevent recovery indefinitely. Retire only exact durable receipts and confirmed isolated owners; UNKNOWN remains fenced. | Earlier Linux Agent 132/132 and TUNIO 26/26; integrated frozen gates remain required. |
| Core `634909d`, `d4a46bc`, `99a06ea` | Expired successor cache entries retained slots. Release memory only when durable anti-rollback evidence exists; preserve uncertain or sole memory fences. | Linux exact successor-expiry test 1/1. |
| Core `f614282` | Candidate journal directory traversal allocated every entry before applying limits. Stream entries within a bounded scan budget and return a typed incomplete-scan error; exact prior receipts remain usable. | Linux exact overflow/isolation test 1/1. |
| Runtime `c9e62e0` | A parallel test fork could inherit an unrelated Unix listener before exec, invalidating an immediate endpoint-close assumption. Use an isolated helper that owns the endpoint, then prove its exit. | Native full suite 104/104; Linux follow-up required. No production ownership change. |

## Preserved Failures

The earlier strict shared-pool v6 startup failure, v7 drain-observation race,
v8 missing metadata, and v8b/v9 initial convergence failures remain failed
evidence. See `SDWAN_DYNAMIC_SCALING_FAILURE_REVIEW_20261016.md`. Component
tests do not replace strict continuous-traffic scale acceptance.

Frozen source v10 uses Core `f614282` and Runtime `b75d6f5`, manifest
`10dc782c7c0f51023d7c86e2c89f193267fb6c7b8e980d352ddf4a185cdf5d39`.
The first parallel Linux Agent run failed 1/138 after dropping its test listener;
the unchanged serial run passed 138/138. A Linux fork reproducer confirmed that
CLOEXEC does not prevent the pre-exec child from retaining that listener. Both
test logs are retained under `artifacts/sdwan-20261016/registered-mbb-source-v10/`.

The initial release build `registered-mbb-release-v10` failed because the default
builder image was unavailable, before product compilation. The replacement
`registered-mbb-release-v10b` uses the installed runner image; its recorded source
manifest is `dd45daca428c0bf0328c040e625bb2a7e6d54668700f5c6b9f2c3463c4ffb2e5`.
Its release build and integration result must be read separately from v10's
debug/test artifacts.

### Frozen Release v10b Results

The six release artifacts built successfully. The Core ELF SHA-256 is
`02ca0009e2397c690c102552b8a892bba169c51b5b1b8387e9be2d463a78d249`.
These results use that immutable set, not subsequent source edits:

| Evidence directory | Result | Interpretation |
| --- | --- | --- |
| `shared-pool-negotiated-final-v10` | FAIL, 62.49 s | Scale to two workers does not converge. Candidate journals show installed/probed/drained, but repeated netd finalize calls can change the same owner's deadline and replay consumed fences. Fix and fresh gate required. |
| `successor-server-restart-v10` | FAIL, 60.91 s | Test compared the retained IO record against the pre-injection worker epoch. Exact PID/start time/inode/binding/authorization/IO epoch are unchanged; the deliberately killed Core recovered once and updated IO's worker epoch. Runtime `13f8c35` corrects the baseline and adds full Core-record stability assertions. Fresh gate required. |
| `shared-host-lifecycle-v10` | PASS, 2.64 s | Selected frozen shared-host lifecycle fixture only. |
| `mixed-listener-two-domain-v10` | PASS, 17.60 s | Two domains, real ICMP and Proxy HTTP, exact activation ACK, worker recovery, two master restarts, preserved TUNIO/domain workers, and no live orphan workers. |
| `proxy-release-v10-active-drain-v1` | PASS | Runtime Rust client held TCP tail/FIN, UDP/DNS, negotiated active-session drain and replacement admission. No full release acceptance implied. |

The restart failure does not prove a production TUNIO replacement. Ordinary
redials rejected while an existing attachment remains authoritative retain
the active-owner fence. No bypass of that fence is included in the test fix.

## Proxy UDP Findings

`proxy-frozen-v6-reliability-v1` remains FAIL. It uses the Runtime Rust client
and Core SHA-256
`97d4ca1829f47bcc68abc639f0648e800e809cc635427a1566950fc477f0137c`.
TCP/UDP basic compatibility, worker recovery (1.164 s), negotiated drain,
admission exhaustion/recovery, worker distribution, and logging backpressure
passed their measured subsets. The ordinary 1200-byte rate cohort lost 20/300
packets: 15 did not reach the echo target and 5 lacked a return. Scheduling
violations occurred concurrently; their presence does not exclude a product
fault. This run does not include the focused DNS drain gate.

`proxy-frozen-v6-udp-v2` remains FAIL with disjoint CPU affinity and no CFS quota.
All four ordinary cohorts (64/512/1200/4096 bytes, 300 each) passed exactly.
After the explicit 4096-packet overload, the original recovery cohort lost
9/300 packets and had 100 generator scheduling violations. Process identities
were unchanged. Kernel UDP receive-buffer errors increased by 2370 on the
client and 24 on the server across the complete test, including the deliberate
burst. Aggregate counters cannot attribute those nine recovery losses to one
socket or stage. Independent scheduling witnesses also observed overlapping
pauses. Root cause and a valid complete UDP recovery pass remain open.

`f262ed3` adds a focused UDP-only runner with kernel/socket/queue observations.
`f1afaac` retains the unchanged one-second recovery criterion and adds a later
health observation only after a failure. A later pass cannot overwrite the
original recovery failure. No packet-loss or scheduling threshold is relaxed.

`proxy-release-v10-udp-v3` retains FAIL: all six cohorts returned 300/300,
but the first pacer correction accumulated ordinary sleep jitter and made
every cohort's nominal schedule invalid. Runtime `f46b97b` and `54f1afb`
correct and test this harness defect. A long pause or oversleep rebases once,
short jitter permits at most twice the nominal pacing rate, and original
nominal lateness and rebases still fail the load-validity gate. The receiver
observes one second after actual sender completion within a bounded total
window. Idle target logging flushes without waiting for another packet.

`proxy-release-v10-udp-v4` also retains FAIL. All five cohorts returned exactly
300/300 with no loss. Ordinary 512/1200/4096-byte and one-second-after-overload
1200-byte recovery cohorts have valid schedules and pass. Ordinary 64-byte
load had one schedule rebase and remains invalid, so the complete gate fails.
This supports recovery of this frozen build in that measured cohort, not a
claim that all earlier packet loss was environmental or that UDP is accepted.

Core `44b8838` separately repairs demonstrated IPC coupling: ACK and Data
queues are independently bounded; ACK has writer priority and bounded enqueue;
QUIC receive does not wait for byte credits. Full queues and unavailable credit
now emit rate-limited structured drop summaries. Native IPC tests 14/14 and
strict transport Clippy pass. Finite UDP dropping remains intentional. This
commit is not in frozen v10b and needs fresh Linux regression. Relative-deadline
extension remains a separate issue until its fix and tests complete.

## Remaining Acceptance

- Vanished-actor UNKNOWN retirement: durable exact actor/domain completion,
  actual master revocation, authenticated bilateral confirmation, and a distinct
  durable terminal before any fresh transaction. Foundations do not close it.
- The real QUIC/Unix IPC control-pressure short gates pass on frozen v16,
  including control-credit renewal and a genuine queue burst. This does not
  establish maximum throughput or Go-client interoperability.
- Reconciliation and domain-evidence Linux checks and affected traffic gates
  pass as recorded below. Vanished-actor automatic retirement remains separate.
- The latest strict scaling, activated-successor restart, mixed-role,
  Proxy UDP and negotiated-drain results are in the v16 table below. Earlier
  failures remain retained; the passing subsets are not full release acceptance.
- Two-hour renewal is deferred by the user's explicit choice. Performance and
  platform package acceptance are not claimed by short container gates.

## Frozen Release v11 Follow-up

The six release artifacts built successfully from Core `ce874e7` and Runtime
`5a2e8d3`, source manifest
`959a5cebd070a56cbf024dfca62d37746edea4cdf7cc7d762dde24af05f05b64`.
Core ELF SHA-256 is
`f0c8d7c851126ed2bc9442c65394a9be7e1168ed0790b00782c516f456aaa94e`.
The IPC v2 build is verified on Linux; native transport IPC tests 20/20 and
strict transport Clippy passed before freezing.

| Evidence directory | Result | Boundary |
| --- | --- | --- |
| `shared-pool-negotiated-final-v11` | FAIL | Finalize now converges, but at workers=2 both domains moved to a new host lose ICMP seq50. Domains retained on the original host have no missing sequence. No zero-loss acceptance. |
| `successor-server-restart-v11` | PASS, 63.32 s fixture | Exact activated-successor restoration and corrected Core/IO baseline assertions. Deliberate restart recovery includes failed reachability probes; this is not zero interruption during an injected death. |
| `bilateral-mbb-final-v11` | PASS, 57.85 s fixture | Two domains, two live policy rounds, exact Prepare/Commit retries and 400/400 continuous ICMP per domain; later ordinary-redial probes are independently retried. Does not close cross-process scale continuity. |
| `shared-host-lifecycle-v11` | PASS | Selected lifecycle fixture only; intentionally invalid child commands test exit isolation. |
| `mixed-listener-two-domain-v11` | PASS, 15.35 s fixture | Real ICMP/Proxy HTTP, worker recovery, two listener master restarts, preserved TUNIO/domain workers. |
| `proxy-release-v11-active-drain-v1` | PASS | Runtime Rust client held TCP tail/FIN, UDP/DNS and exact negotiated active-session drain/replacement admission. |
| `proxy-release-v11-udp-v1` | FAIL | Valid 64-byte 100-PPS cohort loses seq95; target log also lacks seq95. Master reports one `credit_unavailable` drop. Other cohort details remain in the JSON evidence; a subset cannot close the gate. |

Core `ca24a4f` and Runtime vendor `845acc9` address a separately proven
PacketPort defect: CommitOwner cancelled accepted old outbound packets before
drain. A nonempty old queue now retains Prepared and requires exact Commit
retry. A deterministic Linux socket-backpressure test is added. This defect is
not yet established as the cause of v11's missing seq50; fresh strict scale
evidence is still required.

The valid Proxy UDP loss is being investigated against the single-poll async
credit probe. Pending async lock acquisition is not proof that byte capacity is
exhausted. Any correction must retain real capacity limits, ownership fencing,
rollback and fairness for waiting requests.

The vanished-actor UNKNOWN Commit path remains **OPEN P0**, independently of
the passing activated-successor restart. Core's
`docs/sdwan-unknown-owner-retirement-design-20261016.md` records the missing
durable process/domain completion, transport revocation, bilateral confirmation
and distinct terminal contract. It is a design, not implemented automatic
recovery. An elapsed operation cap cannot substitute for full authorization
expiry or prove a prior activation never happened.

Runtime `418cdc9` adds the mixed-role quota/slow-consumer combination fixture;
`1763f2f` supplies a frozen Runtime launcher and records its hash. At these
commits the actual combined Linux gate is NOT_RUN. The two-hour soak remains
deferred.

## Frozen Release v12 Follow-up

All six release artifacts built from Core `eca0872` and Runtime `f838e40`.
Source manifest is
`ad5b07ca15d882efe92e50e8b7e12ae41e0335d7c9563960cfcef4e5e1de1912`;
Core ELF SHA-256 is
`594bd0544371cae7d17204d3091415e18946e521501cd3d8489d17d957011094`.
This set includes the independent full authorization witness, original absolute
UDP deadlines, synchronous datagram credit check, PacketPort pending-output
preservation and exact-policy netd owner handoff.

| Evidence directory | Result | Boundary |
| --- | --- | --- |
| `shared-pool-negotiated-final-v12` | FAIL, 66.96 s fixture | Four domains have no missing ICMP sequences through `1→2`, and `forward_owner_committed_policy_preserved` is observed. `2→4` fails convergence with repeated `worker_candidate_transaction_busy`; the complete scale gate remains open. |
| `mixed-role-fault-v12` | FAIL, 5.28 s fixture | Explicit principal quota rejection is observed; both real SD-WAN domains return 34/34 continuous ICMP. An existing Proxy request times out before quota-release/slow-consumer coverage; master reports one `expired_at_master` datagram. The failing operation was not yet recorded, so exact attribution needs further evidence. |
| `proxy-release-v12-udp-v1` | FAIL | All five original cohorts return 300/300, without duplicate/corrupt payloads. 64/512-byte schedules are valid; ordinary 1200/4096-byte and original recovery schedules exceed the unchanged timing threshold. Later recovery also returns 300/300 with invalid scheduling. No `credit_unavailable` is reported; six master-queue drops occur around the deliberate burst. Packet integrity alone does not close load validity or the complete gate. |
| `proxy-release-v12-active-drain-v1` | PASS | Runtime Rust held TCP tail/FIN, UDP/DNS, active negotiated drain and replacement admission. Overall release acceptance remains incomplete. |
| `bilateral-mbb-final-v12` | PASS, 67.61 s runner | Two domains, two live policy rounds and exact Commit retry, continuous 400/400 ICMP per domain; original cap expiry and ordinary-redial checks complete. |
| `successor-server-restart-v12` | FAIL, 73.29 s fixture | HTTP Proxy probe fails after the injected server-worker restart. Evidence retains accepted Proxy session 13 without a matching target HTTP request; the original probe omitted its caller and IO cause. No attribution or successful restart acceptance is inferred from v11. |
| `shared-host-lifecycle-v12` | PASS | Selected shared-host lifecycle fixture only. |
| `mixed-listener-two-domain-v12` | PASS, 19.71 s runner | Real two-domain ICMP/Proxy HTTP, worker recovery, listener restarts and infrastructure/process preservation assertions. |

Linux mutable-source regressions: Agent 142/142; transport 206/206; pending
PacketPort socket test 1/1; Runtime exact pending-Commit retry 1/1; netd
infrastructure 25 passed, 4 ignored. Strict Linux Core and Runtime Clippy pass
with `-D warnings`, using derived image
`candy-short-gates-clippy:20261016`. Runtime `7e14ee2` only moves unchanged
argument tests below production items to satisfy `items_after_test_module`;
it is outside frozen v12 and changes no production behavior. Logs and the
explicit mutable-source scope are retained in `short-linux-regression-v12`.

Runtime `213694e` adds the missing mixed-fixture operation phase, traceback and
exact target UDP sequences for the next frozen gate. It does not change packet
retries, pacing, deadline or acceptance criteria. The v12 failures are retained.
Runtime `94ffc19` records the failed Proxy probe caller, attempt count, elapsed
time, IO error kind and detailed error without changing its existing retries or
timeout. These diagnostics are outside frozen v12.

## Frozen Release v13 Follow-up

Six artifacts built from Core `d98c236` and Runtime `2233eab`; source manifest
`d3e63292a6e2b303594c80e423edb372a1e4c46e485fe00e5737414fa7c01248`.
This set contains synchronous candidate proof publication, exact publication
retry, preserved unresolved original reservations, Prepared schema 3 local
authorization-origin evidence, and detailed UDP expiry diagnostics. It excludes
the later control byte-reserve implementation `a2c842e`.

Frozen-source Linux checks pass: candidate journal 25/25, including actual
Linux process capture; MBB recovery guard 3/3; Core application/runtime/transport
and Runtime netd/Agent all-target strict Clippy with `-D warnings`. See
`short-linux-regression-v13` for exact commands, scope and the retained initial
read-only bind-mount setup failure, which did not execute tests.

The following traffic gates use the same frozen artifact set, three pinned VM
CPUs and no periodic CFS quota. Before/after `cpu.stat` records show zero
throttling for these completed runs. This differs from v12's quota-based runner
and is explicitly recorded; the missing-sequence, identity and receipt criteria
are unchanged.

| Evidence directory | Result | Boundary |
| --- | --- | --- |
| `shared-pool-negotiated-final-v13` | PASS, 61.61 s runner | All `1→2→4→2→1→2→1` stages have zero missing ICMP in four domains, including original transaction cap expiry; exact bilateral handoff receipts, infrastructure identities, host resource bounds, isolated host crash and shutdown tests complete. Does not prove vanished-actor UNKNOWN retirement. |
| `mixed-role-fault-v13` | PASS, 13.25 s fixture | Real quota rejection and release recovery; 60 fresh TCP requests, held TCP, 61 exact 4-KiB UDP packets; 10,420,224 bytes accepted into a never-read flow and at least two actual socket write timeouts before healthy traffic checks. Both SD-WAN domains have zero loss (114/114 and 115/115), and held UDP process/socket/source port remain exact. |
| `successor-server-restart-v13` | PASS, 63.59 s runner | Activated successor authorization restored after the deliberately killed server worker; preserved TUNIO, unrelated domain identities, exact receipts and subsequent Proxy probes. Injected worker death may cause failed recovery probes; this is not a zero-interruption claim for that domain. |

These passes do not erase v12's failures or establish that the v12 Proxy
timeout was caused by CFS throttling. Its original packet budget/age and precise
failed operation were not recorded. The new control reserve addresses a
separately demonstrated structural coupling and requires its own frozen gates.

## Frozen Release v14 Follow-up

Six artifacts built from Core `a2c842e` and Runtime `be48310`; source manifest
`fe01e4a2b2190f5e9d20e5b4aeba7b4b507d606e4101e44f3fb9ba8ea4657178`.
Core ELF SHA-256 is
`8c16bf9508a11eb19de04bd139b9f36e1acc184e56531051cd4972906050bfde`.
This set adds bounded directional control byte reserves carved from the existing
worker/pool/shared totals. The exact classified first control stream receives
the reserve; ordinary worker requests cannot select it. It does not add QUIC
connection flow-control headroom or resolve vanished-actor UNKNOWN retirement.

Frozen-source Linux transport tests pass 213/213. Strict all-target Core
application/runtime/transport Clippy passes with `-D warnings`; commands and
logs are retained in `short-linux-regression-v14`. Traffic runs are serial,
without build/native-test contention; shared fixtures use three pinned VM CPUs
without periodic CFS quota and Proxy fixtures use disjoint service/generator
CPU sets. Receipt, identity, missing-sequence and load-validity criteria remain
unchanged.

| Evidence directory | Result | Boundary |
| --- | --- | --- |
| `mixed-role-fault-v14` | PASS, 14.71 s runner | Real quota rejection/release recovery, held TCP, 60 fresh TCP requests, 61 exact 4-KiB UDP packets and unchanged held UDP owner/socket. Never-read flow accepts 10,289,152 bytes and reaches two actual write timeouts before healthy probes, six afterward. Both SD-WAN domains return 115/115 with no loss. This does not prove data-credit saturation or QUIC control headroom. |
| `shared-pool-negotiated-final-v14` | PASS, 60.18 s runner | Four domains, full `1→2→4→2→1→2→1`, zero missing ICMP at all scale stages, original operation-cap expiry, bilateral receipts, preserved infrastructure and resource bounds. Does not resolve vanished-actor UNKNOWN. |
| `successor-server-restart-v14` | PASS, 63.84 s runner | Exact activated-successor restoration after injected server worker death, preserved TUNIO/unrelated identities, receipts and later Proxy probes. Recovery probes may fail on the deliberately killed domain; no zero-interruption claim. |
| `proxy-release-v14-active-drain-v1` | PASS | Actual Runtime Rust client, held TCP tail/FIN and UDP/DNS, authenticated bounded negotiated drain, exact receipts, replacement admission overlap, original deadline and listener/master identities. All detailed drain subgates pass. |
| `proxy-release-v14-udp-v1` | PASS | All five original cohorts (64/512/1200/4096-byte ordinary traffic and 1200-byte recovery one second after overload) return exactly 300/300 with zero duplicate/corrupt/foreign payloads. Every schedule is valid: zero lateness violations and zero rebases. Deliberate overload is 4096 packets of 4096 bytes; later TCP probe returns 262,144 bytes without a restart. This is bounded 100-PPS recovery, not maximum PPS or throughput acceptance. |

The fixtures retain their diagnostic logs, including the isolated nft/iptables
`DOCKER-USER` compatibility probe warnings and intentional fault responses.
Passing traffic assertions do not mean that every diagnostic line is error-free.
The v14 UDP pass closes this frozen build's bounded load/recovery gate; it does
not establish why every earlier invalid-load or lost-packet cohort failed.
Two-hour renewal remains deferred by the user's explicit choice.

## Frozen v15/v16 Short Gates And Fixture v17

This completes the selected short-gate batch and the newly found blocking
fixes. It does not complete every P0 or authorize a production rollout.
All test containers were removed afterward; the six pre-existing Cloud
containers remain running. No production node, release, signature or remote
Git branch was changed in this batch.

### Fixes Included

| Commit | Correction |
| --- | --- |
| Core `bc66acf`, Runtime `c5d1348` | Query the original live actor and re-read the actual immutable historical peer CommitAck file; verify the original tuple and Reserve/Reserved hashes. Historical ACK is not current forwarding or permission for a new transaction. |
| Core `e2f1566`, Runtime `00b724e` | Original task incarnation, actual joined completion and authenticated evidence client foundation. Controller-submitted owner/checksum association is not independent master attestation. |
| Core `1a9939d`, `9b6d599` | Checked IPC owner shutdown retains the actual JoinHandle across cancellation and requires task/admission/endpoint cleanup. Receipt scope excludes separate pool admission, domain completion and bilateral retirement. |
| Core `1e49b49` | Actually consumed reserved-control credit now renews QUIC MAX_DATA at the bounded reserve threshold. Before correction, stopped Data readers could stall a long control exchange around result 495. Existing windows and capacity remain unchanged. |
| Core `43a17ca`, `9a78d8e` | A temporarily full required-message queue waits for its original bounded permit instead of closing the shared connection as ActorStopped. Real consumer closure remains connection-scoped; cancellation releases a pending frame. Adds true concurrent wire burst coverage. |
| Core `0a9093a` | One 1.2-second evidence budget and shared 500-ms Probe budget replace N independent two-second actor waits. Retain at most one filesystem read per original session and four process-wide. Reconcile bypasses status writes and stale publication caching, preserves pending Install and revalidates controller/cap/plan before return. |
| Core `e70d1e9`, Runtime `be0c2f4` | Equivalent conditional expressions satisfy strict Linux Clippy; no evidence semantics change. |
| Runtime `72876b3`, `672c041`, `487e5d0` | Real Linux evidence socket fixture, authenticated worker registration, and a private routable endpoint configured inside its isolated namespace. |

The diagnostic budget does not extend authorization. A first stalled peer can
consume the shared Probe budget, leaving later local actor phases UNKNOWN for
that query while their disk evidence is still checked. This is bounded latency,
not full actor-query fairness. Uninterruptible filesystem reads may outlive a
caller and consume the bounded four-read pool; no hard real-time scheduler or
filesystem guarantee is claimed. See Core's
`SDWAN_RECONCILIATION_BUDGET_20261016.md` for exact boundaries.

### Build Provenance And Linux Regression

Frozen v15 built six artifacts from Core `9a78d8e` and Runtime `be0c2f4`,
manifest `a39e32dfc7587f021fb8d98fa9b05ab4a40410446947f293a49cce3148652c63`.
Frozen v16 built six artifacts from Core
`0a9093aee0937759fd08531d36579c18f3d51123` and Runtime
`672c0418e97b24bf786360f7edb108ab7f0591fa`, manifest
`b462baa96441a1c45974dcbe74a7ec42e254b284fae34f571421eafac87eb3cc`.
The v16 Core ELF SHA-256 is
`fd0e57fadd417d501c132671a806e7b9abac81e4dcba0139f6e30a092b8495a4`.
Both freezes read committed blobs, excluding unrelated local edits.

| Frozen Linux check | Result | Evidence |
| --- | --- | --- |
| v15 transport library | 217/217 PASS | `short-linux-regression-v15/transport.log` |
| v15 carrier runtime library | 362/362 PASS | Includes eight reader-backpressure and six actual Linux control-transport tests. |
| v15 candidate reservation / worker control / domain evidence | 6/6, 10/10, 5/5 PASS | These precede the later budget fix; v16 full application coverage below includes it. |
| v15 standalone Quinn | 287/287 PASS | `quinn-standalone.log`; the first workspace command did not execute tests and is retained separately. |
| v15 Runtime Agent / TUNIO library | 148/148, 26/26 PASS | Includes Linux ownership/reconciliation, MBB guard and shared-evidence validation. |
| v15 Runtime Agent/netd and TUNIO strict Clippy | PASS | All targets, `-D warnings`, no lint exemption. |
| v16 full Core application library | 150/150 PASS | Includes budgeted queries, actual persisted CommitAck validation and original publication retry. |
| v16 Core application/runtime/transport/server strict Clippy | PASS | All targets, `-D warnings`; replaces the preserved v15 manual_map failure. |
| v16 and v17 TUNIO strict Clippy | PASS | All targets, `-D warnings`, including the final evidence fixture. |

v15's complete runtime/transport/vendor regression is applicable to unchanged
files in v16. The v15→v16 source delta is confined to seven application files
and one evidence fixture; the full affected Core application and strict checks
were rerun. No component count is presented as a complete release matrix.

### Serial Traffic Gates

Traffic runs began only after all native and Docker compilation had ended.
Shared/wire fixtures use three pinned VM CPUs without periodic CFS quota;
Proxy fixtures use disjoint service and generator CPU sets. Original timeouts,
missing-sequence, exact-identity and load-validity requirements remain intact.
Proxy uses the frozen Runtime `candy-client` launcher and the actual Rust Core.

| Evidence directory | Result | Measured boundary |
| --- | --- | --- |
| `control-reserve-wire-v16` | 4/4 PASS, 10.91 s runner | Actual authenticated/classified QUIC and Unix IPC. Two stopped downloads retain full 16,384-byte Data charge; lifetime and unpaced concurrent burst each return 8,192 exact results, same owner/connection, and a later fresh probe. Lifetime MAX_DATA delta is 65. Original 2-second per-result and 30-second total deadlines remain. Protocol fixture, not Runtime CLI or Go compatibility. |
| `mixed-role-fault-v16` | PASS, 14.41 s runner | Quota rejection/release recovery; held TCP, 60 fresh requests and 61 exact 4-KiB UDP packets. Stopped reader accepts 9,109,504 bytes, with two actual write timeouts before healthy probes and six afterward. Both SD-WAN domains return 115/115; held UDP PID/start/inode/port remain exact. |
| `shared-pool-negotiated-final-v16` | PASS, 59.07 s runner | Full `1→2→4→2→1→2→1`; four domains have zero missing ICMP at every scale stage. Original-cap expiry, exact bilateral receipts, TUN/IO identities, resource bounds and isolated crash/shutdown assertions pass. |
| `successor-server-restart-v16` | PASS, 62.03 s runner | Activated successor restores after deliberately killing its server worker; infrastructure/unrelated owners and later Proxy remain healthy. Recovery probes on the killed domain may fail; this is not zero interruption under process death. |
| `bilateral-mbb-final-v16` | PASS, 58.96 s runner | Two live policy rounds, exact original retries/receipts, 400/400 continuous ICMP per domain and preserved TUN/process identities; original-cap and later renewal/redial checks pass. |
| `proxy-release-v16-active-drain-v1` | PASS | Held TCP tail/FIN, UDP/DNS, authenticated negotiated drain, exact receipt, original deadline, replacement overlap/admission, same listener/socket/master. Every detailed drain subgate passes. |
| `proxy-release-v16-udp-v1` | PASS | Five original cohorts each return 300/300 with no missing/duplicate/corrupt/foreign packet; zero schedule violations/rebases. Includes recovery one second after 4,096×4,096-byte deliberate burst (0.01131 s). Later TCP returns 262,144 bytes and service identities remain exact. This is 100-PPS bounded recovery, not maximum PPS/throughput. |
| `domain-evidence-socket-v17` | PASS, 1.58 s runner | Two real signed tasks, authenticated registration/control, actual packet sockets, original incarnation/controller checks, exact association conflicts, actual cancel/join, pinned-forget rejection, unrelated task preservation and same-path replacement. No forwarding/master-lease or candidate-retirement claim. |

v17 is a fixture-only rebuild from Runtime `487e5d0`, manifest
`87f7e6a5332c829c0961b380f4fe621a06abe4181837f3a6633e2da697a6bdc9`.
The manifests prove the only changed source is
`linux/common/apps/candy-tunio/tests/fixtures/shared_domain_evidence.rs`.
The helper was rebuilt; the other five artifacts were inherited from v16 only
after verifying every checksum. Core is unchanged. This is explicitly recorded
in `registered-mbb-release-v17/build-provenance.json`; it is not described as
six freshly compiled artifacts or a rerun of all v16 traffic.

### Preserved Failures And Remaining P0

- v15 first Quinn workspace invocation: NOT_RUN because the vendored package is
  not a workspace member. The standalone manifest run passes 287/287.
- v15 strict Core Clippy: FAIL on Linux-only `manual_map`. The equivalent
  expression fix is committed and v16 strict checks pass.
- `domain-evidence-socket-v16`: FAIL before task startup because loopback is
  rejected by production endpoint validation. The isolated private bridge fixes
  the fixture; production validation is unchanged. v17 passes. No failed
  evidence directory was overwritten.
- The original native control-lifetime stall and queue-burst disconnect remain
  retained in Core's control-credit review alongside the corrected results.
- Logs retain intentional rejection/fault events, overload drops and isolated
  nft/iptables compatibility warnings. A passing short reliability gate does
  not mean every log line is error-free or overload cannot drop UDP.

**Vanished-actor UNKNOWN automatic retirement remains OPEN P0.** The current
foundations still lack a durable original binding independently attested by the
master, complete pool/transport revocation evidence, reboot/controller recovery,
authenticated bilateral retirement confirmation, and a durable distinct
terminal with evidence-consumption/reclamation. Do not wire every Prepare into
the in-memory pinned evidence API until consumption and persistence exist;
otherwise evidence grows to its bound and prevents host retirement.

Next implementation order is durable original binding → independently verified
master revocation → authenticated original-participant reconciliation → distinct
terminal and evidence consumption → actual crash/persistence fault gates. Keep
legacy/incomplete cases UNKNOWN and preserve other domains, Proxy and TUN.
Core's `sdwan-unknown-owner-retirement-design-20261016.md` remains the acceptance
contract. Two-hour renewal is explicitly deferred. Performance optimization,
800-Mbps acceptance, Go interoperability, physical OpenWrt/Android packaging,
release signing and production rollout are not certified by this batch.
