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

- Fresh strict managed `1/2/4/2/1` with unchanged infrastructure and exact
  bilateral actor/PacketPort/netd/drain receipts.
- Independent server restart with durable activated-successor restoration.
- Frozen mixed-role fault/quota isolation and shared-host recovery.
- Fresh Proxy UDP recovery, DNS, held TCP tail/FIN, and negotiated drain.
- Strict static checks for the final affected source and the isolated Linux
  endpoint test correction.
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
