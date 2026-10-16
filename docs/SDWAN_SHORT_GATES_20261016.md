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
