# Master/Worker Open Gates, 2026-10-15

This is a current implementation and evidence index. Earlier architecture and
fault matrices contain historical statements such as "no process manager";
those statements must not be used as the current implementation inventory.
Neither API existence nor passing a related fixture closes an end-to-end gate.

Current iteration and frozen v14/v15 outcomes:
[P0/P1 progress](p0-p1-progress-20261015.md).

The user's current priority defers throughput optimization and the formal
performance matrix. Correctness, fault isolation and recovery remain required;
the historical performance failures below are retained as measurements, not
used to block this prioritized reliability iteration or relabelled as passes.

## Verified Subsets

| Area | Evidence | Exact boundary |
| --- | --- | --- |
| Modern Proxy UDP and stable Rust ingress | Core `42e5f99`, then `65f83b3`; [Rust gate report](proxy-rust-client-gate-20261015.md) | Runtime packaged Rust client, native and explicit fallback correctness; old datagram-only feature combination rejected without terminating later TCP |
| Managed worker restart | Frozen `65f83b3`, Linux v7 | Both actual Proxy children killed; original master preserved; two fresh children restored TCP in 1.138 seconds; later UDP passed |
| Worker horizontal placement | Linux v7 | Real independent Runtime processes prove actual simultaneous stable flows on all 1/2/4 workers; this does not prove migration or aggregate throughput scaling |
| Transport capacity exhaustion | Linux v7 | Effective seven-connection limit; existing traffic survives rejection, rejected client recovers automatically after a slot is released |
| UDP overload recovery | Linux v7 | Clean low-rate packets and later fresh flows pass after a bounded burst; not a maximum PPS or mixed-role overload gate |
| Concurrent admission ordering | Core `65f83b3` | ID allocation and owner publication share one mutex; transport 192, server 79 and application 84 tests, strict Clippy, frozen Linux build and v7 compatibility pass |
| Worker logging isolation | Core `2b68729`, Linux v12/v13 | Dedicated bounded exporter; all three actual exporters blocked while a held flow and 640 fresh requests pass without master/worker replacement; recovery reports 389 dropped records in v12. Application 88 tests and strict Clippy pass |
| Legacy peer UNKNOWN containment | Core `5c51322` | Original transaction/owners retained; durable intent prevents replacement after uncertain Commit; original terminal reason retained; not automatic actor/transport reconstruction |
| Runtime UNKNOWN containment | Runtime `cbd5d75` | Optional process proof distinguishes absence from unreadable/corrupt files; fallible liveness and typed-context retry preserve ownership on unknown state. This does not restore a lost actor/transport or complete make-before-break |
| Signed routing and TUN recovery | Existing signed Linux v12 and mixed-listener v10 reports | Prior frozen/source-worktree scopes remain valid; not silently promoted to current frozen release acceptance |
| Bilateral real actor handoff and post-cap redial | Core `090f93d`, `bilateral-mbb-final-v1` | Two signed domains, generations 1 -> 2 -> 3, 800/800 ICMP, exact duplicate Commit, post-cap ordinary successor redial, unchanged TUNIO/TUN and surviving Proxy; not managed cross-process acceptance |
| Integrated Linux Proxy drain | Runtime `7c8394f`, Core `090f93d` | Runtime Rust client: TCP 24/24, native UDP first packets 24/24, DNS 104/104, zero generator retries; held TCP tail/FIN and UDP owner survive, exact old-worker OS reap, original master/listener retained |
| Linux client local fault recovery | Core `a3e7209`, [fault report](../../candy-core/docs/proxy-linux-role-fault-gate-20261016.md) | Actual Rust client with test-only injected TCP/UDP/DNS/adaptive/dispatcher faults; 283/283 coverage and strict Linux Clippy; stable ingress sockets and recovered authenticated traffic; not uninstrumented release black-box acceptance |
| Durable activated successor context | Core `a3e7209`, [recovery report](../../candy-core/docs/activated-successor-recovery-20261016.md) | Actual Activated receipt precedes durable publication; current trust and original signed expiry revalidated on restart. Native 105/105 and Linux 130/130 pass; independent server restart gate pending |
| Unconsumed candidate descriptor recovery | Runtime `f7d3d24`, [recovery report](SDWAN_PRECOMMIT_RECOVERY_20261016.md) | Actual manager FIFO proof and exact old binding allow durable precommit cancellation; actual Prepared/Committed return original receipts, late Prepare is fenced. Linux Agent 129/129 and TUNIO 25/25, strict Clippy; not committed-actor recovery |
| Candidate continuity defects | Core `d34f6bc`, `e682271`, [continuity report](../../candy-core/docs/sdwan-candidate-continuity-20261016.md) | Preserve original Prepare transport and local receipt after uncertainty; verified activation becomes Active, stream-ready does not downgrade it, old per-connection probes are removed on exact replacement, acknowledged predecessor close yields instead of redialling old policy. Focused tests and strict Clippy; fresh strict scaling pending |
| Scoped restore/fencing isolation | Core `467ff27`, `414ce1c`, [recovery report](../../candy-core/docs/activated-successor-recovery-20261016.md) | Remote principal fence is independent of local Runtime fence; bounded partial restore preserves known contexts; corrupt, expired or unreadable same-scope successor cannot authorize static rollback. Focused component tests; immutable restart acceptance pending |
| Conservative dead master generation cleanup | Core `572035a`, `92d5f49`, [GC report](../../candy-core/docs/proxy-master-generation-gc-20261016.md) | Exact boot/master/child identities, private FD-relative traversal, bounded startup scan, unknown/live generations preserved. Cleanup failure does not retain a reaped worker's pool credit; spawn publication is constant-size. Linux Runtime 341/341 and 13 real worker-manager tests pass; final Proxy black-box regression pending |

## Open Implementation And Acceptance

| Priority | Gap | Required change or verification |
| --- | --- | --- |
| P0 | Complete managed acceptance for staged peer replacement | Real Reserve/Prepare/Install/Activate/Drain is implemented and bilateral final gate passes. Strict Runtime scaling v1-v3 failed and exposed placement-selection, first-Prepare ordering and same-host rendezvous issues. Repair and rerun with immutable binaries before enabling capabilities |
| P0 | UNKNOWN after process restart blocks replacement but does not rebuild the original coordinator's actor/transport | Reconcile the persisted original tuple against live participant receipts; reconstruct only authorized matching context; preserve old valid forwarding and TUN; do not convert absence of a reply into Abort or invent a fresh transaction |
| P0 | Full managed make-before-break acceptance | Runtime caller, remote staged attachment, exact candidate selector, PacketPort commit and actor Installed receipts are connected. First-Prepare ordering is fixed by `bbed1e9`; complete strict cross-process traffic/Netd/journal evidence remains required |
| P1 | Managed shared-pool 1/2/4/2/1 continuous scaling | Validate four signed domains migrating between shared hosts with exact per-domain actor/PacketPort/netd handoff, stable TUNs, zero sequence loss before faults, bounded target reservation, drain and exact OS reap. This does not certify splitting one domain's peer set across multiple simultaneous workers |
| P1 | Final release validation for negotiated Proxy drain | The integrated frozen `proxy-integrated-final-v1` correctness/drain gate passes. Keep feature bit 20 off until the supported caller/release matrix passes; this does not close SD-WAN scaling or long-duration acceptance |
| P1 | Frozen mixed-role failure and quota chain | Repeat two signed Runtime domains plus Proxy on one listener with current frozen binaries. Inject per-role exhaustion/slow worker/death while proving healthy-role traffic and unchanged TUN infrastructure |
| P1 | Performance floor and architecture cost | Runner now supports simultaneous bidirectional, 16 streams per connection per direction, and four independent packaged Rust clients, with every client's resource cost and per-direction floors. Actual full valid measurements remain required: direct/B0/worker, 10 s warmup, 60 s samples, five repeats, >=800 Mbps, <=5% goodput regression, <=20% CPU increase and original p99 criterion |
| P1 | Long-duration renewal | Two hours of actual signed renewal and mixed traffic; retain PID/start identities, authorization deadlines, TUN identity, bytes/FD/credit trends and all fault/recovery observations |
| P2 | Dead master generation recovery final integration | Conservative bounded cleanup is implemented in Core `572035a`. Complete the frozen Proxy restart/drain regression; UNKNOWN/legacy generations and total disk budget remain separate retained-evidence administration, not automatic recursive cleanup |
| P2 | Cross-platform package acceptance | Current Linux arm64 Docker evidence does not verify x86_64/OpenWrt ARMv7/IPQ40xx/Android installation, rollback or physical performance. Use the corresponding builds and dedicated platform gates |
| P2 | Cloud-wide shared allowance | One listener's ledger cannot impose an aggregate allowance across independent nodes. Use authoritative Cloud issuance/reservations where a global pool limit is required; do not invent signed terminal quota fields |

## Current Measurement Failures

V7 passed the ordinary compatibility/recovery subset but failed the diagnostic
performance matrix. It includes a 292 Mbps direct outlier, a 676 Mbps four-worker
single-upload sample and a failed loaded-latency sample. Those failures remain.
V8's same-source B0 short comparison passed its measured thresholds, but UDP
generator delay and 4 KiB loss made compatibility FAIL. No release is justified
by either run.

V9 FAIL: direct upload measured 947.7 Mbps over 60 seconds; the following
in-process B0 transfer verified its payload but failed loaded latency with four
probe-capacity errors and approximately 1004 ms maximum generator start lag.
Bulk and probes shared a Python process in this revision. The matrix stopped
before completing its requested groups; this is not a worker-versus-B0 result.

V10 FAIL: probes moved to an independent process, with separate timing witnesses
in each namespace. The first direct 60-second transfer verified 7,125,139,456
measurement bytes (950.0 Mbps), but maximum probe start lag was 38.059 ms,
exceeding the unchanged 20 ms generator limit. No B0/candidate performance cell
completed. Both witnesses record an overlapping pause around monotonic 11061.95
seconds during the direct measurement. This supports a shared scheduling issue;
it does not establish a hypervisor or physical-host root cause.

V10 ordinary UDP/recovery received all 1500 packets exactly, without duplicates
or corruption. Two 1200-byte probe sends exceeded generator scheduling tolerance,
so compatibility remains FAIL. Burst losses remain allowed only for the
separate explicit overload phase. A requested 4 MiB target receive buffer was
actually clamped to 425984 bytes; evidence retains the actual kernel value.
Do not report the requested buffer size as the applied size or treat burst
receive-buffer drops as ordinary low-rate packet loss.

V12 passes the complete runner compatibility/recovery subset, including logging
backpressure; performance was not requested. V13 repeats compatibility with
disjoint service and generator CPU affinity and no CFS quota. Its first direct
download/4-stream round measures 941.33 Mbps but fails the unchanged 20 ms
generator limit at 214.138 ms. Both timing witnesses have overlapping scheduling
gaps; neither namespace reports CFS throttling. No B0/worker performance round
completed, so pinning alone did not make this VM suitable for that acceptance.

The logger repair fixes a separate code-proven fault propagation path. It does
not retroactively explain v9/v10/v13 or change their outcomes. The runner now
also retains slow replies after the measurement boundary in the original offered
cohort; four focused tests and re-analysis of v13 raw observations verify this
correction. A fresh full valid measurement is still needed, along with the
implementation gaps listed above.

V14's four-independent-client bidirectional diagnostic passes compatibility but
fails performance: worker upload 784.02 Mbps versus B0 946.34 Mbps, CPU cost
126.9% of B0, and loaded p99 above the original limit. Direct download is only
629.98 Mbps. V15 adds actual generator thread CPU/context-switch counters and
repeats compatibility successfully; direct upload/download are
953.52/872.68 Mbps and the next B0 round fails the unchanged 20 ms generator
limit at 27.269 ms. No V15 worker performance cell completes. These short runs
do not close the full performance matrix or prove a product/host root cause.

## Rollout Boundary

The P0 containment patch bounds candidate reply delivery to two seconds and
the original authorization deadline, handles shutdown/transport loss, and
retains the original controller/receipt on uncertain delivery. Process-bound
version 2 authorization caps reject reused Quinn IDs and recreated owner tuples
after actor restart. This prevents false recovery; it does not reconstruct a
lost actor or close the UNKNOWN recovery gate. Core application 93 and runtime
317 tests pass, including actual QUIC rejection followed by data on the same
connection. See Core `docs/sdwan-p0-containment-20261015.md` for the intentional
outbound hot-replacement restriction and remaining integration work.

Master still owns Quinn state. A master restart requires reconnection and is not
an nginx-style lossless executable handoff. Existing ordinary production
listeners are not migrated by these gates. Source/test commits can be reviewed
independently; release/signing, default capability advertisement and deployment
require the relevant complete acceptance evidence.

The strict v4 failure remains recorded in
[the failure report](SDWAN_STRICT_GATES_V4_FAILURES_20261016.md). Its remote-fence,
lost-Prepare-session and snapshot-retirement defects have source fixes; a
successful component rerun does not change that failed end-to-end result. The
same applies to the single lost ICMP sequence in successor-restart v1: continuity
fixes require a fresh zero-loss gate. A committed candidate that loses its
process/transport still requires explicit failure isolation and durable original
receipts before fresh recovery; precommit cancellation does not cover it.
