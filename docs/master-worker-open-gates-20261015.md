# Master/Worker Open Gates, 2026-10-15

This is a current implementation and evidence index. Earlier architecture and
fault matrices contain historical statements such as "no process manager";
those statements must not be used as the current implementation inventory.
Neither API existence nor passing a related fixture closes an end-to-end gate.

Current iteration and frozen v14/v15 outcomes:
[P0/P1 progress](p0-p1-progress-20261015.md).

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

## Open Implementation And Acceptance

| Priority | Gap | Required change or verification |
| --- | --- | --- |
| P0 | Legacy peer replacement has no staged/installed actor proof | Unsafe success removed: ordinary responders return tuple-bound Abort, keep the transport and do not advance its fence; outbound hot replacement is rejected before ordinary OPEN can evict the old remote lane. Still connect the authenticated candidate initiator to actor prepare/commit/query receipts and pass the real two-end gate before enabling capabilities |
| P0 | UNKNOWN after process restart blocks replacement but does not rebuild the original coordinator's actor/transport | Reconcile the persisted original tuple against live participant receipts; reconstruct only authorized matching context; preserve old valid forwarding and TUN; do not convert absence of a reply into Abort or invent a fresh transaction |
| P0 | Full same-domain make-before-break remains incomplete | Integrate Runtime caller, remote staged attachment, candidate selector, PacketPort/netd commit and exact Installed confirmation. A prepared listener receipt is not proof of user forwarding or remote installation |
| P1 | Same-domain 1/2/4/2/1 continuous scaling | Implement/validate the domain worker set with unique peer/prefix owners, sticky sessions, bounded target reservation, drain and exact OS reap. Four independent domains or static Proxy worker counts do not close this gate |
| P1 | Complete negotiated Proxy drain on Linux | Run retained-tail/FIN, unsent-Open withdrawal, failed replacement auth, existing UDP ownership and final reap with actual Linux Runtime clients. Keep feature bit 20 off until supported callers pass |
| P1 | Frozen mixed-role failure and quota chain | Repeat two signed Runtime domains plus Proxy on one listener with current frozen binaries. Inject per-role exhaustion/slow worker/death while proving healthy-role traffic and unchanged TUN infrastructure |
| P1 | Performance floor and architecture cost | Runner now supports simultaneous bidirectional, 16 streams per connection per direction, and four independent packaged Rust clients, with every client's resource cost and per-direction floors. Actual full valid measurements remain required: direct/B0/worker, 10 s warmup, 60 s samples, five repeats, >=800 Mbps, <=5% goodput regression, <=20% CPU increase and original p99 criterion |
| P1 | Long-duration renewal | Two hours of actual signed renewal and mixed traffic; retain PID/start identities, authorization deadlines, TUN identity, bytes/FD/credit trends and all fault/recovery observations |
| P2 | Dead master generation directory recovery | Add bounded control-plane cleanup only with exact dead master and exited child proofs, private ownership/modes and no-follow traversal. Preserve unknown generations; never unlink a live dispatch endpoint to make startup succeed |
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
