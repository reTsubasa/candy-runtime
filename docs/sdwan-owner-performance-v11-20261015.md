# PacketPort owner performance comparison, v11, 2026-10-15

## Result

Default diagnostics-off comparison: throughput PASS and steady output integrity
PASS. Detailed executor diagnostics comparison: throughput FAIL and steady output
integrity PASS, including a second run with no reported concurrent builds. Full
G0-G6 acceptance remains incomplete. No production change or release was made.

## Frozen source and scope

- Core: `9c4f64f38082568a686064c4d63e40aff6ac0690`.
- Runtime: `f9d1bfc3548fc02f00904a93bbf784acf51ec697`.
- Source manifest SHA256:
  `709e0a61d19dfa31ba61cf15d0ebc9b0fdd761e50572a3e23d8c488c97cd1276`.
- Six release binaries built; all 643 frozen source files and six binary hashes
  independently verified. This build predates the isolated freeze cache change.
- Two isolated aarch64 Docker endpoints, real QUIC/TUN/Agent/netd/TUNIO,
  four TCP streams, 750 Mbps offered load, four alternating 60-second rounds.
- PacketOutput limits remain 256 packets, 512 KiB and 100 ms. Output diagnostics
  and independent scheduler observation remain enabled in both modes.
- These runs exercise steady forwarding, with zero renewals. They do not cover
  the subsequent mixed-listener, quiesce, candidate selector or application
  staged-barrier integration. Docker results do not establish physical-link,
  IPQ40xx or Android acceptance, or the 800 Mbps design target.

## Measurements

| Round | Direction | Default Mbps | Clean detailed diagnostics Mbps |
| --- | --- | --- | --- |
| 1 | Upload | 749.9990 | 649.6356 |
| 2 | Download | 750.0083 | 749.9702 |
| 3 | Upload | 749.9925 | 680.3696 |
| 4 | Download | 750.0006 | 746.0860 |

Default client CPU averaged 1.54-1.56 cores during upload and 2.06-2.08 during
download. Clean detailed diagnostics averaged 2.39-2.40 and 2.75-2.77 respectively.
These are whole-container cgroup measurements, not Core-only CPU. All samples
reported zero CPU quota throttling. Default and clean diagnostic runs both
reported zero Core drops/read/write errors and zero TUNIO slot, byte, channel,
backpressure, deadline and stale drops in both directions.

The first detailed diagnostic run measured 618.37/727.76/656.66/738.77 Mbps.
A concurrent native Cargo check was reported during that run; the exact interval
is unavailable. Its `environment-interference.json` is retained. It is not an
exclusive comparison. The clean rerun reproduces the upload slowdown, so this
interference alone cannot explain the diagnostic cost. Detailed diagnostics
remain disabled by default. Per-operation clock reads and other instrumentation
cost require further profiling before assigning an exact cause.

The clean export reports no lost events, but exporter shutdown-tail delivery is
not verified. Observed long operations include high CPU polls as well as
low CPU heartbeat delays. Nested spans overlap and must not be summed. Missing
records cannot prove absence of stalls, and this run does not prove that earlier
intermittent deadline failures are eliminated.

## Evidence

Under `/Users/hyc/Documents/candy/docs/artifacts/sdwan-20261015/`:

- `sync-span-release-v11/`: frozen source, manifest, binary hashes and build logs.
- `perf-owner-v11-default/`: baseline samples, status deltas, completion,
  `summary.json` and `scheduler-analysis.json`.
- `perf-owner-v11-diagnostics/`: original contaminated diagnostic comparison,
  including its interference record.
- `perf-owner-v11-diagnostics-clean-v2/`: fresh clean comparison, original samples,
  status deltas, executor exports, `summary.json` and `scheduler-analysis.json`.

The runner completed and test containers were cleaned up. Remaining gates include
integrated candidate failure/commit-ACK-loss recovery, client drain replacement,
same-domain 1/2/4 worker placement, mixed roles, UDP 64/512/1200, latency p99,
800 Mbps performance, two-hour renewal and target-platform installation.
