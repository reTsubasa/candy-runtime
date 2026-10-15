# Runtime Rust Client Proxy Gate, 2026-10-15

## Supported Test Matrix

The Runtime `candy-client` wrapper executes the real Rust `candy-core client`.
The isolated server executes `candy-core server proxy-master`, with real OS
worker processes. The fixture uses two network namespaces connected by a
1 Gbps veth, with 5 ms one-way delay. It never modifies production machines.

Per the product decision on 2026-10-15, the legacy datagram-only combination
without fragmentation or stream fallback is deprecated and removed from the
supported acceptance matrix. Modern native QUIC DATAGRAM remains the primary
UDP path. The explicit stream fallback profile remains a recovery gate.
Core `42e5f99` rejects that feature combination at UDP session admission, while
fixed native forwards require fragmentation during negotiation. Ordinary small
UDP wire records remain necessary inside the modern profile; their decoder is
retained. Rejected legacy UDP must not prevent later TCP on the same connection.

## Recorded Findings

| Finding | Implementation | Verification |
| --- | --- | --- |
| Cold UDP admission consumes the 5 ms packet budget | Core `f02de8a` separates admission from send readiness, retaining original age telemetry | Native client 268 tests; real Linux small UDP first packets pass |
| Linux transparent receive error type mismatch | Core `8c609a8` retains I/O kind and error chain | Linux build and client regression pass |
| Readiness, DNS and dispatcher failures spread beyond their role | Core `a3fa37b` isolates these failures | Native client 272 tests; further role recovery work remains |
| Fragment ACKs consume deadline serially | Core `d691448` submits a bounded fragment batch with one absolute deadline | Runtime 313 tests, strict Clippy, failing-before/passing-after deterministic regression |
| IPC DATAGRAM maximum remains frozen at bootstrap | Core `fb304d2` refreshes owner-fenced path capability | Growth/shrink/disabled and owner-fencing regressions pass |
| Primary UDP packets use redundancy-scale 2.5/5 ms expiry | Core `42e5f99` separates primary 20/50 ms from redundant 2.5/5 ms; enqueue age is immutable | Native deterministic regressions and later `65f83b3` Linux low-rate/overload recovery pass |
| Managed concurrent connection ID allocation can overtake pool binding | Core `65f83b3` allocates and binds under the existing pool mutex | 32-thread allocation, retirement/retry/exhaustion regression; transport 192, server 79, application 84 pass; strict Clippy pass |
| Synchronous platform logging can stall current-thread workers | Core `2b68729` uses a bounded dedicated exporter | 88 application tests and strict Clippy; real Linux stderr fault gate below |

Frozen `8c609a8` Linux library regressions passed 918 tests: client 269,
Runtime 310, transport 187 and protocol 152. One client test was ignored.
These results predate later fixes and are not a final release gate.

The `42e5f99` native four-library regression passes 937 tests: client 277,
Runtime 317, transport 190 and protocol 153. Strict all-target Clippy passes.
Its Release build and black-box measurements must be recorded separately.

## Committed Release Candidate

Core `65f83b3` was built from `git archive` of that commit, mounted read-only.
The Linux arm64 Release build used Rust 1.88.0, `--locked --offline`, three Cargo
jobs and the recorded runner image. It completed in 3m10s. No compiler ran during
the measurements. The ELF SHA-256 is
`4d32a37a77e421496f454e34722af97ae79370f0539013eab97e165c272af10a`.
Build log: `/tmp/candy-linux-65f83b3-release.log`.

The subsequent logger candidate `2b68729` also uses a read-only `git archive`,
Rust 1.88.0 and three jobs with `--locked --offline`; its Linux arm64 Release
build completed in 2m46s. ELF SHA-256:
`0151f933ba3b674fd3346fcd92a8bab7dd47fe4c32da7cb10fa44b40d291e525`.
Build log: `/tmp/candy-linux-2b68729-release-attempt2.log`. The first build attempt
stopped before compilation because rustup attempted a toolchain metadata lookup
with networking disabled. Explicit `rustup run 1.88.0 cargo` uses the already
installed toolchain; both logs remain available. No compiler ran during gates.

## Black-Box Evidence

Workspace evidence is under
`/Users/hyc/Documents/candy/docs/artifacts/sdwan-20261015/proxy-rust-cli-v*`.
Each result records binary, wrapper, guest and runner SHA-256, image identity,
negotiated state, command failures and owned-container cleanup.

`v11` verifies wrong authentication and certificate pin rejection without
interrupting a healthy client. Killing both owned workers preserved the master
incarnation and restored TCP in 1.15 seconds; both replacement workers were
verified. The recommended TCP/UDP profile passed in that run. Later runs
reproduced intermittent UDP loss, so the overall compatibility gate remains
FAIL. A successful individual run cannot override reproduced failures.

Some earlier fixture failures were test defects: placeholder SNI/secrets/pins,
using local feature support instead of effective authorization, and log reuse.
They are retained as failed attempts and do not count as product regressions.

### Version 7 Real Runtime Evidence

Local evidence directory:
`/Users/hyc/Documents/candy/docs/artifacts/sdwan-20261015/proxy-rust-release-65f83b3-netem-v7`.
Overall result is FAIL: compatibility PASS, performance FAIL. These are 3-second,
one-round, 2-second-warmup diagnostic measurements, not full duration acceptance.

- Recommended and explicit stream fallback profiles preserve correct payloads,
  TCP half-close and later healthy traffic after bad authentication or pin.
- Both exact owned Proxy workers were killed. The master incarnation survived;
  two fresh workers restored TCP in 1.138 seconds. Later UDP probes passed.
- 64/512/1200/4096-byte UDP at 100 PPS for three seconds each had no observed
  missing, duplicate or corrupt packets. A 4096-packet burst was followed by
  correct fresh UDP and TCP traffic. This does not establish maximum UDP PPS.
- Effective transport quota was seven despite a configured request of eight.
  Filling all slots rejected only the new owner, preserved six held flows and
  the main client, and automatically recovered the rejected client after a slot
  was released. Master and worker process identities remained unchanged.
- Independent real Runtime clients carried stable actual egress flows on all
  1/2/4 configured workers. Four workers needed five bounded connection batches;
  the four incomplete hash-coverage batches are preserved. The passing batch
  proved all four concurrently, using PID/start time, listening inode and exact
  business socket tuples. It is not a live-migration gate.

| Workers | Upload 1 stream | Upload 4 streams | Download 1 stream | Download 4 streams |
| --- | ---: | ---: | ---: | ---: |
| 1 | 934.5 | 939.5 | 893.6 | 920.3 |
| 2 | 907.4 | 923.8 | 938.0 | 883.4 |
| 4 | 675.6 | 942.0 | 879.9 | 908.1 |

All values are receiver payload Mbps, with full payload/sequence/hash checks.
The four-worker single-upload sample misses 800 Mbps and its p99 is 569 ms.
The two-worker four-download sample also misses that runner's latency threshold.
One direct single-upload sample reached only 292.2 Mbps; other direct medians
were roughly 946-956 Mbps. Consequently this run cannot establish a stable
throughput floor or attribute all variation to Candy. CPU cgroup snapshots show
no quota throttling; this does not rule out host scheduling or kernel drops.

V7 compares latency to direct TCP only. The subsequent runner adds the required
same-source in-process B0 comparison, CPU and architecture goodput checks; V7
must not be retroactively labelled as passing those new checks.

### B0 And Scheduling Follow-Ups

Evidence directories use prefix
`/Users/hyc/Documents/candy/docs/artifacts/sdwan-20261015/`.

| Run | Result | Observation and limit |
| --- | --- | --- |
| `proxy-rust-release-65f83b3-b0-smoke-v8` | FAIL | Short upload direct/B0/worker: 947.7/913.0/932.4 Mbps; short comparative thresholds pass but duration is incomplete. UDP had generator delay and 23 missing 4 KiB packets; compatibility fails |
| `proxy-rust-release-65f83b3-b0-long-v9` | FAIL | Direct 947.7 Mbps/60 s. B0 payload verified, about 870.5 Mbps, but four latency probe capacity errors, p99 about 981 ms and maximum generator start lag about 1004 ms. No completed B0/worker matrix |
| `proxy-rust-release-65f83b3-b0-long-v10` | FAIL | Independent probe process; direct payload verified, about 950.0 Mbps/60 s, but start lag 38.059 ms exceeds 20 ms limit. No B0 or candidate performance cell. Ordinary/recovery UDP 1500/1500 exact; two sends exceeded generator timing tolerance |
| `proxy-rust-release-2b68729-log-isolation-v11` | FAIL | TCP/UDP integrity, both feature profiles, exact worker crash recovery (1.152 s), worker distribution and quota recovery pass. Ordinary/recovery UDP 1500/1500 exact, but recovery generator starts were late. Logger fault reached all three blocked exporters; fixture incorrectly required queued bytes to equal nominal pipe capacity, so the traffic-under-fault phase did not run |
| `proxy-rust-release-2b68729-log-isolation-v12` | PASS compatibility; performance NOT_RUN | Both profiles, 32-session payload/FIN, exact UDP, low-rate/burst/recovery, worker distribution, admission rejection/recovery and platform logging fault pass. Worker recovery 1.145 s. This is not a performance or full SD-WAN acceptance |
| `proxy-rust-release-2b68729-pinned-long-v13` | FAIL performance; PASS compatibility | Core restricted to three disjoint CPUs per side, generator/witness on a separate CPU per side; no CFS quota/throttling. Direct download/4 streams 941.33 Mbps over 60 s, but generator start lag 214.138 ms invalidates the first round. No completed B0/candidate comparison |

V9 moved UDP target diagnostic writes out of per-packet open/close calls, recorded
actual socket buffers and retained generator/receive timestamps. V10 moved loaded
latency probes out of the bulk process's GIL and added bounded independent
scheduling witnesses on both sides. Both record an overlapping pause during the
v10 direct measurement around monotonic 11061.95 seconds. This supports shared
scheduling interference, without identifying a physical-host/hypervisor cause.
The actual target receive buffer is 425984 bytes despite requesting 4 MiB;
burst-induced drops are tracked separately from ordinary/recovery integrity.

The v11 logging fixture failed its own precondition: Linux pipe page/slot
fragmentation can reject a new write while queued bytes are below `F_GETPIPE_SZ`.
The corrected precondition requires actual `EAGAIN`, nonempty pipe and all three
exact owned exporter threads blocked in `pipe_write`. It does not change product
traffic, integrity or timing requirements. The failed v11 attempt is retained.

V12 proves all three actual exporters blocked in kernel `pipe_write` before and
after the fault traffic. A held TCP connection and 640 fresh 64-byte requests
passed; the fresh requests finished in 1.300 s, followed by another correct
request. Master and both workers kept their PID/start-time identities. Draining
the pipe recovered output with a report of 389 dropped log records, and later
TCP still passed. Record: `platform-log-backpressure.json` in that directory.
V13 repeats this fault and the compatibility subset successfully with CPU
isolation. Earlier failed attempts remain failed; these are subsequent passes.

V13 records actual service affinity `0-2`/`3-5` and witness affinity `6`/`7`.
Both independent witnesses show delayed scheduling overlapping the worst probe
around monotonic 12334.85-12335.08 seconds. The namespaces report zero CFS
throttled periods before and after. CPU isolation did not resolve this shared
pause; it is insufficient evidence to assign a Candy regression or to identify
the host/VM cause. Do not repeatedly rerun this environment until a valid sample
appears or replace the unchanged 20 ms generator criterion with a higher limit.

### Latency Cohort Correction

The runner after v13 keeps every request scheduled within the measurement
window, even if its reply arrives after bulk stops. Earlier code excluded those
late completions, which could hide a slow tail. Every one of the 20 Hz offered
requests must have exactly one result; missing, duplicate and out-of-window
sequence entries fail, and every request error remains a failure. Four focused
unit tests cover late tails, failed tails, start lag and invalid offered cohorts.

Re-analysis of retained v13 observations using the corrected function yields
1200 successful requests instead of the old completed-inside-window count of
1199, p99 130.661 ms and unchanged generator lag 214.138 ms. This validates the
correction against real records, but does not rerun or promote the failed gate.
Its original frozen scripts and result remain unmodified. CPU pinning and
measurement criteria must stay recorded for any later comparison.

Raw goodput from a round with invalid generator timing remains diagnostic only.
No result above closes the performance acceptance gate. The logger repair is a
separate code-level containment fix, not a proven explanation of these failures.

### Gate Tool Corrections

- Count listening Unix socket inodes instead of duplicated FDs; bind proof to
  the exact child launch directory and its worker identity.
- Respect the applied transport-memory admission budget. Rendezvous hashing does
  not guarantee one worker per newly opened connection. Retry only incomplete
  coverage, with a finite batch bound, preserving all attempts.
- Preserve closed readiness attempts while proving exactly one current live
  business socket for each marker.
- Disable veth segmentation/GSO/GRO before netem, retaining before/after flags.
- Offer latency requests at a fixed rate with bounded concurrency and retain
  errors and raw timestamps. A failed probe cannot disappear from the result.
- Require ten-second warmup, sixty-second windows and five repeats for duration
  compliance. Short passing measurements remain INCOMPLETE; observed failures
  remain FAIL. Duration compliance alone is not full release acceptance.
- Freeze runner/guest/load/scaling/UDP/admission sources with hashes in evidence.
  Record namespace socket/drop counters, applied QUIC status and stream TCP_INFO.
- A local HTTP 204 endpoint supplies the real built-in URL check in isolation;
  no public DNS or external health target is required by the fixture.

## Remaining Acceptance

- Repeat the modern native UDP and fallback checks under the full load matrix;
  the current committed Release's ordinary correctness and recovery subset pass.
- Demonstrate bounded overload behavior and continued later requests without
  avoidable primary-packet expiry or global connection resets.
- Preserve the passed independent worker ownership proof while adding aggregate
  multi-connection throughput and continuous scale/drain/migration validation.
- Use Release binaries and stop concurrent compilation for throughput tests.
- Complete the same-source B0 and long-sample loaded latency/CPU/performance gates.
  Investigate observed throughput and latency failures before claiming 800 Mbps.
- Retain separate two-hour renewal, same-domain candidate replacement,
  x86_64/OpenWrt/IPQ40xx/Android installation and rollback gates.

The scripts currently provide useful compatibility and exploratory throughput
evidence. They do not establish physical 1 Gbps acceptance or all SD-WAN gates.
No production deployment or release is justified by the results recorded here.
