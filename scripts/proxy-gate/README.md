# Runtime Rust Proxy Gate

The client is the packaged `candy-client` shell entry point executing the real
Rust `candy-core client --format candy-json` process. No Go client or protocol
stub substitutes for it. The server is the real `server proxy-master` entry.

Build the disposable executor:

```sh
docker build -t candy-proxy-netem-runner:20261015 scripts/proxy-gate
```

Run compatibility and recovery with a Linux Core ELF built from a recorded
source revision:

```sh
python3 scripts/proxy-gate/run.py --binary /absolute/path/candy-core \
  --evidence /absolute/path/new-evidence-directory
```

Add `--performance` for the 1/2/4 worker, upload/download, 1/4 flow matrix.
Bulk throughput uses one client QUIC connection with one or four TCP streams.
`--workers`, `--directions` and `--flows` select diagnostic subsets; sixteen
streams are also supported. Direct, same-source in-process B0 and master/worker rounds are interleaved and the
first measured kind alternates between repeats. A subset never establishes
completion of the full standard.
Separate independent Rust client processes prove actual worker distribution by
matching each live egress socket inode, tuple and marker to its worker PID,
start time and dispatch listener. Pool size alone is not a scaling proof.
Defaults follow the 2026-10-13 standard: five sixty-second measurement rounds
per cell with ten seconds warmup. `--seconds`, `--rounds` and `--warmup` can shorten exploratory runs, but those runs
produce `INCOMPLETE` performance status and cannot pass the performance gate.
Observed threshold failures remain `FAIL`, including shortened runs.
Never compile concurrently with performance runs.

Check the latency cohort's failure and tail handling:

```sh
python3 -m unittest discover -s scripts/proxy-gate -p 'test_*.py' -v
```

On an eight-CPU Docker VM, `--pin-cpus` reserves CPUs 0-2/3-5 for client/server
Core trees and 6/7 for the corresponding generators, targets and timing probes.
Disjoint namespace cpusets replace CFS quotas; each service still has exactly
three allowed CPUs. Actual service affinity is asserted before/after each round,
and generator/witness affinity is recorded. This is an optional measurement
fixture, not a product setting or a change to acceptance thresholds. V13 shows
that it cannot prevent all shared VM/host scheduling pauses.

Two dedicated containers have no default external network. A veth has 1 Gbps
egress shaping and 5 ms delay on each side. TCP segmentation, GSO, GRO and UDP
segmentation offloads are disabled before shaping; before/after flags are saved.
Earlier runner revisions kept default veth offloads and exhibited unstable
direct saturated latency. Those failures remain available for comparison.
The server has the Docker VM PID
namespace solely to move its veth peer into the client namespace. This is a
privileged test fixture, not production packaging. Container names and labels
are unique to the evidence directory; cleanup removes only owned containers.

## Acceptance

- Two real negotiated feature profiles: recommended native UDP with
  fragmentation and stream fallback, and explicit stream UDP fallback.
  Applied status must confirm Candy BBR and the BBRv1 preset.
- The legacy datagram-only profile without fragmentation or stream fallback
  is deprecated and excluded from the supported acceptance matrix. This does
  not remove modern native QUIC DATAGRAM as the primary UDP transport.
- 32 concurrent TCP sessions verify payload bytes and final half-close/FIN.
- UDP 64/512/1200 bytes verifies exact payload and sequence in every profile;
  recommended additionally verifies 4096-byte fragmented payloads.
- Wrong authentication and certificate pin produce explicit expected failures
  while the positive client continues forwarding.
- Killing only exact owned Proxy worker children must leave the master alive;
  actual TCP/UDP forwarding must recover within 30 seconds.
- A prefilled blocking stderr FIFO is inherited by the master and both workers.
  Require all three exporter threads in `pipe_write`, actual nonblocking write
  rejection (`EAGAIN`), verified held-flow traffic and 640 fresh TCP requests.
  Drain the FIFO, require a positive dropped-record summary and later traffic.
  The same master/worker incarnations must survive the full logging fault.
- Every performance group requires direct receiver median >=900 Mbps and
  Proxy receiver median >=800 Mbps and >=95% of the in-process B0 median.
  Loaded latency must have zero errors and each Proxy round
  p99 <=max(1.2*B0 median p99, B0 median p99+2 ms).
  Total client+server CPU seconds per measured GiB must be <=120% of B0.
  CPU, RSS, FDs and threads include
  master and all worker children, with stable process identities required.

`load.py` uses the common Linux VM monotonic clock, checked during each stream
handshake. All streams share the configured warmup and an exact measurement
window. Receiver goodput counts only complete blocks received inside that
window. Each 64 KiB payload is checked against deterministic content and its
sequence; the complete sender/receiver SHA-256 and count must also match.
Latency requests arrive at a fixed 20 Hz with at most 32 concurrent requests.
Capacity exhaustion is an error, and no unbounded waiting queue is created.
Requests are recorded with timestamps. Every request scheduled inside the
measurement window belongs to its cohort, including slow replies arriving after
the window ends. Missing, duplicate or out-of-window offered probes fail; all
20 Hz requests must complete without error. Any probe error fails.
The latency generator runs in its own process, separate from bulk transfer's
Python GIL. Every probe retains scheduled, started and finished timestamps;
generator start lag above 20 ms invalidates the round. A failed round still
retains verified payload counts, raw throughput and latency observations, which
are diagnostic data and cannot count as accepted performance.
Independent lightweight processes in both namespaces record scheduling gaps
over 20 ms with bounded history. Their observations can identify coincident
pauses; they do not measure packet latency or prove the cause of a stall.

`udp.py` validates exact payloads at 100 PPS for each modern payload size,
then injects a bounded 4096-packet burst and verifies a fresh UDP flow and TCP
request. Burst loss is allowed; normal/recovery loss, corruption, duplicates
and generator lag over 20 ms fail. This is not a maximum UDP PPS benchmark.
The worker distribution test uses six clients plus one reserved fixture client,
respecting the effective seven-connection memory budget. Rendezvous hashing
may require up to twelve batches; every incomplete batch remains in evidence.
`--scaling-attempts` can lower that bound. A passing batch must have all workers
carrying actual flows concurrently and stable throughout its measurement.
Product, socket ownership and cleanup failures never receive this retry.

`admission.py` reads the applied transport connection limit, fills its remaining
slots with real Runtime clients, confirms explicit capacity rejection and exact
existing-flow payloads, then releases one slot and requires the rejected client
to reconnect automatically. It verifies later TCP traffic and exact child-group
cleanup. It does not increase configured admission to make the test pass.

CPU seconds per measured GiB includes warmup and latency probe work; its label
records that scope. Resource snapshots cover the complete owned service tree.
The B0 server executes the existing `candy-core server --config` entry from the
same binary, on a separate private listener, using equivalent transport and auth
settings. Its own Runtime Rust client uses the same wrapper and options. Every
B0 run must have exactly one server process; master/worker snapshots include the
master and all its workers. The other fixture service remains idle during each
measurement. This isolates the architecture comparison within the same source;
it is distinct from a baseline built from an earlier released artifact.
Namespace TCP/UDP counters, qdisc and cgroup snapshots are retained before and
after. Each stream records Linux TCP_INFO, including final sender retransmissions
after receiver confirmation. Half-close remains part of the integrity contract;
sender counters cross the fixture's shared evidence mount, not application bytes.
The benchmark proves distribution separately; it does not claim aggregate
multi-connection throughput scaling from the single-connection bulk result.
The default matrix still lacks a released-artifact B0 comparison, bidirectional
traffic, sixteen streams and long-duration renewal. Duration
compliance alone is not full G3-G6 acceptance.

Raw receiver, hash and timestamp observations, command outcomes, process logs,
applied status and binary/wrapper/script SHA-256 are retained. Earlier runner
revisions used iperf and unsynchronized side probes; those results retain their
original exploratory scope. A filter matching no tests is never counted as PASS.
Each process launch archives its previous log. Shutdown verifies the recorded
process incarnation and waits for the entire owned process group to exit before
reusing a private master directory.
An overall compatibility PASS without `--performance` leaves performance as
`NOT_RUN`. Neither local aarch64 Docker results nor shortened samples establish
physical x86_64, OpenWrt/IPQ40xx or Android acceptance. Two-hour renewal and
same-domain make-before-break gates remain separate.
