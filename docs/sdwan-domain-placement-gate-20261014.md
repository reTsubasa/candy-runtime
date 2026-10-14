# Dedicated domain worker placement gate (2026-10-14)

## Implementation scope

An independent domain activation may request a local `placement` object with
`revision`, `target_worker_id` and an absolute private `pool_directory`.
This is local Runtime placement, separate from the signed policy generation,
Grant and authorization lifetime. The existing domain supervisor manages the
real business process; no additional supervisor or Cloud synchronizer starts.

Before launching the selected worker, Runtime reserves
`pool_directory/worker-{target_worker_id}.lock` with an exclusive OS file lock.
The same open file description is inherited into that Core process. Core
retains it until its business loop ends, then process retirement releases the
slot. A second domain cannot launch into the occupied slot. Core sets the
descriptor close-on-exec after transfer so later subprocesses cannot prolong
its retirement. Runtime never deletes these slot files during migration.

Core reports its selected worker/revision and actual slot descriptor, device
and inode in authenticated process status. Candidate registration and readiness
check the report against the manager-selected private file and the actual
`/proc/{pid}/fd/{fd}` identity. This binds placement to the spawned process
rather than merely renaming a path or recording a worker label.

The committed immutable plan supplies the current placement. A target change
requires a strictly newer local revision; removal and stale changes are
rejected. Publishing a newer revision triggers the existing signed renewal
transaction even when the signed closure and Grant are unchanged. The loaded
transaction must continue to use the original authorization deadline cap for
that unchanged signed closure, preserve TUNIO/netd and advance only the business
worker epoch, fence and local placement. The committed journal shortcut must
compare placement as well as signed authority before adopting a candidate.

## Limits and evidence

This is **one routing domain per exclusive worker slot**. It does not provide
a shared worker process serving multiple domains, a Transport/Proxy role pool,
or cross-process QUIC state migration. Those integrations remain part of F08.

Executed local tests after the coordinated quiet workload finished:

```text
cargo test --locked -p candy-core-process worker_placement::tests --lib -- --nocapture
2 passed; 0 failed
cargo test --locked -p candy-sdwan-agent local_placement_rotation --lib -- --nocapture
1 passed; 0 failed
```

These verify actual exclusive file descriptor lifetime, release on retirement,
close-on-exec, wrong target file rejection and independent monotonic revision.
An actual loaded Linux same-authority slot rotation
must prove PID/target-slot change, unchanged TUN inode and TUNIO PID, unchanged
signed hash/generation/deadline cap, continuous unaffected domain traffic,
occupied target isolation, restart adoption and late-packet fencing before
claiming this domain-placement gate passed.

## Loaded Linux Harness

The ignored `signed_cli_loaded_domain_slot_rotation_preserves_signed_authority_and_tun`
test reuses the strict signed Core/Agent/netd/TUNIO harness and real server
network namespace. It requires the isolated-kernel opt-in and `iperf3`. Two
independent continuous UDP loads run at 8 Mbps, one in each direction. This
loads the functional transaction without claiming an 800 Mbps performance
result. Every committed stage must advance both actual TUN directions by at
least 64 KiB with all four traffic processes still alive, and recover actual
ICMP through the signed tunnel.

The sequence covers slot 1/revision 1 -> slot 2/revision 2; an actual exclusive
slot 3 conflict that preserves slot 2 and resumes after the lock releases;
slot 3/revision 3 -> the same slot/revision 4 with a new real Core PID; rejected
stale and removed placement; Agent SIGKILL followed by adoption of that exact
Core and slot. Assertions bind live slot reports to the child's actual procfs
descriptor and verify the OS lock remains exclusive. The original IO PID,
start ticks, IO epoch, TUN state, signed hash/generation and Unix expiry must
stay unchanged, and every forwarding monotonic cap must remain at or below its
original and previous value. Old committed forwarding owners must be rejected
after rotation.

The harness preserves raw duplex traffic and Agent logs plus a JSON report
with actual process records, live status, forwarding owners and each step.
Its loaded Linux execution is still **NOT RUN** pending the coordinated
binary freeze/build; source formatting does not constitute a gate pass.
