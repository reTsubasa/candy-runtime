# Real Linux netd guard and domain regression

Runtime code: `a196957`, `6922354`; diagnostic fixture: `746ec14`.
Environment: disposable aarch64 Linux Docker, `--network none --privileged`, image
`candy-netd-test-runner:rust-1.88.0-aarch64`; no production namespaces or listeners.

Results:

- `cargo check --target aarch64-unknown-linux-gnu -p candy-netd --all-targets`: PASS on macOS with a separate target directory.
- Native Linux `cargo check -p candy-sdwan-agent --all-targets`: PASS. The host cross-check for Agent lacks `aarch64-linux-gnu-gcc`; the native Linux check covers the actual Linux-gated code.
- Native Linux netd/proto `--all-targets`: 103 passed, 8 intentionally ignored kernel/helper cases before explicit kernel runs.
- `infrastructure.log`: 3 real kernel tests PASS. The connected UDP socket remains the same before Guard, during Guard, and after netd guarded journal recovery; each send reaches the real TUN queue. Route JSON remains unchanged during Guard. Candidate replacement now installs its new underlay/local throw bypass routes. Permanent revoke/expiry remains unreachable and infrastructure identity is retained.
- `domains.log`: 2 real domain tests PASS, including 1/4 namespace activation, two domains using the same prefix, scoped failures/leases/journals and independent descriptor ownership.

Kernel tests share a fixed `candy0` name and must run with `--test-threads=1` in a disposable namespace. An initial parallel infrastructure run collided on that name; the corrected serial run is preserved here. This is a harness concurrency constraint, not a production pass.

These results do not close the loaded placement gate. Existing v10/v11 continuous UDP traffic exits with `EHOSTUNREACH` during business owner handoff. The added placement route/rule/link and ICMP collectors retain the actual error source for the next loaded run; the traffic-survival assertion is unchanged.

## Loaded handoff diagnosis and follow-up

- v13 evidence in the parent project's `docs/artifacts/sdwan-20261014/signed-handoff-gate-v13/` identifies a local route rejection during controller adoption: at 09:44:23.795056 the healthy client route becomes unreachable, then returns to `dev candy0` at 09:44:23.815959. Existing connected UDP traffic exits with `No route to host`. Commit `93fd6ec` guards the live retained forwarding owner before adoption changes its controller fence.
- v14 retains that route during the handoff. The only recorded client unreachable transition is 09:48:55.542601, during test failure cleanup. The new failure occurs earlier: TUNIO rejects `StageAuthority`, the Agent stops the fresh Core, and the server's new lane subsequently fails packet-probe readiness. The combined rejection message in v14 does not prove which envelope predicate failed. The stale-forward-owner message is in the later cleanup path; it cannot independently establish the primary cause.
- Code review found a deterministic cross-second defect: the monotonic verification timestamp and cap were sampled before the stop/spawn barrier, while `verified_at_unix` was sampled afterward. If that barrier crosses a wall-clock second, the same legal cap can exceed the validator's shortened verified wall duration. Commit `c9bfa24` retains the paired wall/monotonic sample and prints a distinct rejection reason with clock values. Existing receipt caps still only reduce the effective deadline.
- The cross-second reproduction passes on macOS and native Linux. Native Linux TUNIO authority-control regression passes 5/5, including invalid envelope recovery and deadline non-extension checks. Native Linux Agent compilation after `93fd6ec` and host Agent library tests (92/92 at that revision) also pass.
- A prepared transport's probes travel directly over the negotiated authenticated packet stream and do not require TUNIO authority activation or netd commit. No evidence supports disabling the carrier watchdog merely while the local forwarding transaction is pending. Candidate death after a rejected authority must be distinguished from a live prepared lane incorrectly retired by a watchdog.

The loaded placement gate remains open after v14; neither the above narrow tests nor the route-gap fix establish full loaded handoff, convergence, throughput, or release readiness. v14's other two test failures are fixed-name veth collisions after the first panic, so their product results must come from fresh isolated namespaces.

Commands:

```sh
cargo test -p candy-netd --test infrastructure_v2 real_linux_ -- --ignored --nocapture --test-threads=1 --skip real_linux_creation_crash_child
cargo test -p candy-netd --test domains_v2 -- --ignored --nocapture --test-threads=1 --skip real_multidomain_fd_child
```
