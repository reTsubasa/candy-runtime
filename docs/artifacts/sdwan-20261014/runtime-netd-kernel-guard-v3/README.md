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

Commands:

```sh
cargo test -p candy-netd --test infrastructure_v2 real_linux_ -- --ignored --nocapture --test-threads=1 --skip real_linux_creation_crash_child
cargo test -p candy-netd --test domains_v2 -- --ignored --nocapture --test-threads=1 --skip real_multidomain_fd_child
```
