# netd transient forwarding guard verification

Scope: `candy-runtime` commits `1ce7f30`, `6ffbbd6`, `fda4ac4`, `6ba7991`, plus signed renewal wiring `46683a3`.

The guard protocol is intentionally narrow:

* `ForwardGuard` requires the exact live owner and retains the lease/auth deadline.
* `Phase::Guarded` retains the existing unicast route to the owned TUN. It never installs `unreachable` or `blackhole` routes, which can return `EHOSTUNREACH`/`EINVAL` to connected local UDP sockets.
* packet quiescing is performed by the IO authority owner. A guarded owner can be replaced only by a higher fenced owner; expired owners still use permanent fail-closed revoke.
* cleanup recognizes old static `unreachable`/`blackhole` residues only for signed remote prefixes in the exact route table.

## Narrow verification command

```sh
cd /Users/hyc/Documents/candy/candy-runtime
CARGO_TARGET_DIR=/tmp/candy-f08-driver-target cargo test -p candy-netd -p candy-netd-proto --all-targets
```

Run this after a clean build window is available. Do not use the shared `/build` target.

## Socket behavior check

A real connected UDP socket test must run in an isolated Linux namespace with `CAP_NET_ADMIN` and a disposable TUN. Install the signed unicast route to the TUN, send through the connected socket, apply `ForwardGuard` (no route mutation), then stop the IO owner and verify sends remain successful or are locally discarded without `EHOSTUNREACH`/`EINVAL`; restore the route and attach the candidate owner, then verify delivery resumes. Do not run this against a production namespace.

The current macOS host cannot create the required Linux TUN/netlink namespace; the existing `candy-sdwan-systemd-gate` container has no source mount and is not suitable for this test.

## Results (2026-10-14)

* `CARGO_TARGET_DIR=/tmp/candy-f08-driver-target cargo test -p candy-netd -p candy-netd-proto --all-targets`: passed (netd 7 unit + 20 infrastructure + 27 transaction + other targets; proto 6 unit + 10 protocol + 1 vectors).
* `CARGO_TARGET_DIR=/tmp/candy-f08-driver-target cargo check -p candy-sdwan-agent --all-targets`: passed.
* No production or loaded placement test was run in this narrow gate.
* Real netlink/TUN socket behavior remains an isolated Linux namespace gate. The macOS host and existing container do not provide a disposable privileged TUN namespace.
