# Netd v2 live policy publication

A signed route-only publication now uses `ForwardPolicyUpdate` on the exact live
Active owner. It preserves the TUN, IO holder, worker/fencing epochs, original
physical authorization cap, interface address/MTU, exclusions and shared sysctls.
Only routes and their derived nft policy change. Non-Active owners and changes
to infrastructure require the normal replacement transaction.

The request carries a monotonic local policy revision, signed generation and
snapshot SHA-256. Exact replay is idempotent; metadata-only refresh does not call
the kernel backend. Status distinguishes physical owner from active policy
revision/generation/hash and a pending publication revision.

Before kernel changes, Netd durably stores the exact target. A partial failure
retains the Active owner and retries that target after a later request or restart.
It never overwrites an unfinished intent with a newer policy or drops the TUN.
Linux installs target routes using route replacement, replaces the owned nft
table in one transaction, and removes stale routes. The original declaration is
retained until all steps and the final journal commit succeed.

Expiry or explicit revoke persists cancellation before cleanup. Both original
remote routes and potentially installed target remote routes are fenced first;
target Local throws cannot override original Remote rejects. Cleanup removes
new target routes/selectors and restores original rejects, without replaying the
expired target. A failed cleanup stays durable and is retried after restart.
Cancelled target-only prefixes return to the host's existing routing policy;
this change does not introduce a permanent reject policy for those prefixes.

The journal bound is `2 * MAX_NETD_FRAME_LEN + 65536` bytes. It stores either
current plus candidate or current plus pending policy, never all three. Existing
journal checksums remain readable because absent policy metadata serializes as
absent. IPC frame and route-count limits are unchanged. Domain admission accounts
for declaration vector capacity and hash capacity and validates the policy table
and domain on both requests and journal recovery.

## Validation

- macOS infrastructure integration: 31 passed; protocol library: 7 passed.
- Linux Rust 1.90 Docker: Netd, client and protocol unit/integration suites passed
  (privileged kernel tests remain explicitly separate from the default suite).
- New regressions cover exact replay, metadata-only refresh, route updates,
  stale owner/revision/generation, immutable infrastructure, candidate conflicts,
  partial failure/restart, journal intent failure without fencing healthy traffic,
  expiry, revoke plus failed-cleanup restart, and current+pending journals above
  the previous 64 KiB limit.
- Isolated privileged Linux kernel gate passed: twenty alternating updates of
  remote routes and local source prefixes, with actual nft derived rules,
  unchanged full TUN link/address dumps and unchanged owner/fence. It deletes the
  owned nft table to cause a real failure after target routes install, expires
  the owner, and verifies target-only route/selector cleanup and original rejects.
- Strict Linux clippy for Netd, client and protocol, all targets: passed.

This gate establishes the kernel policy and infrastructure boundary. It does
not claim an end-to-end throughput or packet-loss result or a production rollout.
