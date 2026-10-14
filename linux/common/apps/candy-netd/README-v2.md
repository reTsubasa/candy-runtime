# Independent infrastructure ABI (experimental)

The existing service and `NetdClient` remain version 1. Their rollback, descriptor and
orphan semantics are unchanged. Select version 2 explicitly using `--protocol-v2` and
a separate `--socket`/`--infrastructure-journal`; a v1 frame is rejected in v2 mode.
Do not run v1 and v2 against the same interface or network namespace.

The original version 2 path supports one infrastructure interface (`candy0`) and one routing
domain. Its `Capabilities` reports `multi_domain=false`. Another domain cannot take over
the retained domain. A retained active/revoked policy may have one prepared candidate;
preparation validates without changing the live kernel policy. Commit records intent,
guards both route sets, installs the candidate firewall/steering, and removes obsolete
owned routes. A failed commit restores the previous live unexpired policy. Interrupted
repair stays journaled and is retried before another mutation. The explicit namespace
dispatcher described below supports multiple domains; full Agent integration remains
a separate system gate.

Routing table and shared sysctl requirements (`require_ipv4_forwarding`,
`manage_rp_filter`) are retained infrastructure attributes. Address/MTU changes require
explicit retirement. Remote/local prefixes, underlay exclusions, forwarding permission
and MSS clamp may change with a new signed generation and a higher fence. An identical
policy can change worker epoch without changing signed generation. Only one candidate
is retained; it must commit/revoke before another is accepted. Candidate cancellation
or expiry consumes its fence. Commit has a bounded fail-closed transition, not a
promise of zero packet loss or an atomic whole-kernel snapshot swap.

## Responsibilities

- `InfraEnsure`: administrator identity, namespace identity, interface address/MTU and
  persistent TUN. Durable creation intent with a random marker precedes exclusive
  nonpersistent device creation. The marker is applied as the interface alias before
  persistence is enabled. A crash before persistence leaves no device; a crash after
  persistence restores only the device carrying the exact journaled marker in its
  original namespace. An unmarked/differently marked existing device is never adopted.
- `InfraAcquireIoFd`: one authenticated caller instance/PID/boot ID/Linux process
  start-time identity and monotonically increasing
  `io_epoch`; a live retained I/O PID blocks all duplicate acquisitions, including a
  lost reply retry. Supervisor must prove the previous process exited before retrying.
- `InfraReleaseIo`: administrator may release a dead I/O owner; closing one duplicate
  fd is insufficient proof when its process remains alive.
- `ForwardPrepare/Commit`: domain, signed generation, worker epoch, fence, authorization
  and monotonic lease deadline. Business operations cannot change interface address/MTU.
- `ForwardRevoke` and expiry: replace signed remote routes with unreachable routes and
  remove owned firewall state. Interface, address, lifetime and base routing remain.
  Unreachable steering prevents an unapproved fallthrough to the default/direct route.
- `ForwardFailedPrefixes`: exact signed remote prefixes, current owner/fence and live
  authorization. An independent monotonic `failure_revision` allows authoritative full
  snapshots to withdraw and recover prefixes within one signed generation. Lower
  revisions or equal revisions with different contents are rejected. Equal completed
  snapshots are idempotent. Status includes the applied and pending revisions.
  An active update replaces only routes whose health changed;
  unreachable failures never become throw/direct fallbacks. Other prefix routes, policy
  rules, firewall and TUN remain. Prepared failures are recorded without activation and
  honored by commit. Intent is persisted before changes; interrupted updates retry after
  restart and preserve previous failure state during failed policy replacement. A failed
  scoped repair does not block lease renewal or status. New policy/failure mutations wait
  for the retained repair, preventing a second change from losing partial kernel state.
  Changed prefixes are first guarded as unreachable, then the target routes are applied.
  A target installation error attempts to restore those scoped guards and retains intent
  for retry; this is not an atomic multi-route kernel snapshot. The Agent must verify
  Core publication token, process identity, snapshot freshness and packet-path readiness
  before requesting restoration; Netd verifies its authenticated owner and authorization.
- `InfraRetire`: explicit administrator action after forwarding is revoked and I/O
  process has exited. Removes owned steering and the infrastructure device.

Linux also offers opt-in `--domain-config` namespace dispatch. Its root-owned JSON
`domains` list maps `domain_id`, `infra_id`, `namespace_path`, `journal_path`, and
`table_id`. Each domain must have a different precreated namespace and journal. The
router accepts explicit `InDomain` operations on one control socket, pins namespace
identity, holds exclusive journal locks and uses one control thread per domain. Each
namespace has its own candy0, sysctls, routes and firewall. TUNIO must execute in that
namespace; each live PID/start-time/boot and caller instance is bound to one domain.
Netd never chooses a domain from a packet destination. This configured path advertises
`multi_domain=true`; the original single-domain path remains false. Namespace plumbing
and per-domain TUNIO/worker deployment are separate Agent responsibilities.

The JSON must also contain an explicit `budgets` object: `max_domains`, `front_control_threads` (at least 2),
`max_control_threads`, `thread_stack_bytes` (minimum 262144), `max_total_stack_bytes`,
`max_pending_control_requests`, `max_pending_control_bytes`, and `max_reserved_fds`.
Total thread and stack budgets include namespace threads plus the fixed ingress pool.
Startup admission precedes namespace/journal/thread/kernel/socket side effects. It
checks inherited `RLIMIT_NOFILE` without changing it. Each domain gets one control
thread and at most one unfinished operation; ingress/active/response requests share global count/byte
permits. A response timeout retains its permit until real completion. Heap accounting
reserves 262144 bytes per ingress frame, then retains the greater of that reservation
and decoded vector-capacity accounting. Response handling shares the permit until both
operation and response complete. Rejection identifies the exhausted
resource and required/allowed values with `code=domain_resource_budget_exceeded`.

Use `candy-netd --check-domain-resources /etc/candy/netd-domains.json` before replacing
a running controller. This read-only check validates resource admission only; complete
namespace/journal wiring is checked again by startup. It does not reserve resources.

The multi-domain accept loop dispatches to a bounded fixed pool, not one thread per
connection. Frames have a 2-second absolute receive deadline and responses a 2-second
absolute write deadline. One slow domain operation cannot hold the global I/O binding
mutex or occupy multiple front waiters. Binding rollback uses a reservation token;
late failures clean only their own record. Multiple unidentified partial connections
can still saturate bounded ingress, causing deadlines/retry rather than unbounded work.

The checksum journal is independent from v1's transaction journal. Initial prepared/
ambiguous intent on restart is revoked; a prepared replacement candidate is discarded
while its live previous policy remains. An interrupted replacement commit repairs the
previous policy. Active unexpired state survives netd restart, and a host
boot-id change invalidates prior monotonic authorization deadlines. Persistence keeps
the device when descriptors close; carrier `LOWER_UP` can change when all queue holders
exit. This does not imply lossless service or host restart. Recovery of missing/changed
interface identity fails closed. A repeated administrator `InfraEnsure` may restore a
missing owned device after the old I/O owner exits, explicitly report a new ifindex,
and leave forwarding revoked. A changed existing device is never silently adopted.

The socket UID/GID is the privileged control capability. Run business workers without
access to this socket or that identity. The I/O process needs only the fd acquisition
channel; future role-specific capability delegation must be installed before sharing
the control UID across untrusted workers. No Core/Agent capability is inferred merely
because this service supports v2.

This opt-in journal format is still experimental and has gained marker/pending-prefix
fields. An older v2 prototype journal is not a supported production migration source;
prepare a fresh isolated installation or explicit administrator migration. Production
v1 journals/codecs remain unchanged.

## Integration

`candy_netd_client::v2::InfrastructureClient::exchange(Operation)` returns the response
body and zero/one descriptor; errors are structured `code/module/reason`. Query durable
state after an ambiguous response. `Body::IoFd` carries `InfraSpec.infra_id/generation`,
`ifindex` and `io_epoch`. Bind packet IPC to these infrastructure fields plus
`ForwardOwner.domain_id/worker_epoch/signed_generation`; `ifindex` is acquisition evidence,
not a substitute for generation or an identity carried on every packet.

Agent must prepare/commit the TUN I/O domain snapshot and epoch before activating
forward steering. TUN I/O rejects expired/old-epoch packets independently while Agent
is unavailable. Netd does not participate in per-packet processing. No extra per-worker
window or duplicated whole-pool budget is allocated by these control operations.

## Tests

```sh
cargo test --locked -p candy-netd-proto -p candy-netd-client -p candy-netd
cargo clippy --locked -p candy-netd-proto -p candy-netd-client -p candy-netd --all-targets -- -D warnings
```

The ignored kernel test requires a dedicated isolated Linux network namespace,
`/dev/net/tun`, writable namespace sysctls, `CAP_NET_ADMIN` and `iproute2`:

```sh
CANDY_NETD_ISOLATED_KERNEL_TEST=1 cargo test --locked -p candy-netd --test infrastructure_v2 -- --ignored --nocapture --test-threads=1
```

Never run this test on a production host. It creates, changes and explicitly retires
`candy0` inside the isolated namespace. A default Docker network namespace with a
dedicated privileged test container is suitable; host networking/PID namespaces are not.
The kernel test validates real TUN/interface/route behavior, including candidate
preparation, changed policy commit, expiry, restart and duplicate FD denial. It does not
validate throughput, multi-worker
ownership or a signed production installation. The release gates remain separate.
The creation test SIGKILLs a subprocess before create, after create, after marker and
after persistence, then injects an external unmarked device to prove refusal. The prefix
test compares the healthy route, policy rules and TUN before/after failure and recovery.
Run these tests sequentially because they use the same isolated `candy0`/routing table.
