# Experimental independent TUN I/O

This is an explicitly gated prototype. The normal Runtime launch
and packaging paths continue to use the existing netd v1 integration.

`candy-tunio` acquires its own netd v2 descriptor, preserving the actual holder
PID in netd's ownership record. The Agent creates a connected Unix datagram
socket pair; the worker receives only its IPC endpoint. The immutable binding
contains infrastructure/domain identity and infrastructure/I/O/owner/policy
generations. The shared implementation lives in Core's lightweight `candy-packet-port`.
The prototype requires a sibling `candy-core` checkout at the matching revision.

The I/O process keeps draining TUN when the worker disappears or authorization
expires. Its TUN writes have their own deadline check and cancellation, so a
blocked write cannot complete after the authorization deadline. Only explicit
infrastructure retirement removes the persistent interface.

The Agent command is:

```sh
candy-sdwan-agent experimental-packet-port-run \
  --experimental-packet-port-ipc --plan /absolute/private/plan.json
```

The 0600 current-user plan contains `schema_version: 1`, absolute paths for
`netd_socket`, `tunio`, `core`, `core_config`, `core_status`, `binding_file`, a
16-byte `instance_id`, a netd v2 `infrastructure` spec, 16-byte `domain_id`,
`io_epoch`, `worker_epoch`, `fencing_token`, `signed_generation`,
`auth_deadline_unix`, and the validated netd `declaration`. The binding file
must be a new path. Core's initial status generation is the signed policy
generation; this need not equal the infrastructure generation.

Before changing netd, the Agent runs real Core `compile-control` with a ten second
timeout and bounded output. It verifies domain, generation, exact routes, MTU,
address and signed underlay exclusions. The administrative deadline can only
shorten the minimum expiry of verified segment/projection/Grants.
It is not ready for normal releases or production. Original-authorization Core
replacement and packet-port rebinding are available only in the explicit unified
Agent prototype with the `experimental-tunio-rebind` build feature. Production
platform supervision and fresh signed authorization renewal remain incomplete.
Core keeps `PDEATHSIG`; TUN I/O keeps it unless the plan explicitly declares
`independent_supervision` with absolute `control_socket`, `status` and
`process_record` paths. Those endpoints require current-user 0700 parent
directories, and detached authorization is limited to one hour.
The detached TUN I/O has an authenticated local control challenge. A replacement
Agent may adopt it only after the previous controller's PID/starttime is dead:

```sh
candy-sdwan-agent adopt-tunio --experimental-packet-port-ipc \
  --record /absolute/private/io-process.json \
  --expected-executable /absolute/path/candy-tunio \
  --control-socket /absolute/private/io-control.sock
```

Adoption verifies executable identity, process epoch, private status/token and
authorization before changing controller epoch. It does not reacquire the TUN
descriptor or extend authorization. An expired authorization keeps draining
without forwarding. Only the current controller may request Stop.
An explicit `independent_worker` object with absolute `control_socket` and
`process_record` paths additionally enables independent business Core ownership.
It requires independent TUN I/O. Core verifies the signed deadline itself,
authenticates the parent socket identity and publishes its private control endpoint.
It clears `PDEATHSIG` on its original thread only after the Agent persists its
actual process record and sends the authenticated registration Probe. It stops
its own forwarding at the earliest signed or
administrative expiry, even with no Agent running. Agent replacement uses:

```sh
candy-sdwan-agent adopt-packet-port-worker --experimental-packet-port-ipc \
  --plan /absolute/private/plan.json
```

Takeover preserves Core PID, packet binding and signed generation, advances
controller epoch and netd fence, applies the current complete failure snapshot,
and renews only the bounded forwarding lease. It cannot renew signed authority.

For statically configured multi-domain netd, `routing_namespace` identifies the
precreated namespace. Agent checks its inode/device, starts Core/TUN I/O there,
and scopes netd requests to domain+infrastructure. Only TUN I/O receives the fd;
the privileged manager validates the actual holder's namespace. Namespace and
domain resource budgets must be configured explicitly.
The `inspect-managed-process` command validates evidence only; it does not
adopt, signal, or alter the process or netd state.

Build and unit-test the excluded prototype explicitly:

```sh
cargo test --manifest-path linux/common/apps/candy-tunio/Cargo.toml --locked
```

The ignored `linux_infrastructure` test starts real netd v2 and TUN I/O binaries
inside an isolated Linux namespace. It requires `/dev/net/tun`, `CAP_NET_ADMIN`,
`ip`, `ping`, `CANDY_NETD_ISOLATED_KERNEL_TEST=1` and an absolute
`CANDY_NETD_TEST_BINARY`. Never run it in a production network namespace.

The real-kernel tests prove local descriptor ownership, packet transfer,
interface preservation and actual Agent adoption. The adoption test also needs
`CANDY_AGENT_TEST_BINARY`, the actual Runtime Agent executable. These tests do not
prove WAN throughput. The separate signed CLI recovery test covers Core replacement.

The ignored `signed_cli` tests use actual signed Core CLI clients and server,
real QUIC and two actual TUNs. `CANDY_CORE_TEST_BINARY` and
`CANDY_SIGNED_FIXTURE_BINARY` point to the real Core and its
`sdwan_signed_cli_fixture` example. They prove same-generation peer recovery,
Grant tamper rejection, minimum signed expiry, and actual independent Core/IO
Agent takeover followed by expiry without retiring infrastructure. A scoped
namespace variant exercises the multi-domain Agent/TUN I/O integration.

The gated unified Agent prototype runs the Cloud library and static domain
supervisors in the same process:

```sh
candy-sdwan-agent experimental-runtime-agent \
  --experimental-packet-port-ipc --config /absolute/private/runtime-agent.json
```

Its private 0600 configuration declares `schema_version: 1`, `status`,
`domain_plans`, a `cloud` object (absolute `state_dir`/`run_dir`, optional identity,
CA/Core/config paths, public endpoints, interval and retry milliseconds), and
`budgets` with `max_domain_supervisors`, `max_managed_threads`,
`thread_stack_bytes`, `max_managed_stack_bytes`, `event_capacity`,
`cloud_iteration_deadline_ms`, `shutdown_timeout_ms`. Status requires a current
user 0700 parent. One Cloud thread plus one thread per static domain is admitted
before spawning. These are declared managed thread/stack/notification budgets,
not enforced global RSS limits. Separate legacy Cloud/Agent units must be disabled
before a production migration; the prototype does not change platform units.

Cloud errors retry with bounded backoff and preserve domain tasks. A live Cloud
call is never replaced or entered concurrently. Cancellation checkpoints and
HTTP request deadlines are available, but OS DNS and filesystem calls are not
hard cancellable. Shutdown reports an incomplete drain honestly if its budget
expires. Fixed notification capacity coalesces updates and retains full latest
task state. A real signed QUIC/TUN test verifies that repeated Cloud identity
failures do not prevent same-generation peer recovery and real ICMP traffic.

Recovery revalidates existing records before activating: complete live Core/I/O
pairs are adopted. With the explicit Linux `experimental-tunio-rebind` feature,
dead Core plus live I/O uses authenticated Attach/Revoke/Probe to install a new
Core with a new owner epoch under the original signed deadline. Live Core plus
dead I/O is still preserved without reverse recovery. Missing/stale records with
a kernel-authenticated live private endpoint delay replacement; this inspection
does not authorize adoption. Transient failures retry; invalid signed/configuration
inputs wait for a changed plan. The real signed test kills Core twice and Agent
once, verifies actual ICMP recovery, and preserves the original I/O PID, TUN and
expiry. New-Grant renewal and production platform migration remain incomplete.
