# Mixed Role Fault Isolation Gate

## Scope

This test extends the real two-domain shared-listener fixture. Each SD-WAN
domain uses actual Runtime Agents, netd, Linux namespaces and TUNIO. Proxy uses
the production Runtime `candy-client` launcher and the same frozen Rust Core
ELF as the listener. Proxy and SD-WAN enter the same QUIC listener.

The exact ignored test is
`signed_cli_mixed_role_quota_and_slow_consumer_isolation` in the `signed_cli`
test binary. Its Python workload is embedded with `include_str!`, so a frozen
test helper contains the exact workload. `CANDY_PROXY_CLIENT_BINARY` must name
the frozen Runtime launcher; `CANDY_CORE_TEST_BINARY` selects the Core ELF.
The isolated shared-pool runner records the launcher hash and mounts its copy
read-only. This test must run in disposable privileged Linux only.

## Assertions

1. Two real SD-WAN domains activate with exact committed listener receipts and
   carry ICMP before faults. Continuous 10 Hz ICMP then runs through the quota,
   recovery and slow-consumer phases. Each domain requires at least 20 offered
   packets and exact transmitted/received equality with zero reported loss.
2. The fixture requests six global transports and two Proxy PSK-principal
   transports. Two independent Runtime clients carry verified TCP bytes. A
   third must produce an explicit post-auth principal-capacity rejection in
   the master's log. A silent timeout does not satisfy quota exhaustion.
3. While quota is exhausted, the original held TCP flow remains usable,
   twenty fresh TCP sessions return exact bytes, and twenty distinct 4096-byte
   UDP payloads return once. The generator performs no retransmissions.
4. Releasing the extra client lets a new independent Runtime client carry
   verified bytes within fifteen seconds. Existing TCP/UDP are checked again.
5. A new TCP flow on the original authenticated Proxy transport targets a real
   accepted socket whose application never reads. The target receive buffer is
   4096 bytes. The sender must write nonzero data and observe at least two actual
   socket-write timeouts before the independent traffic phase begins. The
   workload stops after at most 256 MiB and has a fifteen-second pressure bound.
   Mere sleep or opening an idle connection does not satisfy pressure evidence.
6. Under that pressure, the held TCP, twenty fresh TCP sessions and twenty
   single-send 4096-byte UDP requests must still succeed. The original UDP
   worker PID/start time, egress socket inode and source port must be identical.
7. All four SD-WAN worker records and infrastructure TUNIO records, both client
   TUN ifindices, master identity, exact Proxy worker population and current
   SD-WAN activation ACKs must survive unchanged. Automatic replacement would
   fail this isolation gate even if later traffic recovered.

Warmup readiness and quota recovery have explicit bounded retries. Traffic
inside the fault phases has one attempt per request and no retry conversion.
The evidence includes JSON counters, original UDP owner identity, continuous
ICMP logs, all client/server logs and the existing fixture state capture.

## Execution Status

Implemented on 2026-10-16. Local Python syntax/parser tests and Rust formatting
are developer checks only. The real combined gate has **not yet run** at this
commit; it requires the coordinator's next immutable Linux helper freeze.
This document claims no throughput, long-duration, physical-platform or
production acceptance.
