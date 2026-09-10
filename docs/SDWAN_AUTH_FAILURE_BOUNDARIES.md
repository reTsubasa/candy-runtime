# SD-WAN Authentication and Failure Boundaries

Standalone Proxy PSK users are an explicit, unenrolled-server deployment mode.
They are not a fallback identity for Cloud-managed SD-WAN or its Proxy traffic.

## Authentication

- Enrolled servers launch only validated Cloud-managed activations.
- Missing, dangling, invalid, withdrawn or rejected candidates never start the
  standalone configuration. Unenrollment is an explicit operator operation.
- The agent never launches a standalone server during rollback or retry.
- Generated server activations inherit listener/TLS/transport settings, not
  `users`. Server activation format v3 replaces legacy immutable v2 artifacts;
  the sync-state revision forces a full fetch even when the Cloud ETag is unchanged.
- Core Cloud Grant listeners reject PSK AuthProof before accessing PSK users.
  Cloud-authorized Proxy and signed SD-WAN tunnels can share a listener without
  sharing the standalone PSK authentication path.

## Failure Classification

| Evidence | Handling |
| --- | --- |
| Packet streams opening | Wait; no route admission before ready-owner evidence |
| Initial peer loss | Bounded readiness wait followed by activation retry |
| Committed peer loss | Retain authenticated Core and withdraw affected steering |
| netd connection loss, system failure, generation contention | Rollback/reconcile and retry with bounded exponential backoff |
| Core executable temporarily missing, IPC EOF or timeout | Retry without rejection receipt or standalone child |
| Grant outage, expiry, not-yet-valid | Do not admit credentials; retry resolution without rejecting signed policy |
| Local publication failure | Leave delivery unacknowledged and retry |
| Invalid signature/scope, unauthorized IPC, malformed protocol/config/status | Fail closed; never reinterpret as successful authentication |
| Commit outcome uncertain | Preserve candidate and reconcile the transaction; never report it permanently rejected |

Retries revalidate the immutable activation binding and expiration; withdrawal,
supersession or shutdown cancels retries. No retry bypasses signature validation.

## Verification

Run the complete `candy-sdwan-agent`, `candy-cloud-sync` and Core
`candy-carrier-server` test suites, plus `linux/server/tests/candy_server_launcher_test.sh`.
The Core suite exercises real QUIC PSK rejection and Cloud Grant acceptance.

Production rollout must include both Runtime and Core. Do not relabel existing
signed release assets. Check regenerated activations contain no `users`, running
processes use activation `core.toml`, and peer/stream readiness and traffic recover.
