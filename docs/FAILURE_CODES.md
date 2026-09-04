# Candy Runtime failure codes and ownership

The data planes are independent. A code beginning with `sdwan_` may stop or
rollback only SD-WAN-owned state; it must not stop the ordinary Candy Proxy.
Proxy errors are reported as `proxy_*` and remain local to the Proxy module.

| Code | Meaning | Owner | Recovery |
| --- | --- | --- | --- |
| `proxy_listener_missing` | Proxy Core is not listening on its configured listener | Proxy | restart Proxy only |
| `proxy_session_open_failed` | Proxy session admission or stream open failed | Proxy | retry node selection; retain SD-WAN |
| `proxy_stream_reset` | An established Proxy stream was reset | Proxy | close the flow and reconnect the node |
| `proxy_no_data_plane_evidence` | Node is connected but has no successful session/probe yet | Proxy | show standby; do not claim healthy traffic |
| `sdwan_prepare_failed` | netd rejected the SD-WAN transaction during prepare | SD-WAN | rollback transaction; keep Proxy |
| `sdwan_reconfigure_invalid_transition` | SD-WAN hot reload attempted an invalid owner transition | SD-WAN | retain last-good generation |
| `sdwan_reconfigure_platform_failed` | Platform preflight rejected the SD-WAN declaration | SD-WAN | retain last-good generation |
| `sdwan_core_readiness_lost` | SD-WAN Core lost readiness after commit | SD-WAN | suspend SD-WAN steering and retry |
| `sdwan_peer_loss` | All required SD-WAN peer lanes are unavailable | SD-WAN | fail over to Proxy or local WAN |
| `sdwan_rollback_failed` | SD-WAN-owned netd state could not be rolled back | SD-WAN | retry cleanup; never invoke Proxy fail-open |
| `cloud_sync_waiting` | Cloud activation cannot be evaluated yet | Cloud sync | preserve last-good activation |
| `public_endpoint_required` | Server public endpoint is missing | Cloud sync | fix environment and retry |

## Release gate

Before publishing a Runtime/Core pair, run:

```sh
./scripts/runtime_preflight.sh /path/to/candy-core /path/to/candy-runtime
```

The gate checks the Core process API, the independent Proxy/SD-WAN lifecycle
contracts, and the regression tests. A release is rejected if SD-WAN cleanup
contains a call to the global Proxy fail-open path.
