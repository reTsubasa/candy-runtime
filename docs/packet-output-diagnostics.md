# PacketOutput admission diagnostics

## Queue drain correction (2026-10-14)

Core commit `123fb58` supplies the shared writer correction. A reusable batch
drains up to 64 packets through nonblocking writes before yielding; blocked
writes wait on readiness. Epoch and deadline checks precede every packet, and
expired queued packets never invoke the port. The deadline branch also wins
when a waiting writer becomes ready together with its deadline. Previously,
`timeout_at` could poll a ready inner send before noticing an elapsed deadline.
Packet/byte credits remain held through queued and in-flight work, then release
on send, drop or cancellation. The limits remain 256 packets / 512 KiB / 100 ms.

The v4 diagnostic's slot exhaustion with zero byte/channel exhaustion proves
local packet admission pressure. It does not equate this queue with the 64 MiB
QUIC window or establish that a larger queue improves throughput. The patch
removes avoidable ready-write futures, batch allocations and late writes;
upload/download throughput, CPU, residence, drops and overload recovery still
require the same-build performance gate. Narrow tests confirm expired packets
do not touch the fd, ready queued writes preserve order across batches, fencing
prevents old-epoch writes, and all credits recover.

The vendored public `candy-packet-port` package exposes counters that split packet output admission failures into slot, byte-credit, and channel-full causes, plus queue depth/high-watermark and nonblocking write-blocked observations. Existing limits and behavior remain unchanged: 256 packets, 512 KiB byte credit, and a 100 ms write deadline. These fields are diagnostic evidence only and do not alter admission, retry, or fail-open behavior.

Admission classifications overlap the enqueue error already counted by the caller. SD-WAN Core status exposes these as independent `tun_output_queue_slot_exhausted`, `tun_output_queue_byte_exhausted`, and `tun_output_queue_channel_full` fields, outside `drop_reasons`. Runtime bridges already record a rejected enqueue once in `queue_drops`; they must not add classifications from `OutputDelta` again. Output folding alone owns asynchronous backpressure, deadline and stale-epoch drops, which occur after admission.

## Direction and timing evidence

TUNIO writes a separate diagnostic sidecar at `status.with_extension("outputs.json")`, for example `tunio-status.outputs.json` beside `tunio-status.json`. It includes `bridge_outputs.to_worker` (TUN → worker IPC) and `bridge_outputs.to_tun` (worker IPC → TUN). Each direction records successful packets/bytes, independent admission classifications, asynchronous drops, queue depth/high watermark, and nonblocking write-blocked observations. Counters accumulate for the infrastructure process lifetime across worker replacement; `bridge_outputs.binding` identifies the current owner (including `owner_epoch`) and is cleared after revoke. `revision` and `sampled_elapsed_millis` identify periodic samples. Direction counters overlap the existing bridge aggregates and must not be added to them.

Only queued writes have timing instrumentation; the direct nonblocking fast path retains its existing overhead. `queued_write_attempts` counts attempts, `queue_wait_micros`/`queue_wait_max_micros` measure residence before the queued send starts, and `send_elapsed_micros`/`send_elapsed_max_micros` measure the awaited send including scheduler/reactor delay. These are wall-clock observations, not pure syscall durations. Core exposes the same timing fields with the `tun_output_` prefix for its output toward IPC. Totals and maximums help distinguish slow consumer admission, scheduler delay, and blocked TUN writes; averages must use counter deltas from the same direction and interval.

Bridge sampling runs once per second and folds each output delta once. TUNIO publishes a maximum 16 KiB sidecar from a dedicated thread without taking the controller mutex. The file is private (0600) and replaced by atomic rename, without `fsync`; it is volatile evidence, independent of durable authorization records. Slow or failed snapshot storage cannot hold the control lock needed for owner attachment or authorization renewal. Publication errors emit `code=bridge_status_publish_failed module=tunio_control action=keep_packet_service`; packet forwarding continues. These diagnostics do not relax packet/byte limits, deadlines, owner authorization, or policy fencing.

The sidecar contains `schema_version=1`, `pid`, `process_start_ticks`, and absolute `CLOCK_MONOTONIC` `report_monotonic_millis`. A reader must match PID/start ticks against the current infrastructure record and check report age and sample revision; an old sidecar is never proof that the current process or owner is healthy. Read `bridge_outputs.binding` to attribute observations to an owner epoch. A process crash can lose evidence since its last sample; cumulative direction counters survive orderly owner replacement because both writer tasks are stopped and joined before their final deltas are collected. Queued packets canceled by owner revoke are not successful transmissions and must not be inferred from sent counters.
