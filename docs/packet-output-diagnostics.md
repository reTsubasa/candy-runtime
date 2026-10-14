# PacketOutput admission diagnostics

The vendored public `candy-packet-port` package exposes counters that split packet output admission failures into slot, byte-credit, and channel-full causes, plus queue depth/high-watermark and nonblocking write-blocked observations. Existing limits and behavior remain unchanged: 256 packets, 512 KiB byte credit, and a 100 ms write deadline. These fields are diagnostic evidence only and do not alter admission, retry, or fail-open behavior.

Admission classifications overlap the enqueue error already counted by the caller. SD-WAN Core status exposes these as independent `tun_output_queue_slot_exhausted`, `tun_output_queue_byte_exhausted`, and `tun_output_queue_channel_full` fields, outside `drop_reasons`. Runtime bridges already record a rejected enqueue once in `queue_drops`; they must not add classifications from `OutputDelta` again. Output folding alone owns asynchronous backpressure, deadline and stale-epoch drops, which occur after admission.
