# PacketOutput admission diagnostics

The vendored public `candy-packet-port` package exposes counters that split packet output admission failures into slot, byte-credit, and channel-full causes, plus queue depth/high-watermark and nonblocking write-blocked observations. Existing limits and behavior remain unchanged: 256 packets, 512 KiB byte credit, and a 100 ms write deadline. These fields are diagnostic evidence only and do not alter admission, retry, or fail-open behavior.
