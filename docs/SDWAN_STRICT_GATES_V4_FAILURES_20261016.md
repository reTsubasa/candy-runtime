# Strict SD-WAN gates: frozen v4 failures

## Build boundary

Both isolated Linux gates used identical immutable binary snapshots built from
committed Core `010c949a09c0cbff50e2874c48504b80a7611d38` and Runtime
`3fa857c7c8b0865a0f801581e706566358199ea4`. The source manifest SHA-256 is
`ab7d4a7bc546ea09900458803659f80af11fd934299dc869d12269641216caa7`.
Runtime Agent included `experimental-tunio-rebind`. Each gate's `result.json`
records all six binary hashes. No production service was changed.

## Dynamic 1/2/4/2/1 gate: FAIL

Evidence: `artifacts/sdwan-20261016/shared-pool-negotiated-final-v4/`.

The strict gate failed on the first transition; it does not accept the full
sequence. One domain completed an actual negotiated drain (`agent.log:140`),
but the other domains could not complete ownership migration. The failure
chain is visible rather than inferred from the harness timeout:

- Server candidate drivers rejected remote fences as stale
  (`server-agent.log:93`, `:98`, `:99`). The responder compared a remote
  candidate's fence against an unrelated local Runtime supervisor floor.
- Prepare uncertainty discarded the initiator session. A new connection with
  the same transaction then collided with its durable candidate identity
  (`agent.log:107` onward).
- Retiring snapshots contained retained candidate transaction evidence. A
  directory-not-empty error terminated domain supervision as nonretryable
  (`agent.log:395` onward).

Fixes require independent remote fence scope, retaining the exact original
candidate connection across retries, and retiring only snapshot-owned files
while retaining transaction evidence. Core `d34f6bc` implements the connection
retention; Runtime `9eb4698` implements snapshot retirement. A fresh complete
gate must accept the combined changes before dynamic scaling is accepted.

This fixture migrates four independent signed domains across shared worker
hosts. It does not demonstrate concurrent sharding of one domain's peers.

## Successor server restart gate: FAIL before restart

Evidence: `artifacts/sdwan-20261016/successor-server-restart-v1/`.

The continuity assertion failed with 399/400 ICMP replies in domain 0 (0.25%
loss), before the server process restart phase ran. Therefore this execution
does not accept restart recovery, despite the earlier bilateral gate passing.

Server logs show `lane_drain_input_pending`, predecessor packet-stream send
queue closure, transport revocation/reconnection and `route_has_no_active_peer`
(`agent-server.log:58`, `:61`, `:80`). These are real packet-path failure
observations. The loss is not classified as environmental scheduling noise.
After the combined fixes, rerun with the lossless assertion intact; if closure
persists, investigate predecessor ownership and drain/stream task lifetime.

Both failed test containers were reaped. The failure evidence must remain
available alongside subsequent attempts, without overwriting these results.
