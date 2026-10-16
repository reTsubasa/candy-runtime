# Bilateral Candidate MBB Gate, 2026-10-16

## Scope

This disposable, disconnected Linux Docker gate uses two real Rust Core
clients with netd-owned TUNs. On the server, two Runtime Agent domain workers
and independent TUNIO processes share the actual authenticated listener with
Proxy traffic. Each client performs two signed successor-policy reloads.

The path uses the installed predecessor's authenticated control lane for
ReserveCandidate, receives the current master's admitted candidate selector,
opens a separate candidate transport, verifies signed successor documents and
OPEN authorization, prepares the actual packet stream, then completes
Install, Activate and Drain on both packet actors. An exact duplicate local
commit must return the same outcome.

This is the in-process Core replacement gate. It does not certify Runtime
cross-process candidate handoff, production deployment, OpenWrt or throughput.
Runtime managed PacketPort workers use a separate candidate coordination API;
they deliberately cannot use the ordinary reload socket.

## Findings

1. A completed responder remained under the staged transaction deadline. Its
   eventual exit would close the newly active transport. The responder now
   hands its existing control owner and sole message receiver to ordinary
   reservation service. Exact Commit/Activate/Drain reply receipts are retained
   only until the original authorization cap; receipt expiry does not close
   the active lane.
2. Candidate overlap needs an explicit signed connection budget. The legacy
   fixture Grant permitted two node connections, both occupied by the two
   existing domains. Candidate authentication correctly refused a third with
   `grant_connection_limit`. The gate now signs a four-connection node budget
   and an eight-connection pool budget. No admission limit is bypassed. A
   deployment must budget active connections plus bounded replacement overlap.
3. Candidate negotiation bits are transport control capabilities, rather than
   Grant business entitlements. Adding them to the Grant business mask caused
   fixture rejection. The fixture keeps the existing business entitlement
   format and separately verifies signed policy and authenticated device scope.
4. Earlier dynamic scale tests only required the continuous ping process to
   remain alive. The tightened fixture records unique ICMP sequences, missing
   replies and maximum receive gap, and rejects missing sequences at every
   scale step before fault injection. Earlier immutable results retain their
   original functional recovery scope.

## Results

| Run | Result | Evidence |
| --- | --- | --- |
| bilateral-mbb-v1 | FAIL | Incorrect fixture Grant business capability mask. |
| bilateral-mbb-v2 | FAIL | Signed node connection quota exhausted by two existing domains. |
| bilateral-mbb-v3 | PASS | Two domains, two successor rounds each; generations 1 -> 2 -> 3; 800/800 continuous ICMP replies; exact duplicate commits; stable Core, TUN and TUNIO identity; surviving Proxy requests. |

The v3 test ran for 22.56 seconds; the bounded harness completed in 31.765
seconds. It mounted copied binary artifacts read-only and verified SHA256
before and after copying. `binary-hashes.json` identifies all six artifacts.
The Core SHA256 is
`052cc392a811c190358109feb93efb8d3423c74b5050481172871636120a6b13`.

Linux focused coverage also passed four reservation responder tests and four
durable outbound reservation tests at the frozen boundary. Newer cross-process
transfer changes require their own updated acceptance run.

## Remaining Gate

Run the Runtime candidate coordinator across two separate worker processes,
then rerun dynamic 1/2/4/2/1 with strict sequence continuity on the final frozen
binary set. A prior binary's PASS does not certify later source changes.
