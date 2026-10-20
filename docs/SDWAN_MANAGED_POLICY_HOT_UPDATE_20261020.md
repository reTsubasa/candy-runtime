# Managed SD-WAN policy publication isolation

Date: 2026-10-20

## Problem and required behavior

Managed packet-port workers previously routed every signed catalog or route change through owner renewal. That changed the physical worker/socket even when transport, trust, infrastructure and resource contracts were identical. The new hot path publishes the policy to the existing Core actor and Netd route/nft transaction, while retaining TUN, TUNIO, packet binding, original signed physical authority, process identity and transport sessions.

A policy update is not an authorization renewal. The active policy generation/hash/revision may advance, while the physical binding generation and original authority deadline remain fixed. A shorter grant, different transport/trust/resource contract, changed placement or changed infrastructure uses authenticated make-before-break. If a later grant is available, real authority renewal is scheduled within 120 seconds of the original physical deadline.

## Transaction and recovery boundaries

1. Verify the current managed process and IO authority, including schema-3 pending owner evidence. Prepared/retained/unknown MBB authority prevents policy dispatch.
2. Verify current/desired signed reports and immutable identity hashes; capture a private immutable closure; verify it again. During bounded compile stages renew the exact existing forwarding lease within its original cap so control-plane verification does not consume the entire 30-second lease.
3. Persist the exact snapshot, target generation/hash/revision, original worker record and physical owner in a private durable journal before dispatch. New desired input cannot replace a dispatched intent.
4. Send managed Core `policy_update` with an explicit idempotent policy revision, verify exact Unix peer PID/UID/start identity, then verify durable Core status generation/hash/revision.
5. Apply Netd policy revision using the same live forwarding owner. Only after both acknowledgements publish the effective plan and process record. Shared-listener registration also carries the independent policy revision.
6. Lost/rejected ACK, status mismatch or kernel failure retains the original journal and process receipt. Retry dispatches the exact original snapshot. It does not fall back to an overlapping MBB transaction.

The journal's policy identity is immutable; its lease metadata is not. Recovery reads the current exact physical Netd owner, adopts an already advanced lease, and renews a near-expiry lease without extending authorization. It persists that lease before retrying. This fixes stale exact-owner failures after ordinary supervisor lease renewal or a delayed ACK.

An expired physical owner is not kept UNKNOWN forever once there is terminal evidence. Recovery requires the exact original IO/Netd identity, no candidate/pending authority/policy/failure transaction, a Netd Revoked receipt and an expired lease or authorization cap. It archives the complete intent together with Netd/IO evidence and observation time, preserves the signed snapshot, and allows normal authenticated renewal. The pending-policy branch and an older committed renewal journal cannot silently adopt that terminal owner.

Adoption of an already updated policy additionally verifies Netd active policy revision/generation/hash and absence of pending policy; an Active physical owner alone is insufficient. Registry ordering is scoped to physical incarnation: a new epoch may renew a Grant/hash in the same policy generation and reset revision to zero; an old epoch or a different process reusing the same epoch cannot replace it.

## Verification

Linux aarch64 Docker (`rust:1.90-bookworm`), isolated Cargo target:

- Full `candy-sdwan-agent` library suite: **157 passed**, with `experimental-tunio-rebind`.
- Real Linux Unix-socket orchestration test uses SO_PEERCRED and a real managed PID/start identity, with protocol mocks at Core/Netd boundaries. It covers rejected/lost Core ACK, mismatched durable status, Netd mutation failure after Core success, exact retry despite newer Cloud desired input, unchanged old record until final ACK, unchanged original cap/epochs/fence, prepared/retained IO authority rejection, a frozen expired lease with a current live lease, bounded lease renewal and terminal revoked lease/cap archival.
- Registration tests: **2 passed**, including same-owner revision conflict, same-generation new physical epoch/Grant/hash acceptance, old epoch rejection and same-epoch process replacement rejection.
- Final managed-policy targeted suite: **4 passed**. Final all-targets strict Clippy: **passed** (`-D warnings`). Logs are under `docs/artifacts/sdwan-20261020/managed-policy-linux/`.

These are layered gates. Core's real registry poll/catalog gate and Netd's real kernel gate are validated separately by their owners. This report does not claim a complete Runtime-to-Core-master-to-live-new-OPEN end-to-end run, production deployment, a 20-minute production traffic test, or the deferred two-hour soak.
