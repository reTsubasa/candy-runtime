# Shared Domain Task Evidence API, 2026-10-16

Partial UNKNOWN P0 Stage 1 foundation only; Prepare does not consume this API.
`shared_worker::domain_evidence::EvidenceClient` uses the existing authenticated,
bounded Unix exchange and requests the host's explicit schema 2 evidence API.
Schema 1 ordinary replies remain unchanged.

The client pins the actual host process/boot/incarnation, original Runtime
controller PID/start ticks, exact task incarnation, and controller-submitted
candidate-record checksum plus complete SD-WAN TransportOwner. Query failures,
host death/restart, task absence, reused paths or changed controller/association
produce errors; none produces completion. Only the host's actual joined thread
result can appear as completion. `result_unavailable` and `panicked` do not prove
successful cleanup, and no result proves a master revoked its transport lease.

Runtime lacks the exact Core CandidateJournalRecord checksum today. The caller
must receive it from authenticated Core control before binding; deriving it from
current Runtime authorization/selector/reservation data would invent history.
There is no automatic terminal, replacement permission, successor-controller
takeover, or durable evidence release in this API. Original controller loss
remains UNKNOWN, even for a successor with the same UID.

Pinned task evidence currently prevents host `forget` and host retirement. The
explicit host capacity bounds memory but cannot resolve lifecycle; a durable
exact terminal acknowledgement and release protocol is required before wiring
this into production Prepare. Unbound current traffic keeps existing behavior.
The host evidence is not persisted across host death; that case remains UNKNOWN.

Core implementation and detailed design:
`candy-core/docs/sdwan-domain-task-evidence-foundation-20261016.md`.

Native client validation tests **3/3** and shared-worker subset **4/4** passed.
The Linux endpoint and real process evidence gates remain open. Unrelated
concurrent `candidate_core_control.rs` native dead-code warnings remain outside
this scope; strict Runtime Clippy is not claimed.
