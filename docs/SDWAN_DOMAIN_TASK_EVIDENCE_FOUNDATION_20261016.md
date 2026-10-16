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

## Actual Linux socket gate

`signed_cli_shared_domain_evidence_socket_gate` creates an actual shared Core
host and two signed SD-WAN tasks over Unix sockets and SCM_RIGHTS. The fixture
compiles each signed configuration and takes the routing domain and policy
generation from the compiled control report. Transport retry targets use the
isolated namespace's private address; this gate makes no forwarding or performance claim.
Each task also completes the actual authenticated per-domain management Probe
registration before readiness is accepted. Its reply must match the host's
current PID/start ticks, the original controller identity, epoch 1 and nonce;
shared-host lifecycle probes alone cannot acknowledge this registration.

The original controller inspects, binds and queries the actual host-created
task incarnation. The gate rejects changed owner/checksum/incarnation values
and a second real controller process authenticated by SO_PEERCRED. It observes
completion after cancellation and actual task join, verifies repeated queries,
rejects retroactive binding and forgetting pinned evidence, and checks that the
other real task remains running with the same authority and packet binding.
It also reuses an unbound task's instance path and requires a new incarnation.
Host death makes the socket unavailable; it does not manufacture completion.

The fixed checksum and owner submitted here are **controller association test
inputs**, not proof of a master-issued lease, original candidate installation,
or owner retirement. The API remains disconnected from Prepare and cannot
authorize a terminal transition. This gate does not close UNKNOWN P0.

Run against frozen Linux artifacts with a fresh evidence directory:

```sh
python3 scripts/shared_pool_gate.py /absolute/fresh/evidence \
  signed_cli_shared_domain_evidence_socket_gate --build /absolute/frozen/build
```

Evidence includes `domain-task-evidence.json` and the runner's test result.
At source submission, Linux execution is **NOT_RUN** pending the coordinated
frozen build. Native Python syntax and Rust formatting checks passed, as did
`cargo check --target x86_64-unknown-linux-musl --test signed_cli` for the actual
Linux fixture. Strict cross-target Clippy is blocked by unrelated preexisting
`obfuscated_if_else` warnings in `tests/fixtures/shared_listener.rs`; no strict
Clippy pass or real Linux execution is claimed.

Registration follow-up source validation passed the Linux-target check and
Clippy with `-D warnings -A clippy::obfuscated-if-else`; the allowance isolates
the already documented unrelated fixture lint and is not a strict whole-target
Clippy pass. Real Linux execution remains pending the frozen artifact gate.

The first v16 Linux execution failed before task startup: production transport
validation correctly rejected the fixture's loopback placeholder endpoint.
The fixture now configures `10.200.0.2/24` on its own bridge inside the runner's
disconnected Linux network namespace and signs `10.200.0.2:18443`, following
the existing shared-pool fixture. Its RAII guard removes only that test link.
No production validation is weakened. The v16 failure remains evidence; the
corrected fixture awaits a newly frozen helper and actual Linux rerun.
