# Signed MBB evidence publication and unresolved peer recovery

## Evidence

Frozen scaling run `shared-pool-negotiated-final-v12` completed 1→2 workers with zero missing ICMP in all four domains. Its 2→4 stage timed out after 66.96 seconds. Domain 1 completed; domains 0, 2 and 3 reported `candidate_peer_installation_unconfirmed`, then candidate transport/lifecycle failures. After the original candidates stopped at 08:38:30 UTC, Runtime created new epoch 4 transactions, which repeatedly collided with the old workers' retained `outbound_plan`: `worker_candidate_transaction_busy`.

The exact original failed transactions were:

| Domain | Original transaction | Replacement that collided |
| --- | --- | --- |
| 0 | `400c73a669084ca7883b3ae4d9369d02` | `0bf4b115f51447b58c7af6753fa74236` |
| 2 | `a18773b3604f4959b52e20c8083abfa3` | `219800c72b3842eeadc733e35c4a0ad2` |
| 3 | `41ffa0b9d1434ce6a9ccd65f714caaea` | `8f2e7df5cf6f4a7d93cece40f810a6df` |

The later permanent busy condition is distinct from the original installation confirmation failure. Its cause is demonstrated by the preserved plans and recovery code. A second code defect can produce the earlier confirmation failure: candidate operations update the in-memory Management proof, but previously acknowledged completion without publishing the worker's bound status. Runtime immediately validates that status after Install and can encounter the previous Prepare proof with `installed=false`. Attribution of every v12 failure to that race requires the next frozen integration gate.

## Changes

Core commit `d98c236` publishes the worker status before acknowledging completed candidate operations. Publication uses the original worker status path and checks the authenticated controller PID/start time, controller epoch and authorization cap while holding the management lock. A publication failure or cancellation retains the operation, exact request, original authority and result in the existing worker. Only the same operation and authority can retry publication; it does not issue another Prepare or Install. A different operation, transaction or controller cannot consume that retained result.

Runtime durably records `mbb_peer_prepare_pending` and `mbb_peer_install_pending` before dispatch, so an uncertain Install response retries Install directly. It does not return to Prepare and overtake Core's retained completion.

Reservation expiry, a local precommit cancellation, and a failed candidate with no confirmed peer terminal outcome now retain the original reservation, candidate owner, process identity and epoch. The journal records `mbb_peer_reconciliation_pending`; the supervisor retries that original journal instead of minting a new transaction. A locally expired CommitOwner can still obtain and preserve the exact local retirement receipt, but `local_expired_remote_unknown` no longer stops the candidate or clears its reservation to permit replacement.

## Verification

- Core native worker-control tests: 8/8 PASS, including failed publication, cancelled publication, original-result retry, changed transaction/operation, and changed controller PID/start time/epoch/cap.
- Core application all-target strict Clippy: PASS with `-D warnings`.
- Runtime native application tests with `experimental-tunio-rebind`: 107/107 PASS. These macOS tests do not execute the Linux-only MBB module; existing unused-code warnings in the macOS candidate-control adapter remain.
- Added Linux-only regression `experimental_tunio::signed_renewal::linux::mbb_tests::unresolved_precommit_retains_original_reservation_and_epoch_across_restart`: verifies the journal survives re-read with the original reservation, epoch, candidate record and signed snapshot, including failed journal publication. Execution is pending the Linux gate.
- Host Linux cross-check was blocked before application checking because the machine lacks `aarch64-linux-gnu-gcc` for the `ring` build. This is not a passed Linux check.

Required Linux filter: `cargo test -p candy-sdwan-agent --features experimental-tunio-rebind signed_renewal::linux::mbb_tests`.

## Original-tuple read-only reconciliation

The authenticated worker-control endpoint now accepts `candidate_reconcile` for the retained original plan. It checks the original transaction, signed authorization, controller and owner identity. The operation queries the original actor with Probe; it does not read the original barrier reply receiver, issue another Prepare/Commit/Abort, renew the original operation cap, or clear the reservation. Local actor phase is reported separately from the remote outcome. An absent remote receipt remains `unknown`, including when the local actor reports Installed.

After validating CommitAck on the original authenticated control stream, Core retains the ACK in memory before the first persistence await. It publishes an immutable private `.outbound-installed` receipt containing the exact selector, barrier, connection identity, local/peer attachments, Reserve/Reserved hashes and encoded ACK. Failed or cancelled persistence can retry the same historical ACK without consuming the only ACK or sending another Commit. Publishing already authenticated history after operation-cap expiry does not authorize further installation or extend the cap.

Each live-session reconciliation re-reads the actual private `.outbound-installed` file and verifies its original request/response hashes, ACK, connection and attachment binding. It does not trust a cached receipt. A missing file reports remote UNKNOWN; corruption fails reconciliation while preserving the original transaction. If the actor Probe fails, the response records that query error separately and can still report a fully verified historical peer ACK.

Runtime checks the read-only response against the preserved original reservation, boot, deadline, transaction, owner epoch, expected peer coverage, selector, barrier and original Reserve/Reserved hashes before saving `mbb-peer-reconciliation.json`. It uses the authenticated Core endpoint's validation of the encoded wire ACK; it does not implement a second wire parser. This evidence is diagnostic history and is never a substitute for a live installation proof or PacketPort commit authority. Within the original effective window, a failed Install continues the original Install phase. Outside that window the same journal remains pending.

This first reconciliation step deliberately does not recover a lost process's transport, reconstruct a session from an ACK file, provide a remote terminal/cancellation receipt, or infer safe replacement from an expired local owner. Those remain separate implementation and fault-gate requirements.

Native verification of this step: Core candidate tests 6/6 passed; application all-target strict Clippy passed. Runtime full native library regression passed 110/110. The two new `candidate_ownership` tests are Linux-only: the native filter selects zero tests, so their execution and Linux MBB integration remain pending the next frozen Linux gate. The Core historical receipt regression checks actual file re-read, immutable exact retry after expiry, all original tuple mutations, wrong ACK type, corrupted saved hash rejection and missing-file UNKNOWN.

## Remaining OPEN items

The current wire protocol does not provide an authenticated, durable peer terminal receipt for a failed reservation before coordinated drain. Reservation expiry or absence of a local PacketPort commit does not prove that the remote actor never installed. Such transactions intentionally remain unresolved; this change prevents destructive recovery and does not claim automatic recovery for them.

A complete follow-up requires original-tuple peer outcome probing or cancellation/terminal acknowledgement, persistence before permitting a new reservation, and recovery after controller/worker restart without changing the original connection identity or extending the original cap. The separately implemented committed-owner isolation path also needs review of remote transaction finalization. No forced switch, timer-based inference of UNKNOWN, deletion of original evidence, production restart, or relaxed acceptance threshold is part of this change.

The next frozen Linux run must validate repeated shared-pool scaling, exact-operation publication retries, original-candidate preservation, and unchanged TUN/forwarding continuity. Full acceptance remains OPEN until those gates pass.
