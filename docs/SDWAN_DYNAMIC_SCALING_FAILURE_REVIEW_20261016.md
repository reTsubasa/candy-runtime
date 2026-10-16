# Dynamic scaling failure review (2026-10-16)

## Scope and status

Isolated Linux Rust Runtime client, shared Core host and four domains. Required
scale sequence is 1/2/4/2/1. Production nodes were not restarted or modified.
The final strict gate has not passed; the committed fixes below require one
new integrated immutable build and rerun. No failure below is waived.

## Preserved evidence

All paths below are under `docs/artifacts/sdwan-20261016/`.

| Run | Result | Finding |
| --- | --- | --- |
| `shared-pool-negotiated-final-v5` | FAIL | Domain 0 lost one ICMP packet during workers=2 handoff; highest sequence 94, received 93, maximum gap 3.979 seconds. Unsolicited prepared replacement could retire the active lane before the staged transaction committed. |
| `shared-pool-negotiated-final-v6` | FAIL | Test helper referenced `/build/debug/candy-tunio`, but only `/build/release` was mounted. Initial convergence never completed. |
| `shared-pool-negotiated-final-v7` | FAIL | Assertion ran after placement promotion but before asynchronous bilateral drain completed. Final evidence subsequently contained exact committed/drained receipts for all four domains. The immediate assertion failure remains recorded. |
| `shared-pool-negotiated-final-v8` | FAIL | Independent helper bundle lacked `source-freeze.json`; preflight rejected it before traffic. |
| `shared-pool-negotiated-final-v8b` | FAIL | Initial domain control proof timeout stopped live owners; scale loop was not reached. |
| `shared-pool-negotiated-final-v9` | FAIL | Same initial control failure. Two domains recovered through pair replacement; two remained stopped because shared completion EAGAIN lost its typed cause and was classified terminal. Scale loop was not reached. |

## v9 cause and ordering

`shared-pool-negotiated-final-v9/shared-pool-state/agent.log` records:

- By 06:41:49 UTC all four authenticated QUIC peers were active. Only two
  `packet_port_activation_committed` messages were published.
- At 06:41:52.042 two Core control replies failed with Broken pipe.
- At 06:41:52.078-52.083 domains 1/2 closed and emitted
  `shared_domain_stopped`; supervisor then reported process-control EAGAIN with
  `retry=true`.
- At 06:41:54.232-54.247 domains 0/3 closed and emitted
  `shared_domain_stopped`; supervisor then reported naked EAGAIN with
  `retry=false`.
- Server transport IPC/owner revocation follows the client stops. It does not
  establish a server-originated QUIC failure as the initial cause.

Source inspection finds `worker.try_wait()?` and the initial authenticated
controller `Probe` use `?` inside the bootstrap closure. Either timeout leaves
the closure. Cleanup then unconditionally stops the business worker, revokes
the forwarding owner and stops/releases TUNIO. A failure to observe a healthy
worker was therefore converted into a deliberate data-path failure.

The exact cause of the initial control response delay remains unproven. Shared
host management is serial and all four domains bootstrap concurrently; this is
a candidate source of latency, not a measured conclusion. New stage-specific
logs are required to identify which proof timed out in the next Linux run.

## Committed fixes

| Commit | Change |
| --- | --- |
| Core `a651e56691b7e1834e3cb942fba4bda5362c3a02` | Reject unsolicited prepared replacement of an unrelated active lane unless the exact staged transaction authorizes it. Real QUIC regression added; carrier-runtime library 332/332 and strict Clippy passed. |
| Runtime `ee9d9e8` | Mount frozen debug binaries read-only and preflight all six executables. |
| Runtime `0303761` | Scale completion waits for exact transaction, selector, barrier and complete unique bilateral drain receipts. |
| Runtime `1320ac1` | Initial convergence permits legitimate bootstrap pair recovery; a later changed worker epoch still requires exact MBB drain. |
| Runtime `a69c047` | Preserve anyhow/IO types from shared business completion; typed EAGAIN remains retryable. |
| Runtime `b6ab287`, `b75d6f5` | Retry original owner registration/readiness/controller proof within one 20-second bootstrap deadline, and active liveness within two seconds. Deadline uncertainty becomes `ManagedProofPending`; the cleanup branch preserves recorded Core, TUNIO, binding and netd owner only while original authorization remains valid. Confirmed Core/IO exit remains a recovery signal and is never converted into UNKNOWN. |

The retained business and IO handles do not signal processes when dropped.
Shared placement requires an independent per-domain control/record, so the
preservation branch covers shared domains. Recovery re-reads these original
records, awaits bound status and adopts the same identity; it does not spawn a
duplicate activation while the identity remains live. Existing authorization
and lease caps still apply. Retaining an uncertain process is not a readiness
receipt or a successful transaction.

Other renewal/MBB callers keep their existing registration deadline; the new
extended bootstrap budget is passed only by initial `run_plan`.

## Narrow verification and next gate

Native `cargo test -p candy-sdwan-agent activation_proof_tests --lib --offline`
and the same test with `--features experimental-tunio-rebind`: 3/3 passed.
Tests cover same-owner transient recovery, bounded uncertainty and the actual
cleanup predicate, original authorization expiry, unrecorded ownership,
authenticated rejection and confirmed Core exit. Existing non-Linux candidate
helper dead-code warnings remain; no strict Linux build is claimed here.

Next integrated gate must use the latest committed Runtime and Core snapshot,
record exact source/binary/runner hashes, then require complete initial
convergence and 1/2/4/2/1 scaling, unchanged zero-loss continuity assertions,
exact bilateral drain and no premature owner stop. Follow-up crash/restart
gates remain necessary. Debug/test ELF files are not release artifacts or
throughput acceptance.
