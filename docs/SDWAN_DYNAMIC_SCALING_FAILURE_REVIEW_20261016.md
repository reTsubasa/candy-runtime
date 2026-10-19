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

## v10 parallel test endpoint lifetime

Frozen v10 Linux Agent full tests first failed 137/138 in 10.20 seconds:
`unrecorded_live_endpoint_blocks_replacement_without_granting_adoption` received
`ManagedProofPending` immediately after dropping its own `UnixListener`.
The same frozen test executable passed 138/138 serially in 17.21 seconds.
Both original logs remain in `registered-mbb-source-v10/agent-tests*.log`.

A separate Linux kernel reproducer with the existing runner image verified the
invalid test assumption without a build or application traffic. A fork child
held a listener with FD_CLOEXEC while waiting before exec. After the parent
closed its descriptor, connecting still succeeded and SO_PEERCRED returned the
original creating parent's live PID/UID. After child exec and reap the same
path returned ECONNREFUSED. Output was:

```text
after_parent_close: reachable=true authenticated_owner_pid=1 expected_owner_pid=1 FD_CLOEXEC=true inherited_child=7
after_child_exec_and_reap: reachable=false error=ECONNREFUSED
```

This proves a concurrent fork-to-exec window can invalidate immediate endpoint
absence after local descriptor close. v10 did not capture the individual
inheriting child, so its exact PID is not retrospectively established.

The test now starts its own exact self-exec helper. That helper creates the
listener after exec, so unrelated parent tests cannot inherit it. The parent
calls the real `inspect_endpoint_process` and asserts the exact helper process
identity, then proves the live endpoint blocks replacement. It sends explicit
shutdown, waits for successful helper exit with a five-second bound and a
kill/reap guard on failure, then tests both stale and removed socket paths.
Production inspection and recovery code are unchanged. This is a source test
change after the v10 freeze; v10 business binaries are not claimed to contain
it. Native Agent tests passed 104/104; this Linux-only helper test still requires
the coordinated next Linux test build.

## v10 finalization replay defect

The strict v10 scale gate reached exact bilateral drain in all four domains,
but failed to converge to two workers within its unchanged 60-second deadline.
Candidate Core status contained the exact installed transaction and complete
drain markers. Client renewal journals recorded `mbb_outcome=drained`, while
netd journals had already accepted the replacement owner for three domains.
The remaining candidate and repeated `stale_forward_owner` /
`forward_candidate_pending` errors are preserved under
`shared-pool-negotiated-final-v10/shared-pool-state`.

This is a production transaction replay defect. `mbb_finalize` recalculated the
authorization and lease deadlines on every call, then blindly submitted
ForwardPrepare and ForwardAuthorize for the same fencing token. A netd domain
operation can complete after the caller's IPC deadline: replaying Prepare
against an already Active owner then fails the monotonic fence check, while
changing deadlines against a retained candidate fails exact owner equality.
ForwardAuthorize is valid only for Prepared, so it also cannot be blindly
replayed after Commit has succeeded. The IPC timeout alone does not prove that
the backend operation failed.

The fix persists the final owner once with the existing terminal MBB outcome
and retains every field across retries. Scoped ForwardStatus selects Prepare,
exact Prepared continuation, or exact Active continuation. An exact Active
continuation skips Prepare and Authorize, then still replays
ForwardCommitAuthorized with fresh actual TUNIO/Core evidence so netd checks
the original authority, process identities, authorization cap and packet
proof. It does not infer authority from public forwarding status alone.
Unknown candidates, changed same-fence owners, consumed fences, Guarded or
Revoked owners and expired authority remain explicit errors; their owner or
deadline is never silently changed. Existing pre-fix journals whose exact
owner was already corrupted are not automatically adopted by this repair.

Native Agent full library tests passed 106/106. Two added regressions cover
reply loss after Prepare/Authorize/Commit, exact candidate and Active replay,
changed deadlines/domain identity, consumed fencing token, guarded/revoked
state and immutable authorization expiry. Linux compilation, the real
netd/TUNIO integration and strict dynamic 1/2/4/2/1 gate remain required on the
next coordinated frozen build; v10 remains a recorded failure.

When a replay reaches the lease deadline before the original authorization cap,
the agent now has one scoped repair path. It requires netd status with no
unknown candidate, an exact revoked/reclaimed owner or an older owner, and a
watermark that has not consumed a higher fence. It allocates and journals a
strictly higher forwarding fence, keeps the original signed authorization cap,
worker epoch, transaction and declaration, and starts the normal Prepare /
Authorize / receipt Commit sequence. The lease remains bounded by the original
cap. An active same-fence owner, a higher watermark, an unknown candidate or
the expired authorization cap is a hard preservation error and cannot be
silently adopted or extended.

After adding this lease-expiry repair, native Agent library tests passed
107/107; all three focused MBB replay/expiry tests passed. The additional
expiry test proves a new local fence is persisted/replayed exactly and cannot
extend the original authorization cap or override a higher consumed fence.
