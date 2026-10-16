# SD-WAN precommit descriptor recovery

## Failure and recovery boundary

A candidate PacketPort descriptor exists only in Runtime memory until TUNIO
consumes `PrepareOwner`. If Runtime fails after publishing its candidate journal
but before that consumption, an ordinary transaction probe reports no receipt.
Repeating that probe cannot recreate the descriptor and previously left the
candidate stuck indefinitely.

Schema 3 now provides authenticated `RecoverPrecommit`, scoped to the exact
original envelope and the complete previous active PacketPort binding. Runtime
may issue it only while the durable journal has `commit_intent=false`. The
TUNIO controller serializes the request with Stage and Prepare and obtains the
actual PacketPort manager state through its FIFO queue.

Recovery returns an existing exact Prepared or Committed outcome. It confirms
cancellation only if the original full binding is still active, there is no
pending or retained owner, no conflicting authority exists, and the manager's
highest consumed transaction revision is below the candidate revision. A queue
failure, RPC timeout, consumed revision, changed envelope or unknown ownership
is not evidence of absence.

## Cancellation ordering

1. TUNIO clears only the exact staged candidate and consumes its authority
   revision, owner epoch and policy generation as cancellation fences.
2. TUNIO writes and fsyncs its status, renames it, then fsyncs the parent directory
   before acknowledging cancellation. Late Stage and Prepare for the cancelled
   transaction are rejected; exact cancellation retries are idempotent.
3. Runtime validates the authenticated response, complete old binding and exact
   cancellation envelope, then persists that response in the original journal.
4. Runtime persists cleanup intent before stopping only the candidate process.
   The old owner and TUN infrastructure remain running.
5. Runtime persists `precommit_cancelled` with the old reservation removed.
   Existing renewal reconciliation then retires the original transaction and
   allocates a fresh transaction and epochs.

A failed file or directory sync never grants cleanup permission. If cleanup or
its final publication fails, recovery repeats the original cancellation instead
of creating a fresh transaction. A Core reservation can remain live until its
original cap expires; cancellation does not forge a Core abort or extend a cap.

## Process lifetime limitation

TUNIO status is an observable process-bound receipt, not a WAL that reconstructs
the PacketPort manager. The cancellation fence is scoped to that same live IO
process and controller identity. If IO disappears, its old identity cannot
authenticate recovery and infrastructure/owner pair recovery is required.
Prepared, committed and uncertain transactions retain the existing exact
reconciliation path; this change does not infer successful drain or rollback.

## Verification

Linux Docker tests use real TUNIO control sockets, SCM_RIGHTS descriptor transfer
and old-owner bidirectional PacketPort traffic. Added cases cover:

- Failure before and after Stage, with an unconsumed candidate descriptor.
- Lost cancellation ACK, exact retry and changed-envelope rejection.
- Late Prepare and Stage rejection after cancellation.
- Prepare sent with its ACK deliberately unread, followed by exact recovery.
- Actual Prepared and Committed results, and consumed revision rejection even
  when the original owner is still active after Abort.
- Wrong full binding, unavailable manager and failed status publication.
- Runtime response fencing, durable commit-intent rejection and journal sync
  failure without candidate cleanup.

Focused results: Runtime candidate recovery 3/3 and TUNIO recovery 3/3. The
Linux Runtime library passes 129/129 with `experimental-tunio-rebind`; the
standalone TUNIO library passes 25/25. Both all-targets Clippy runs pass with
warnings denied on Rust 1.88. This is component and live-IPC evidence, not a
claim that the complete process-crash make-before-break acceptance gate has
passed. Two existing timing tests were given realistic startup/control budgets:
the retirement test still checks rejection before its absolute deadline and
acceptance afterwards, and the renewal test still checks expiry before attaching
fresh authority.
