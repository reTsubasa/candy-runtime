# Runtime negotiated owner handoff

## Cross-process transaction

Runtime reserves the predecessor Core's exact peer identities and original
boot-scoped monotonic deadline, then persists the reservation before creating a
candidate. The candidate inherits a private packet IPC endpoint, not the TUN.
TUNIO Prepare opens its inbound path while retaining the predecessor as the
only outbound owner. Core Prepare/Install must supply exact authenticated actor
installation and reciprocal packet probe proofs for every reserved peer.

Runtime fsyncs Commit intent before TUNIO Commit. An uncertain acknowledgement
queries the same transaction; it cannot abort, replace, or extend the original
cap. An authenticated replacement Runtime controller can reconcile the original
immutable envelope without changing its candidate, deadline, or identities.

After Commit, Core activates the installed remote lanes. The predecessor sends
FIFO markers and reports real marker-written, marker-received and packet output
interval completion for every exact barrier. Candidate drain accepts those
receipts. TUNIO Finish additionally waits for predecessor IPC queues. It never
labels cancelled or expired queues as successfully drained.

Only then does Runtime prove fresh packet readiness, publish the authoritative
failed-prefix snapshot, commit Netd forwarding and process records, retire the
predecessor and adopt the candidate. The committed plan clears the temporary
candidate reservation so subsequent ordinary restarts use signed configuration.

## Bounded failure convergence

Before Commit, a positively dead candidate or expired original prepare cap can
be cleaned up only while exact TUNIO receipts still prove the predecessor owns
outbound traffic. Unknown process or Commit outcomes preserve the transaction.

After exact Commit and the original cap expires, Core can explicitly retire a
failed drain. It preserves live activated peers and uses ordinary signed redial
for affected peers. Proofs retain the actual historical outcome of each peer:
exactly one of drain-complete or drain-failed, with at least one failed peer.
Current activation/connection state and recovery action are separate evidence;
a previously drained peer can later require redial without changing history.

Runtime persists that proof before requesting TUNIO RetireOwnerAfterFailure.
TUNIO retires predecessor queues only, preserves the new owner and TUN, and
returns forced-retirement=true, old-owner-drained=false. The operation is exact,
idempotent, forbidden before the original cap, and cannot rewrite a successful
Finish. A crash after successful Finish resumes successful finalization even
after the original handoff deadline. Failed convergence logs
`code=mbb_failed_drain_preserved`, never the successful-drain event.

After fresh Netd forwarding commit, Runtime confirms predecessor business
retirement and submits the exact forced-retirement TUNIO receipt to Core's
authenticated `candidate_finalize_failure` operation. A shared worker host may
remain alive: its exact predecessor domain instance, not the host PID, must be
retired. Core can then retain a compact explicit failure tombstone and admit the
next transaction. Runtime publishes committed process records only after the
finalization acknowledgement; crashes before that point replay the same failure
transaction and cannot bypass its retirement evidence.
The persistent `mbb_outcome` distinguishes `drained` from
`failed_drain_preserved` even after ownership records reach committed; recovery
cannot rewrite an existing terminal outcome.

## Local verification

- Core packet-port tests: 61/61; strict all-target Clippy passed. Completion
  advances only over contiguous settled writes; failed intervals retain their
  error while a later transaction gets a fresh baseline.
- Linux TUNIO authority tests: 11/11; strict all-target Clippy passed.
- Linux Runtime Agent library tests: 124/124, including exact installation,
  unknown Commit, original clock witness, mixed drain outcome and recovery action.
- Linux process-control tests: 5/5, including authenticated bounded JSON exchange.
- The four Core/Runtime packet-port mirrors compare byte-identical.

These are implementation and isolated local checks. Real multi-process dynamic
1/2/4/2/1 and bilateral traffic/fault evidence is recorded by the separate Linux
integration fixture; this document alone does not certify that gate or any
production deployment. No production service restart was performed here.

## Outbound Shared Placement Selection

The immutable `shared-pool-negotiated-final-v1` gate failed at the first 1 -> 2
transition: its committed journal had no negotiated reservation. Runtime had
selected MBB only when the plan registered a local shared listener. An outbound
client's shared worker placement has no such registration, so it incorrectly
entered the dedicated compatibility stop/spawn path.

The selection now also recognizes an authenticated shared worker placement.
With an active TUNIO owner and current predecessor domain, it must enter the
same Reserve/Prepare/Install/Activate/Drain transaction. Reservation errors or
unknown outcomes preserve the original owner rather than downgrade that
transaction to stop/spawn. Dedicated exclusive placements keep their existing
compatibility path. The strict continuous-traffic fixture remains the acceptance
gate; the first failed run is retained and does not certify the fix.
