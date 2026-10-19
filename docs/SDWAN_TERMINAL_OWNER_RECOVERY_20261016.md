# SD-WAN terminal owner recovery

## Actual committed failure

Runtime now reconciles the original PacketPort Manager transaction before
recompiling signed inputs. An expired signed snapshot must not prevent recovery
of an already committed owner forever. Recovery retains the durable commit
intent, original transaction, participant identities, and exact Manager receipt.
It never relabels a committed transaction as aborted or drained.

Isolation requires the exact committed transaction and one actual failure:
`business_is_current=false` or `owner_active=false`. A business-domain RPC timeout
or unknown identity preserves an active owner and uses the existing bounded
Runtime retry. The `mbb_committed_isolating` journal phase grants no independent
permission: every retry repeats the exact Manager revision, complete predecessor
binding, candidate binding, pending-owner, and retained-owner checks.

Runtime persists failure evidence and cleanup intent before stopping the exact
candidate business domain. TUNIO independently permits `IsolateCommittedOwner`
only when the candidate process is confirmed dead or Manager confirms that the
candidate PacketPort is inactive. Passing the original prepare cap is never
business-failure evidence. This also supports shared hosts: the host may remain
alive, but its stopped business domain must release the PacketPort before
isolation succeeds.

The authenticated isolation acknowledgement is published with file and parent
directory sync. Runtime persists that receipt before retiring the predecessor
and releasing the original reservation. The evidence sidecar remains in the
signed snapshot directory, including the original closure and participant
identities. TUN infrastructure is retained for a fresh authorization/owner.

## Actual expired commit intent

A durable commit intent can have an actual Manager `Expired` receipt if the
original prepare expired before Commit reached Manager. This is not an unknown
commit and does not justify an Abort or a successful remote rollback claim.

Schema 3 `RetireExpiredCommit` requires the exact original envelope, cached
prepare deadline and full predecessor binding, exact Manager Expired receipt
and consumed revision, a live original owner, and no pending or retained owner.
It does not mutate Manager ownership. TUNIO durably publishes the retirement
marker, then Runtime persists the acknowledgement and stops only the candidate.
The local outcome is `local_expired_remote_unknown`; the original commit intent
and receipt remain in evidence. A fresh transaction may then use fresh epochs.

Late original Commit, Stage and Prepare are rejected before and after a fresh
owner activates. A failed RPC or failed publication cannot grant retirement
permission. An ACK lost after publication can be retried with the exact request.

## Process and integration boundaries

TUNIO status remains a process-bound receipt, not a Manager WAL. IO process loss
requires infrastructure/owner pair recovery. An active business process with
unavailable original transport/control remains uncertain: Runtime preserves it
and retries; ordinary redial is not claimed as recovery of its original barrier.

These changes have component and real local IPC coverage. They do not by
themselves certify the complete process-crash make-before-break or dynamic
1/2/4/2/1 end-to-end gate. The frozen v6 traffic gate predates these changes.

## Verification

Linux Rust 1.88, existing `candy-sdwan-perf-runner:20261013` image:

- Agent with `experimental-tunio-rebind`: 132 library tests passed.
- Standalone TUNIO: 26 library tests passed.
- Both all-targets Clippy checks passed with `-D warnings`.
- Focused Expired Agent cases: exact persisted receipt, restart and retry,
  invalid process/controller/nonce/scope/revision/ownership evidence, RPC timeout,
  failed persistence and terminal request fences.
- Real TUNIO cases: exact Expired receipt, wrong predecessor rejection,
  failed publication and exact retry, late original operations before/after fresh
  activation, old/fresh bidirectional PacketPort traffic, committed outcome
  preservation, live-after-cap isolation rejection and actual port-loss recovery.
