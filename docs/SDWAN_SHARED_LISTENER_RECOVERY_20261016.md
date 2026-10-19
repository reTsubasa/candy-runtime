# Shared listener recovery and MBB audit (2026-10-16)

## Scope

These are isolated Linux namespace/container gates, not production acceptance.
No live node or release deployment is performed by this follow-up.

## Confirmed recovery defects

### Live transport listener rejected after master loss

Master loss revokes its transport owners. A domain packet supervisor can then
report `lifecycle=failed`, while its independent transport listener remains live
and reports `registered_listener_ready=true`. Runtime previously required an
active/starting packet lifecycle before adoption. Registration remained bound to
the old master, so the replacement master could not admit the traffic needed to
restore packet readiness.

Recovery now accepts this exact listener condition after validating the existing
process identity, status binding and authorization. It publishes registration
after authenticated takeover and before waiting for packet readiness. Stopped,
unknown and failed-without-live-listener statuses remain rejected. This changes
listener recovery eligibility; it does not manufacture packet proof.

The fixture now requires activation ACK equality with the exact current master
instance, in addition to exact domain registration and committed ingress phase.

### Aborted forwarding candidate consumes an invisible fence

The mixed-listener v6 test killed a domain worker during adoption. Adoption had
prepared netd candidate fence 3 while the committed owner remained fence 2.
Candidate cleanup preserved the netd fence high-water mark of 3. A fresh renewal
read only the committed owner, calculated fence 3 again and received
`stale_forward_owner`. The domain supervisor treated that error as terminal.
The dynamic shared-pool v11 gate independently reproduced the same failure.

`ForwardStatus` now exposes `last_fencing_token`. Adoption, signed renewal, Core
recovery and pair recovery choose a fence greater than this value as well as
their recorded owner/candidate/journal values. Revocation does not lower the
fence. The rollback test checks that the original owner stays active, the aborted
fence remains visible and cannot be reused, and a higher fence can commit.

## Evidence

| Evidence | Result | Meaning |
| --- | --- | --- |
| `docs/artifacts/sdwan-20261016/mixed-listener-v4` | FAIL | Original fresh-master recovery circular wait. |
| `docs/artifacts/sdwan-20261016/mixed-listener-v5` | PASS | Initial listener recovery fix; predates stricter ACK check. |
| `docs/artifacts/sdwan-20261016/mixed-listener-v6` | FAIL | Domain kill exposed invisible aborted fence before master restart. |
| `docs/artifacts/sdwan-20261016/mixed-listener-v7` | PASS | Exact current-master ACK, real ICMP, Proxy HTTP, domain recovery, two master restarts, retained TUNIO/domain workers and no live orphan workers. |
| Linux Agent listener registration tests | 2/2 PASS | Failed packet lane only permits an explicitly live listener. |
| Linux Agent shared worker tests | 2/2 PASS | Host exit TOCTOU and error propagation. |
| netd candidate rollback test | PASS | Original owner and consumed fence survive rollback; retry advances fence. |

## Full make-before-break remains a separate requirement

The prior renewal change starts a shared-listener candidate before reaping the
old worker. That process ordering alone is not full make-before-break.

The current renewal attaches the new TUNIO owner before reciprocal packet proof.
`AttachAuthorized` replaces the active packet owner. Candidate spawn therefore
does not prove that the old data path stays usable until the replacement is
ready. TUNIO already provides `PrepareOwner` and `CommitOwner`, but Runtime does
not currently use them in signed renewal.

Core's shared listener receiver has candidate selection, durable candidate
journals, actor Prepared/Installed receipts and reciprocal packet probes. The
normal `open_sdwan_peer` outbound call still uses a domain hint, without a
`RoutingCandidateV1` selector. Runtime writes ordinary/prepared-ingress domain
registration, not a `.candidate` registration for that selector. Existing worker
replacement also creates a different local domain actor, so the old actor's
installed-lane receipt must not be substituted by new-worker health status.

Completion requires one exact transaction through all of these steps:

1. Persist the original authority, selector, participant identities, active
   owner/lane CAS values and fixed authorization deadline.
2. Publish the exact candidate registration and dial that selector.
3. Keep the old PacketPort active with `PrepareOwner`; prepare the candidate
   actor lane and prove both packet directions without forwarding candidate
   application traffic.
4. Obtain actor Prepared and Installed receipts for the exact transport and
   transaction at both peers. A status timestamp is not an Installed receipt.
5. Coordinate TUNIO owner promotion and authorized netd commit, retaining exact
   receipts across lost replies and process restart. An uncertain commit must
   reconcile the original transaction rather than create or abort another one.
6. Complete bilateral negotiated drain before retiring the old owner/worker.
   Prove old traffic remains usable before commit and new traffic works after it.

The mixed-listener recovery and dynamic worker scaling gates do not by themselves
accept these MBB requirements.
