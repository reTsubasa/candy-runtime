# Shared SD-WAN Pool End-to-End Gate, 2026-10-16

## Scope

The isolated Linux Docker fixture uses the Rust Runtime Agent, real Core shared
hosts, signed per-domain policy, netd, TUNIO, network namespaces and four remote
peers. It drives the actual desired pool file through `1/2/4/2/1`, checks real
ICMP forwarding, process placement, unchanged TUN identity and IO PID, domain
authorization preservation, host resource budgets and empty-host retirement.
It then injects one unavailable peer and a killed shared host to verify recovery
and isolation. These results do not constitute production deployment, OpenWrt
acceptance or the deferred throughput target.

The v19 continuous ping assertion checks process liveness; `wait_all` samples
successful forwarding after each reconciliation. It does not prove zero packet
loss during migration. The updated fixture now records sequence loss and reply
gaps at every scale step and requires zero missing sequences before injected
faults. That stricter continuity gate remains pending on the final Runtime
cross-process MBB implementation.

## Discovered Defects And Changes

1. `shared-pool-e2e-v8` failed on scale-down from four hosts to two. Core accepted
   host retirement while completed domain receipts remained. A supervisor then
   lost its authenticated old-worker proof before its `forget` operation and
   stopped with `shared_worker_identity_changed`. Host retirement now requires
   an empty domain map with every completion explicitly forgotten. Lifecycle coverage
   verifies rejection with `worker_has_unacknowledged_domains` until `forget`.
2. Runtime `domain_running` and `forget_domain` could race a host exit between
   their process-identity check and control exchange. A failed exchange is now
   followed by a second confirmed liveness check. Only confirmed exit/changed
   epoch permits stopped/forgotten state; live-host and uncertain errors remain
   errors. Linux unit coverage checks both boundaries.
3. The fixture omitted Core's bounded log exporter from the fixed host thread
   count. Runs v9/v10 correctly reported four live domains, 47 descriptors and
   14 threads. The bound now explicitly accounts for the control thread and
   exporter, plus three threads per domain. Domain budgets remain unchanged.
4. `shared-pool-e2e-v11` completed the `1/2/4/2/1` cycle but failed subsequent
   killed-host recovery with `stale_forward_owner`. An aborted candidate had
   advanced the netd fencing high-water mark beyond the visible active owner.
   The parallel make-before-break work is adding that high-water mark to
   `ForwardStatus` and consuming it in every recovery fence allocation.
5. `shared-pool-e2e-v12` completed scaling and host recovery after the fencing
   fix, then failed graceful Agent shutdown. Adopted-worker supervision sent
   `Stop` but did not wait for business completion or forget shared receipts.
   Adoption now waits at most two seconds, rejects an unconfirmed stop, and
   explicitly forgets a confirmed stopped domain before host retirement.
6. `shared-pool-e2e-v14` exposed shutdown arriving while a domain supervisor
   was in proof retry/backoff. That path had never entered adoption cleanup,
   leaving shared business domains alive. Every domain loop now performs a
   bounded authenticated cleanup sweep using immutable process records. It
   revokes the actual recorded forwarding owner, independently stops business
   and infrastructure I/O, verifies process epochs, forgets shared completion
   receipts, and reports unconfirmed cleanup as a failed shutdown. Missing
   readiness proof cannot prevent stopping an authenticated recorded owner.
   The fixture deterministically injects this missing-proof state before
   shutdown and requires the cleanup to complete.

Scale evidence is published after every successful step so a later fault cannot
erase the record of earlier steps. Failed runs are retained and do not count as
overall gate acceptance.

## Evidence

| Run | Result | Interpretation |
| --- | --- | --- |
| shared-pool-e2e-v8 | FAIL | Reproduces unacknowledged completion retirement race. |
| shared-host-lifecycle-v2 | PASS | Real host refuses retirement until completion is forgotten; 8.834 seconds. |
| shared-pool-e2e-v9/v10 | FAIL | Diagnoses the fixed exporter thread omitted from fixture accounting. |
| shared-pool-e2e-v11 | FAIL | All five scale steps complete; killed-host recovery exposes fencing defect. |
| shared-pool-e2e-v12 | FAIL | All scale and fault steps complete; adopted-domain shutdown omits completion acknowledgement. |
| shared-pool-e2e-v13 | PASS | All scale, isolation, killed-host recovery and graceful-shutdown checks pass; 25.867 seconds. |
| shared-pool-e2e-v14 | FAIL | Integrated Core completes scale/fault checks; shutdown during proof retry leaves business domains alive. |
| shared-pool-e2e-v15 | FAIL | Fault injection changes placement revision and triggers legitimate renewal; missing-proof assertion is not exercised. |
| shared-pool-e2e-v16 | PASS | Corrected missing-proof injection and authenticated cleanup sweep; 49.163 seconds. |
| shared-pool-e2e-v17/v18 | PASS | Final cleanup without unnecessary PID wait; worktree binary evidence only. |
| shared-pool-e2e-v19 | PASS | Immutable snapshot of all six Linux binaries; full scale, fault isolation, recovery and missing-proof shutdown; 31.256 seconds. |
| shared-host-lifecycle-v3 | PASS | Same six immutable binaries; retirement remains rejected until completed domains are forgotten; 9.750 seconds. |

Runs v9-v11 and lifecycle-v2 used Core binary SHA256
`1c75719891551ddb88378916cbfdad6c091a5e8012588c5e02399d4874cf12ee`.
Runs v9-v11 used Agent SHA256
`ab0a52be6a1baf78654d9023f93f77803c5b4a819f0e5e690e237c28c481cee9`.
Concurrent development continued after these binaries were built; these hashes
identify intermediate evidence, not final exact-source acceptance.

Run v13 used that same Core binary, Agent SHA256
`6518d6024de049bc5b9685eef4f8ef45b2c45d2dc768c9f944d42c4054185695`
and netd SHA256
`d4cc67d5ddb4941fb30ffbb433a567b0d4c8c58003b86de07724596b75ce4b18`.
It includes the high-water fencing fix and adopted-domain completion cleanup.

## Immutable Binary Boundary

Run v19 tests copied immutable Linux binaries mounted read-only. The harness
checks source, copied and source-after-copy SHA256 equality and records all six
hashes in `shared-pool-e2e-v19/binary-hashes.json`. Its Core is
`de7e11c8d457593e82544518479974182cd83a4c40afbe9287ce5e3828a2f324`,
Agent is `f1fc5eca7dc66f0ea84670dc776ba3c7fd49e5ac670156d87516ce7f58bc0054`,
and netd is `d4cc67d5ddb4941fb30ffbb433a567b0d4c8c58003b86de07724596b75ce4b18`.
This closes the functional gate for those binary bytes. Concurrent changes
continue in other modules; this evidence does not certify a later source tree,
signed release, production deployment, OpenWrt or throughput acceptance.

## Negotiated Continuity Gate

`shared-pool-strict-continuity-v1` failed before its initial one-worker placement
converged. It used Core `052cc392a811c190358109feb93efb8d3423c74b5050481172871636120a6b13`
and the v19 Agent. No scale-step or zero-loss acceptance follows from this run.
The actual failure was `candidate_old_lane_ambiguous`: four valid domains reused
the same peer attachment identifier, while the new outbound registration index
treated that peer identifier as globally unique. The implementation must scope
it to the signed tenant and segment as well as both attachment identities.

The tightened fixture now uses four real remote Runtime-managed domains and
one shared listener/master, with separate netd namespaces and TUNIO processes.
Its signed node/pool connection budgets explicitly include four active lanes
plus bounded replacement overlap. It does not disable negotiated capabilities
or bypass reservation admission.

Every changed worker epoch must have a committed renewal journal containing
the real reservation and an exact candidate proof: matching transaction, local
PacketPort binding, remote selector/barrier, bidirectional probe, installation
and drain completion. ICMP counts distinct sequence numbers and rejects any
missing sequence during all scaling steps. After `1/2/4/2/1`, the gate waits
31 seconds, verifies the same active epochs, then performs another `2/1`
transition. This explicitly checks that original transaction receipt expiry
does not close active traffic or prevent the next real reservation.

These final negotiated checks remain pending until the coherent integration
binaries pass this revised fixture. Earlier v19 acceptance covers its recorded
binary boundary and the narrower observations described above.
