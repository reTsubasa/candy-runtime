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

## Remaining Gate

The intermediate functional gate is closed by v13. Rebuild the integrated final
Core, Agent and netd, then repeat the selected lifecycle and four-domain scaling
gates with recorded hashes to establish final exact-source acceptance.
