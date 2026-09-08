# Reliability repair plan, 2026-09-08

This is an implementation checklist, not a production acceptance report.
Priority describes user impact: P0 traffic interruption; P1 recovery/control
correctness; P2 diagnostics and delivery gates; P3 documentation/maintenance.
Items are checked only after the corresponding focused regression passes.

## Completed preparation

- [x] Verify no active builds and no tracked files in the cleanup targets.
- [x] Remove only Core `target`, Core `fuzz/target`, Runtime `target`, and
  Cloud `target`: approximately 38.9 GiB of reproducible build caches.
  Source, vendor, toolchains, release artifacts, databases and credentials remain.
- [x] Recheck review assertions against current source before changing behavior.

## Repair and acceptance checklist

| ID | Priority | Observed problem / scope | Repair and acceptance |
| --- | --- | --- | --- |
| R01 | P0 | Core fail-open latch survives partial route-owner recovery | **Done:** failed-owner coverage is tracked; regression covers healthy alternate owner, recovery and re-failure. |
| R02 | P0 | Policy replacement closes old Peer streams before new streams are usable | Stage authenticated, ready replacement lanes before commit; preserve unaffected lanes; abort candidate without dropping current traffic. Test failed preparation and successful switch. Cross-node zero loss requires separate evidence. |
| R03 | P0 | Runtime suspends old forwarding before policy replacement | Coordinate Core prepare/commit and netd transaction ordering; test candidate failure, rollback, process identity and unchanged Proxy. Do not equate a Proxy fallback with preserving existing NAT/TCP flows. |
| R04 | P1 | Partial route readiness can trigger global Runtime fallback | Distinguish per-route unavailability from total loss/fatal process or TUN errors. Test listener/client coverage, recovery and fatal failures without broad error whitelists. |
| R05 | P1 | Cloud status reader rejects persisted `PREPARED` receipt | **Done:** API accepts all three persisted states; DB-backed regression is present (requires `DATABASE_URL`). |
| R06 | P1 | Segment aggregate failure/update colors unrelated links | **Done:** link state uses peer endpoints/attachments; three-site isolation tests pass. |
| R07 | P1 | Offline rejected nodes/sites remain red | **Done:** freshness/online classification precedes faults; stale rejected node/site/link tests pass. |
| R08 | P1 | Path presence can falsely imply Stream readiness | **Done:** stream paths require ready streams; legacy reports use conservative route readiness. |
| R09 | P2 | Core packet/stream failure causes are lost or cleared too early | **Implemented:** bounded drop/error and retired-path history telemetry; transport integration still required. |
| R10 | P2 | Runtime clears all path diagnostics while steering is suspended | **Done:** path evidence is preserved with explicit `forwarding_active`; Cloud distinguishes inactive forwarding. |
| R11 | P2 | Runtime preflight greps private Core source and fails on valid formatting | **Done:** structured manifest contract and isolated checkout/malformed JSON tests integrated into verification. |
| R12 | P2 | Core manifest test hardcodes an obsolete package version | **Done:** compile-time package version assertion passes. |
| R13 | P2 | Local DB tests may silently skip and socket tests fail under sandbox | Report skipped prerequisites honestly; run actual MySQL tests when available and loopback tests with scoped permissions. Never treat permission errors as product failures. |
| R14 | P2 | Runtime test fixture writes into real `/etc/candy` | **Done:** lifecycle fixture paths are redirected into temporary state roots. |
| R15 | P2 | Core Action can build production Core; Cloud release pins duplicate versions | **Done:** Core build workflow removed; Cloud x86/ARM64 inputs reference published `core-v0.3.42`. |
| R16 | P3 | Release/platform docs contradict actual targets and signing ownership | **Done:** Core/Cloud docs and matrix describe current five-target and signing boundary. |
| R17 | P3 | Design docs imply unimplemented multi-stream/telemetry behavior | Record current implementation limits and remaining dynamic multi-stream/observability work; do not call default counters or plans completed features. |

## Verification and rollout gates

- [x] Core focused routing/manifest tests; Core workspace check passes. Real
  loopback transport tests remain environment-gated and were not claimed.
- [x] Runtime manifest, isolated preflight/init and cloud-sync telemetry tests;
  Runtime workspace check passes. The aggregate upgrade script remains
  environment-sensitive on this host and is not treated as a product failure.
- [x] Cloud state/topology tests (47/47), typecheck/build and Cloud workspace
  check pass. Actual MySQL receipt execution remains a separate deployment gate.
- [x] Release-contract tests, formatting and `git diff --check` pass in all
  modified repositories.
- [x] Re-review the combined Core/Runtime hot-switch contract and record the
  remaining cross-node zero-loss and multi-stream risks below.
- [ ] Separately authorized commit, local Core candidate build, release signing,
  Cloud/Runtime Actions and node update. None has been performed by this checklist.

Use `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`
for local regression builds to limit cache growth. Build outputs must not be
removed while any verification or packaging process is using them.

## Non-findings and limits

- A loopback socket denied by the sandbox is not proof of a production bug.
- A database test returning early without `DATABASE_URL` is not a passed DB test.
- The multi-Peer Core translates low-level Stream failures to recognized recovery
  codes; indiscriminately extending a Runtime error whitelist is unsafe.
- No live-node load test, remote release inspection or deployment is implied by
  a passing source test. A fixed 30-minute traffic gate is not required here.
- Multi-Segment runtime support and multiple independently scaled streams per
  Peer need contract evidence before any compatibility/schema expansion.
