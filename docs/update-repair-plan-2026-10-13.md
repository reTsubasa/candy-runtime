# OpenWrt software update repair

## Observed failures

On 192.168.2.1 (IPQ40xx, OpenWrt 25.12.5), r151 returned 1,237,139
bytes of status JSON and took 34 seconds. LuCI captured only 1 MiB,
truncating the JSON. Its configured timeout depended on an unavailable
`timeout` executable. Two page sections polled the same expensive manager.
HTTP and JSON failures were silently ignored. Download, activation and
version selection were spread across overlapping sections.

## Implementation

1. Keep the complete signed catalog for installation authorization and
   rollback. Build a private, atomic display projection bound to the source
   catalog, signature, public key and platform. Include the latest Runtime
   and five newest compatible Cores. Status must never return release history
   for other platforms. Installation must reverify the full signed catalog.
   Only explicit catalog checks rebuild a missing or stale projection; polling
   must not start repeated expensive jobs or leave staging files on timeout.
2. Enforce process deadlines even without an external timeout program. Reject
   oversized capture explicitly instead of returning truncated JSON.
3. Use one status request for the whole page. Poll slowly when idle and
   faster during operations, with a browser request timeout and visible errors.
   Preserve displayed versions on transient failures and disable mutations
   until status recovers.
4. Present Runtime and Core current/latest versions and actions together.
   Keep explicit Core activation and health rollback. Put historical versions,
   manifests, local upload and removal under advanced options. Show operation
   module, phase, code and detail. Never label unknown/incompatible as current.

## Verification and release gates

- Large (>1 MiB) signed catalog, cache invalidation, invalid signature,
  unsupported platform, missing Runtime target and compatible ARMv7 Core.
- Download/integrity errors, Runtime package/health rollback, Core activation
  health rollback and concurrent operation exclusion through existing tests.
- No external timeout: stuck child must be terminated; oversized output must
  be rejected with a specific error. UI HTTP, malformed JSON and timeout paths.
- One poller, idle/busy cadence, upload/activation and old-version selection.
- Full Runtime verification and CI; immutable r152 builds for x86_64 and
  IPQ40xx; central catalog signing and publication; verify published assets.
- IPQ40xx: signed online catalog, compact valid status, healthy active proxy.
  Record measured timings and any incomplete physical upgrade checks.

## Availability boundary

Read-only catalog checks and UI validation must not restart the data plane.
Runtime installation is a separate transaction with configuration and package
rollback. It can require a short service restart; stage and verify every package
before stopping a running service. A successful HTTP submission means accepted,
not installed or healthy. Report completion only from the operation result.

## Validation before publication

- Full `scripts/verify.sh` and `cargo test --workspace --locked` passed.
- Large-catalog, invalid-signature and corrupted-projection regressions passed.
- IPQ40xx: full status reduced from 1,237,139 bytes / 34 seconds to
  9,617 bytes / 2 seconds after projecting only this device's architecture.
- Native Lua supervision on the router stopped a sleeping command after two
  seconds without a timeout applet. Oversized output returned
  `output_limit_exceeded`; the compact status parsed through the real LuCI
  capture helper. Existing client health remained successful.
- Playwright desktop (1420px) and mobile (390px): one initial status request,
  collapsed advanced sections, primary actions visible without horizontal
  scrolling, visible HTTP failure, preserved versions and successful recovery.
- Physical package upgrade is separate from the read-only probes above and
  must be recorded after the signed r152 packages are published.
