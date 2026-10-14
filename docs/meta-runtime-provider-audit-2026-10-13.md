# Meta Core mapping and manual provider update audit

Date: 2026-10-13. Device: 192.168.2.1, OpenWrt 25.12.5,
IPQ40xx Cortex-A7, 512 MiB RAM. Runtime package r152, Rust Core 0.3.62.

## Window mapping

The latest reliable Meta Go release source inspected is d1194760 on
fix/candy-control-stall-20261012. Uncommitted changes in other checkouts are
not release evidence.

| Parameter | Meta Go | Rust generic client | Rust OpenWrt client | HK/BWG server change on Oct 12 |
| --- | --- | --- | --- | --- |
| Stream receive window | 32 MiB | 32 MiB | 2 MiB | 2 MiB retained |
| Connection receive window | 64 MiB | 64 MiB | 16 MiB | 16 MiB retained |
| Local send window | Managed by quic-go | 32 MiB | 16 MiB | Raised to 64 MiB |
| UDP socket buffer request | Separate from QUIC windows | 8 MiB | 8 MiB | Separate from QUIC windows |

Linux reports a doubled SO_RCVBUF/SO_SNDBUF value, explaining the screenshot's
16 MiB effective socket buffers and 8 MiB request. This does not measure any
QUIC flow-control window. Actual window fields are absent from the multi-node
passive status; the OpenWrt values above follow the deployed configuration
path, not a direct passive measurement.

## Findings and required repairs

| ID | Finding | Evidence | Repair | State |
| --- | --- | --- | --- | --- |
| W01 | OpenWrt is unconditionally treated as low memory; client windows cannot be overridden. | candy-core transport/config.rs for_client sets low_memory=true; candy.init passes --platform openwrt. | Add validated stream_receive_window, connection_receive_window and send_window overrides to client config/CLI and Runtime UCI. Preserve OpenWrt keepalive/idle behavior and account for all active nodes. | Confirmed; not changed on the device. |
| W02 | Multi-node diagnostics expose socket buffers but omit effective QUIC windows. | candy-carrier-client MultiNodeAppliedTransportStatus lacks profile/window fields. | Reuse single-node transport status field names; report each node's effective profile and all three windows, then display them separately in LuCI. | Confirmed; pending implementation. |
| W03 | Default BBR preset remains current in Runtime config, init, LuCI and Core CLI. | current uses ProbeBW 1.50/0.90; bbr-v1 uses 1.25/0.75. | Default all entry points to bbr-v1 while retaining explicit existing selections. | Confirmed; device already uses bbr-v1 on all three nodes. |
| P01 | Rule update settings have no manual button. | Existing geo_update/gfwlist_update POST handlers had no UI control. | Add two independent controls, bounded download/reload deadlines, CSRF protection and structured error feedback. | Implemented and deployed as a reversible LuCI patch. |
| P02 | Candidate provider update/validation unnecessarily require both IP families. | CLI update_geo_provider and validate_geo_provider. | Validate only families actually supplied. Preserve empty/invalid CIDR rejection and coverage checks for supplied families. | Core source fixed; 67 CLI library tests passed. Installed Core remains 0.3.62. |
| P03 | The Aug 5 signed provider baseline rejects current sources whose legitimate coverage expanded. | gaoyifan IPv4 candidate-trusted=8156bp; 17mon=8044bp, below 8500bp. | Verify the current upstream dataset and publish refreshed rules plus hashes/counts/manifest through the signed Runtime release. Combine with P02; do not lower the threshold to conceal baseline drift. | Confirmed; packaged baseline not replaced on the device. |
| L01 | Shutdown can spin reconnecting after the retire notification sender closes. | retire.changed() error is ignored in connect/backoff select; 73 endpoint-stopping failures in 1.04 seconds. | Treat channel closure as retirement in both selects; test cancellation and closed sender paths. | Confirmed in prior log audit; pending repair. |
| L02 | Incoming Rust control queue remains 256 and overload closes that QUIC connection. | Core 0.3.61 release notes document this limit. | Validate overload isolation and reject/retry individual work where the protocol permits; preserve subsequent healthy requests. | Residual risk; no triggering evidence on this device. |

Meta's control-progress recovery and fixed UDP session/per-packet target
compatibility already have Rust counterparts in 80cd670 and 6da4fb3. They
must not be reported as missing solely because Go and Quinn use different APIs.

## Provider compatibility measurements

The existing configured source is 17mon/china_ip_list, which is IPv4-only.
It was rejected by the installed Core before the output file was replaced.
Current gaoyifan china46 is dual stack but failed the old baseline check.

| Dataset versus baseline | Baseline coverage retained | Candidate coverage inside baseline |
| --- | --- | --- |
| Current gaoyifan IPv4 versus Aug 5 | 99.9656% | 81.5600% |
| Current gaoyifan IPv6 versus Aug 5 | 99.9679% | 37.0284% |
| Current 17mon IPv4 versus Aug 5 | 99.8130% | 80.4417% |
| Current 17mon IPv4 versus current gaoyifan | 98.4549% | 97.2534% |

The last row satisfies the existing 85% rule in both directions. Current
gaoyifan has 6533 IPv4 and 3473 IPv6 entries; the package has 4209 and 1605.
Upstream now includes unannounced RIR-CN registration fallback; 17mon also
includes WHOIS-CN space. This explains the increased address coverage.

## Implemented LuCI behavior and verification

Advanced settings / Provider updates now has Update GFWList now and Update
China IP now controls. They use the address currently entered in that field,
persist it only after a successful download/validation, and do not submit the
Advanced settings form or invoke its restart handler. Accepted rule files are
loaded with reload_runtime. Failures include code, module and error detail.
Downloaded content is compared against the active file before claiming loaded
success; stopped service or a disabled rule policy are reported as saved only.

The JSON format is explicitly selected in the URL because this device's Lua
compatibility bridge does not reliably preserve the AJAX request header.

Tests: provider_update_test.lua passed success, stopped service, unselected
provider, source persistence failure, activation failure, download failure,
deadline and CSRF cases. Existing LuCI package static tests and log diagnostics
tests passed. Browser tests at 1420px and 390px verified actual authenticated
POSTs, in-progress disabled controls, successful GFWList loading, visible
China-IP error and button sizing. The unauthenticated LuCI login-page RPC error
is excluded from application-page assertions after login.

SSH and browser updates both produced GFWList 4354 entries; runtime file
comparison succeeded and the client health check passed. Client PID 18559
remained unchanged. CN-IP active SHA256 remains the packaged
5220ab4fbf03bb6fa003e7928bb072fe549fefd274269992b3cc817e25bf8ba3.

Live patch backups: /root/candy-backup-provider-ui-20261013. No new Core or
Runtime release was published during this audit. The package version remains
r152; these source/UI changes still require the next signed release.
