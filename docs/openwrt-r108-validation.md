# OpenWrt r108 validation

## Fixes

- TERM handlers wait for their supervised child and enforce a bounded stop;
  procd termination deadlines allow this cleanup to finish.
- Linux agent children receive SIGKILL on parent death, with a fork/exec race
  check. Startup scans full `/proc` arguments for owned orphan Core processes
  before deleting status files, refusing to take over a live owner.
- Readiness files are opened without following symlinks and read with a size
  bound. Schema, PID and token mismatches remain fail-closed, with distinct
  diagnostic codes and no token disclosure.
- Exited-agent committed receipts no longer abort Cloud reconciliation. They
  are ignored without deleting a possibly concurrently replaced receipt.
- Health checks name the failed stage; startup logs only changed pending
  causes and includes the final cause on timeout.
- LuCI strips ANSI, handles quoted fields and explicit tracing severity,
  normalizes timestamps to UTC, and reads Candy-filtered system history.

## Verification (2026-09-10)

Passed: Cloud Sync 81 unit tests; focused readiness binding tests; new shell
lifecycle tests (graceful TERM, forced timeout, owned/unrelated process
matching, live-owner refusal); Lua log parser tests; LuCI static checks;
productization and version checks; Linux x86_64-musl code and test compilation.

## Follow-up evidence (2026-09-11)

Runtime CI run `34545296701` passed full script verification, Rust workspace
tests and Linux/OpenWrt builds. Cloud Sync passed 82 tests; the SD-WAN agent
passed 47 tests, including Linux parent-death enforcement. Local Core socket
regression also passed (243 carrier client and 28 process tests before the
subsequent coexistence change).

Release workflow `34545296406` succeeded. The central release repository
published signed `runtime-v0.4.0-r108` at `2026-09-11T00:19:05Z`.

Hong Kong server logs matching the OpenWrt failure window identify
`stage=auth_method_selection error_code=psk_on_cloud_listener`: the ordinary
Proxy was using its old PSK endpoint, which had become a Cloud Grant listener.
This is separate from r108's process-lifetime fixes. User requirements confirm
both services must coexist with independent authentication and endpoints.
The r109/Core 0.3.45 coexistence changes need their own validation and rollout;
r108 publication alone does not establish successful node acceptance.
