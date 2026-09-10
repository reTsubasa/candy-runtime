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

Not a release acceptance: socket-dependent agent tests fail under this
session's sandbox with `Operation not permitted`; permission escalation timed
out. The existing init integration suite also requires `ps` visibility and
failed its stale-client termination assertion when sandbox denied `ps`.
Linux parent-death execution, full socket regression, and on-node startup
verification must pass before rollout. The ordinary Proxy startup failure
has not yet been reproduced with the new Core connection diagnostics, so its
remote-side cause remains unconfirmed.

Runtime revision is r108 to avoid overwriting r107. Do not report a successful
release or node upgrade on the basis of this source change alone.
