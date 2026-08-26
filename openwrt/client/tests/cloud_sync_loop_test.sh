#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../packages/candy-client" && pwd)
sync_loop="$root/candy-cloud-sync-loop"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() {
	printf 'cloud_sync_loop_test: %s\n' "$*" >&2
	exit 1
}

mkdir -p "$tmp/bin" "$tmp/state/identity"
printf '%s\n' '{}' >"$tmp/state/identity/device-identity-v1.json"
: >"$tmp/logger.log"

cat >"$tmp/bin/id" <<'EOF'
#!/bin/sh
printf '%s\n' 0
EOF
cat >"$tmp/bin/logger" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$CANDY_TEST_LOG"
EOF
cat >"$tmp/bin/jsonfilter" <<'EOF'
#!/bin/sh
expression=
while [ "$#" -gt 0 ]; do
	case "$1" in
		-e) expression=${2:-}; shift 2 ;;
		*) shift ;;
	esac
done
input=$(cat)
case "$expression" in
	@.schema_version) printf '%s\n' "$input" | sed -n 's/.*"schema_version":\([0-9][0-9]*\).*/\1/p' ;;
	@.state) printf '%s\n' "$input" | sed -n 's/.*"state":"\([^"]*\)".*/\1/p' ;;
	@.cleanup) printf '%s\n' "$input" | sed -n 's/.*"cleanup":"\([^"]*\)".*/\1/p' ;;
	*) exit 1 ;;
esac
EOF
cat >"$tmp/bin/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$tmp/bin/start-stop-daemon" <<'EOF'
#!/bin/sh
printf '%s\n' 'level=warn event=runtime_telemetry_report_failed error=conflict' >&2
printf '%s\n' '{"schema_version":1,"state":"activation_rejected"}' >&2
printf '%s\n' '{"schema_version":1,"state":"configuration_updated","network_ready":true}'
rm -f "$CANDY_TEST_IDENTITY_FILE"
EOF
cat >"$tmp/sync" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$tmp/candy.init" <<'EOF'
#!/bin/sh
case "$1" in
	enabled) exit 0 ;;
	status) printf '%s\n' running ;;
	sdwan_reconcile) printf '%s\n' "$*" >>"$CANDY_TEST_RECONCILE_LOG" ;;
esac
EOF
chmod 0755 "$tmp/bin/"* "$tmp/sync" "$tmp/candy.init"

stderr_log="$tmp/stderr.log"
stdout_log="$tmp/stdout.log"
PATH="$tmp/bin:$PATH" \
	CANDY_TEST_LOG="$tmp/logger.log" \
	CANDY_TEST_RECONCILE_LOG="$tmp/reconcile.log" \
	CANDY_TEST_IDENTITY_FILE="$tmp/state/identity/device-identity-v1.json" \
	CANDY_CLOUD_SYNC_BIN="$tmp/sync" \
	CANDY_SDWAN_STATE_DIR="$tmp/state" \
	CANDY_INIT="$tmp/candy.init" \
	CANDY_CLOUD_SYNC_INTERVAL=1 \
	"$sync_loop" >"$stdout_log" 2>"$stderr_log" || fail "supervisor rejected a valid sync result"

[ ! -s "$stdout_log" ] || fail "machine-readable child stdout leaked from the supervisor"
grep -F 'runtime_telemetry_report_failed' "$stderr_log" >/dev/null || fail "Runtime stderr was hidden"
grep -F '"state":"activation_rejected"' "$stderr_log" >/dev/null || fail "structured stderr was hidden"
grep -F 'event=cloud_sync result=ok state=configuration_updated' "$tmp/logger.log" >/dev/null ||
	fail "stderr contaminated the final stdout state"
grep -Fx 'sdwan_reconcile' "$tmp/reconcile.log" >/dev/null || fail "successful synchronization was not reconciled"

# The result contract is the final non-empty stdout record. A trailing stdout
# diagnostic must invalidate the state rather than reusing an earlier JSON line.
mkdir -p "$tmp/state/identity"
printf '%s\n' '{}' >"$tmp/state/identity/device-identity-v1.json"
cat >"$tmp/bin/start-stop-daemon" <<'EOF'
#!/bin/sh
printf '%s\n' '{"schema_version":1,"state":"configuration_unchanged"}'
printf '%s\n' 'unexpected trailing stdout'
rm -f "$CANDY_TEST_IDENTITY_FILE"
EOF
chmod 0755 "$tmp/bin/start-stop-daemon"
: >"$tmp/logger.log"
PATH="$tmp/bin:$PATH" \
	CANDY_TEST_LOG="$tmp/logger.log" \
	CANDY_TEST_RECONCILE_LOG="$tmp/reconcile.log" \
	CANDY_TEST_IDENTITY_FILE="$tmp/state/identity/device-identity-v1.json" \
	CANDY_CLOUD_SYNC_BIN="$tmp/sync" \
	CANDY_SDWAN_STATE_DIR="$tmp/state" \
	CANDY_INIT="$tmp/candy.init" \
	CANDY_CLOUD_SYNC_INTERVAL=1 \
	"$sync_loop" >/dev/null 2>"$stderr_log" || fail "supervisor rejected an unknown successful result"
grep -F 'event=cloud_sync result=ok state=unknown' "$tmp/logger.log" >/dev/null ||
	fail "state parser accepted JSON that was not the final stdout record"

# An explicit stop disables Candy. Cloud synchronization must retain the
# downloaded candidate without restarting it every interval.
mkdir -p "$tmp/state/identity"
printf '%s\n' '{}' >"$tmp/state/identity/device-identity-v1.json"
cat >"$tmp/bin/start-stop-daemon" <<'EOF'
#!/bin/sh
printf '%s\n' '{"schema_version":1,"state":"configuration_unchanged"}'
rm -f "$CANDY_TEST_IDENTITY_FILE"
EOF
cat >"$tmp/candy.init" <<'EOF'
#!/bin/sh
case "$1" in
	enabled) exit 1 ;;
	*) printf '%s\n' "$*" >>"$CANDY_TEST_RECONCILE_LOG" ;;
esac
EOF
chmod 0755 "$tmp/bin/start-stop-daemon" "$tmp/candy.init"
: >"$tmp/logger.log"
: >"$tmp/reconcile.log"
PATH="$tmp/bin:$PATH" \
	CANDY_TEST_LOG="$tmp/logger.log" \
	CANDY_TEST_RECONCILE_LOG="$tmp/reconcile.log" \
	CANDY_TEST_IDENTITY_FILE="$tmp/state/identity/device-identity-v1.json" \
	CANDY_CLOUD_SYNC_BIN="$tmp/sync" \
	CANDY_SDWAN_STATE_DIR="$tmp/state" \
	CANDY_INIT="$tmp/candy.init" \
	CANDY_CLOUD_SYNC_INTERVAL=1 \
	"$sync_loop" >/dev/null 2>"$stderr_log" || fail "disabled service handling failed"
[ ! -s "$tmp/reconcile.log" ] || fail "Cloud sync restarted an explicitly disabled service"
grep -F 'event=cloud_sync_reconcile result=deferred reason=service_disabled' "$tmp/logger.log" >/dev/null ||
	fail "disabled reconciliation was not reported as deferred"

# A transient SD-WAN failure preserves autostart. The next successful Cloud
# sync starts the stopped service once instead of requesting reconnect forever.
mkdir -p "$tmp/state/identity"
printf '%s\n' '{}' >"$tmp/state/identity/device-identity-v1.json"
cat >"$tmp/candy.init" <<'EOF'
#!/bin/sh
case "$1" in
	enabled) exit 0 ;;
	status) printf '%s\n' stopped ;;
	start) printf '%s\n' "$*" >>"$CANDY_TEST_RECONCILE_LOG" ;;
	*) exit 1 ;;
esac
EOF
chmod 0755 "$tmp/candy.init"
: >"$tmp/logger.log"
: >"$tmp/reconcile.log"
PATH="$tmp/bin:$PATH" \
	CANDY_TEST_LOG="$tmp/logger.log" \
	CANDY_TEST_RECONCILE_LOG="$tmp/reconcile.log" \
	CANDY_TEST_IDENTITY_FILE="$tmp/state/identity/device-identity-v1.json" \
	CANDY_CLOUD_SYNC_BIN="$tmp/sync" \
	CANDY_SDWAN_STATE_DIR="$tmp/state" \
	CANDY_INIT="$tmp/candy.init" \
	CANDY_CLOUD_SYNC_INTERVAL=1 \
	"$sync_loop" >/dev/null 2>"$stderr_log" || fail "stopped service recovery failed"
grep -Fx start "$tmp/reconcile.log" >/dev/null || fail "stopped enabled service was not restarted"
grep -F 'event=cloud_sync_reconcile result=recovered reason=service_stopped' "$tmp/logger.log" >/dev/null ||
	fail "successful service recovery was not logged"

# A completed fail-open is a safety latch. Cloud polling may update the
# candidate, but only an explicit service start may clear the fault and reclaim
# traffic after an observed runtime blackhole.
mkdir -p "$tmp/state/identity"
printf '%s\n' '{}' >"$tmp/state/identity/device-identity-v1.json"
printf '%s\n' '{"schema_version":1,"state":"active","reason":"sdwan:core_traffic_blackhole","cleanup":"completed"}' >"$tmp/runtime-fault.json"
: >"$tmp/logger.log"
: >"$tmp/reconcile.log"
PATH="$tmp/bin:$PATH" \
	CANDY_TEST_LOG="$tmp/logger.log" \
	CANDY_TEST_RECONCILE_LOG="$tmp/reconcile.log" \
	CANDY_TEST_IDENTITY_FILE="$tmp/state/identity/device-identity-v1.json" \
	CANDY_CLOUD_SYNC_BIN="$tmp/sync" \
	CANDY_SDWAN_STATE_DIR="$tmp/state" \
	CANDY_FAULT_STATE_FILE="$tmp/runtime-fault.json" \
	CANDY_INIT="$tmp/candy.init" \
	CANDY_CLOUD_SYNC_INTERVAL=1 \
	"$sync_loop" >/dev/null 2>"$stderr_log" || fail "completed fault handling failed"
[ ! -s "$tmp/reconcile.log" ] || fail "Cloud sync restarted a service latched in fail-open"
grep -F 'event=cloud_sync_reconcile result=deferred reason=runtime_fault' "$tmp/logger.log" >/dev/null ||
	fail "completed fail-open was not reported as deferred"

printf '%s\n' "OpenWrt Candy Cloud sync supervisor test passed"
