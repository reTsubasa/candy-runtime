#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
health=$root/openwrt/client/packages/candy-client/candy-runtime-health-check
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-runtime-health.XXXXXX")
socket_pid=
trap '[ -z "$socket_pid" ] || kill "$socket_pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT HUP INT TERM

fail() {
	printf '%s\n' "openwrt_runtime_health_check_test: $*" >&2
	exit 1
}

mkdir -p "$tmp/bin" "$tmp/proc/$$" "$tmp/run"
cat > "$tmp/bin/jsonfilter" <<'EOF'
#!/bin/sh
path=
expression=
while [ "$#" -gt 0 ]; do
	case "$1" in
		-i) path=$2; shift 2 ;;
		-e) expression=$2; shift 2 ;;
		*) exit 2 ;;
	esac
done
case "$expression" in
	'@.updated_unix_ms') sed -n 's/.*"updated_unix_ms":\([0-9][0-9]*\).*/\1/p' "$path" ;;
	'@.generation') sed -n 's/.*"generation":\([0-9][0-9]*\).*/\1/p' "$path" ;;
	'@.config_sha256') sed -n 's/.*"config_sha256":"\([0-9a-f]*\)".*/\1/p' "$path" ;;
	*) exit 2 ;;
esac
EOF
chmod +x "$tmp/bin/jsonfilter"
cat > "$tmp/service" <<'EOF'
#!/bin/sh
[ "$1" = running ]
EOF
chmod +x "$tmp/service"

runtime_config=$tmp/run/runtime.json
ready_file=$tmp/run/client.ready
passive_status=$tmp/run/passive-status.json
control_socket=$tmp/run/control.sock
printf '%s\n' '{"name":"health-test"}' > "$runtime_config"
runtime_sha=$(sha256sum "$runtime_config" | awk '{print $1}')
printf '{"pid":%s,"listeners":["127.0.0.1:12345"]}\n' "$$" > "$ready_file"
printf 'candy-core\000client\000--config\000%s\000' "$runtime_config" > "$tmp/proc/$$/cmdline"
ln -s /test/candy-core "$tmp/proc/$$/exe"
now_ms=$(( $(date +%s) * 1000 ))
printf '{"schema_version":2,"generation":7,"config_sha256":"%s","updated_unix_ms":%s}\n' "$runtime_sha" "$now_ms" > "$passive_status"

python3 - "$control_socket" <<'PY' &
import socket
import sys
import time

listener = socket.socket(socket.AF_UNIX)
listener.bind(sys.argv[1])
time.sleep(30)
PY
socket_pid=$!
for _ in 1 2 3 4 5; do
	[ -S "$control_socket" ] && break
	sleep 1
done

run_health() {
	PATH="$tmp/bin:$PATH" \
	CANDY_READY_FILE="$ready_file" \
	CANDY_RUNTIME_CONFIG="$runtime_config" \
	CANDY_PASSIVE_STATUS_FILE="$passive_status" \
	CANDY_CONTROL_SOCKET="$control_socket" \
	CANDY_SERVICE_INIT="$tmp/service" \
	CANDY_PROC_ROOT="$tmp/proc" \
	CANDY_CORE_EXECUTABLE_NAME=candy-core \
	"$health" client
}

run_health || fail "valid local runtime health contract was rejected"
printf '{"schema_version":2,"generation":7,"config_sha256":"%s","updated_unix_ms":1}\n' "$runtime_sha" > "$passive_status"
if run_health; then
	fail "stale Core heartbeat was accepted"
fi
printf '{"schema_version":2,"generation":7,"config_sha256":"%064d","updated_unix_ms":%s}\n' 0 "$now_ms" > "$passive_status"
if run_health; then
	fail "passive status for a different runtime config was accepted"
fi
printf '{"schema_version":2,"generation":0,"config_sha256":"%s","updated_unix_ms":%s}\n' "$runtime_sha" "$now_ms" > "$passive_status"
if run_health; then
	fail "zero runtime generation was accepted"
fi

printf '%s\n' "Candy OpenWrt semantic runtime health check passed"
