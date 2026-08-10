#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
launcher=$root/linux/server/apps/candy-server/candy-server
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-server-launcher-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() {
	printf '%s\n' "candy_server_launcher_test: $*" >&2
	exit 1
}

fake_core=$tmp/candy-core
cat >"$fake_core" <<'EOF'
#!/bin/sh
set -eu

case "${1:-}" in
	runtime-api-version)
		exit_code=${FAKE_INSPECT_EXIT:-0}
		[ "$exit_code" -eq 0 ] || exit "$exit_code"
		printf '%s\n' "${FAKE_CORE_API:-1}"
		;;
	server)
		shift
		: "${FAKE_ARGS_FILE:?}"
		: "${FAKE_PID_FILE:?}"
		printf '%s\n' "$$" >"$FAKE_PID_FILE"
		: >"$FAKE_ARGS_FILE"
		for argument in "$@"; do
			printf '<%s>\n' "$argument" >>"$FAKE_ARGS_FILE"
		done
		printf '%s\n' "${CANDY_RUNTIME_PROCESS_API_VERSION:-}" >"$FAKE_ARGS_FILE.api"
		printf '%s\n' "${CANDY_RUNTIME_ROLE:-}" >"$FAKE_ARGS_FILE.role"
		if [ "${FAKE_WAIT_FOR_TERM:-0}" = 1 ]; then
			trap 'exit "${FAKE_TERM_EXIT:-42}"' TERM
			while :; do
				sleep 10 &
				wait "$!" || true
			done
		fi
		exit "${FAKE_SERVER_EXIT:-0}"
		;;
	*)
		exit 64
		;;
esac
EOF
chmod 0755 "$fake_core"

managed_core=$tmp/cores/releases/v1/candy-core
mkdir -p "$(dirname -- "$managed_core")"
cp "$fake_core" "$managed_core"
ln -s releases/v1 "$tmp/cores/current"
managed_args=$tmp/managed.args
managed_pid=$tmp/managed.pid
CANDY_CORE_ROOT="$tmp/cores" \
	FAKE_ARGS_FILE="$managed_args" FAKE_PID_FILE="$managed_pid" \
	"$launcher" --config /tmp/managed.toml
grep -Fx '</tmp/managed.toml>' "$managed_args" >/dev/null ||
	fail "launcher did not locate Core through the managed current symlink"

if CANDY_CORE_BINARY="$tmp/missing-core" "$launcher" >"$tmp/missing.out" 2>&1; then
	fail "missing Core unexpectedly launched"
else
	status=$?
fi
[ "$status" -eq 69 ] || fail "missing Core exit code was $status, expected 69"
grep -F "managed data plane is not installed" "$tmp/missing.out" >/dev/null ||
	fail "missing Core error is not actionable"

if CANDY_CORE_BINARY="$fake_core" FAKE_CORE_API=2 "$launcher" >"$tmp/api.out" 2>&1; then
	fail "incompatible Core unexpectedly launched"
else
	status=$?
fi
[ "$status" -eq 78 ] || fail "incompatible Core exit code was $status, expected 78"
grep -F "requires process API 1" "$tmp/api.out" >/dev/null ||
	fail "incompatible Core error does not name the required API"

if CANDY_CORE_BINARY="$fake_core" FAKE_INSPECT_EXIT=17 "$launcher" >"$tmp/inspect.out" 2>&1; then
	fail "Core with failed API inspection unexpectedly launched"
else
	status=$?
fi
[ "$status" -eq 69 ] || fail "inspection failure exit code was $status, expected 69"
grep -F "inspection failed with exit code 17" "$tmp/inspect.out" >/dev/null ||
	fail "Core inspection failure does not preserve its exit evidence"

args_file=$tmp/args
pid_file=$tmp/pid
if CANDY_CORE_BINARY="$fake_core" \
	FAKE_ARGS_FILE="$args_file" FAKE_PID_FILE="$pid_file" FAKE_SERVER_EXIT=23 \
	"$launcher" --config "/tmp/server config.toml" --preflight; then
	fail "Core server exit 23 was not forwarded"
else
	status=$?
fi
[ "$status" -eq 23 ] || fail "Core server exit code was $status, expected 23"
cat >"$tmp/expected.args" <<'EOF'
<--config>
</tmp/server config.toml>
<--preflight>
EOF
cmp "$tmp/expected.args" "$args_file" >/dev/null || fail "server arguments changed at the process boundary"
[ "$(cat "$args_file.api")" = 1 ] || fail "Runtime API environment was not published"
[ "$(cat "$args_file.role")" = server ] || fail "Runtime role environment was not published"

signal_args=$tmp/signal.args
signal_pid=$tmp/signal.pid
CANDY_CORE_BINARY="$fake_core" \
	FAKE_ARGS_FILE="$signal_args" FAKE_PID_FILE="$signal_pid" FAKE_WAIT_FOR_TERM=1 \
	"$launcher" --config /tmp/server.toml &
runtime_pid=$!
attempt=0
while [ ! -s "$signal_pid" ] && [ "$attempt" -lt 100 ]; do
	attempt=$((attempt + 1))
	sleep 0.02
done
[ -s "$signal_pid" ] || fail "Core server did not start"
[ "$(cat "$signal_pid")" = "$runtime_pid" ] || fail "launcher did not exec Core into the Runtime PID"
kill -TERM "$runtime_pid"
if wait "$runtime_pid"; then
	fail "Core TERM exit unexpectedly succeeded"
else
	status=$?
fi
[ "$status" -eq 42 ] || fail "Core signal exit code was $status, expected 42"

if CANDY_CORE_BINARY="$launcher" "$launcher" >"$tmp/recursive.out" 2>&1; then
	fail "recursive Core selection unexpectedly launched"
else
	status=$?
fi
[ "$status" -eq 78 ] || fail "recursive Core exit code was $status, expected 78"
grep -F "points back to candy-server" "$tmp/recursive.out" >/dev/null ||
	fail "recursive Core error is not actionable"

printf '%s\n' "Candy Linux server process launcher test passed"
