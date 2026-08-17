#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
launcher=$root/linux/server/apps/candy-server/candy-server
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-server-launcher-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
tmp=$(CDPATH= cd -P -- "$tmp" && pwd -P)

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

fake_agent=$tmp/candy-sdwan-agent
cat >"$fake_agent" <<'EOF'
#!/bin/sh
set -eu
: "${FAKE_AGENT_ARGS:?}"
: "${FAKE_AGENT_CALLS:?}"
agent_command=
for argument in "$@"; do
	case "$argument" in run|validate-activation) agent_command=$argument ;; esac
done
[ -n "$agent_command" ] || exit 64
printf '<%s>\n' "$agent_command" >>"$FAKE_AGENT_CALLS"
: >"$FAKE_AGENT_ARGS"
for argument in "$@"; do
	printf '<%s>\n' "$argument" >>"$FAKE_AGENT_ARGS"
done
EOF
chmod 0755 "$fake_agent"

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

activation_id=$(printf 'ab%.0s' $(seq 1 32))
activation_dir=$tmp/sdwan/activations/$activation_id
mkdir -p "$activation_dir"
printf '%s\n' '{"schema_version":1,"core_role":"server"}' >"$activation_dir/activation-v1.json"
ln -s "activations/$activation_id" "$tmp/sdwan/candidate"
agent_args=$tmp/agent.args
agent_calls=$tmp/agent.calls
: >"$args_file"
CANDY_CORE_BINARY="$tmp//candy-core" CANDY_SDWAN_AGENT="$fake_agent" \
	CANDY_SDWAN_STATE_ROOT="$tmp/sdwan" \
	CANDY_SDWAN_ACTIVATION_LINK="$tmp/sdwan/candidate" \
	FAKE_AGENT_ARGS="$agent_args" FAKE_AGENT_CALLS="$agent_calls" \
	FAKE_ARGS_FILE="$args_file" FAKE_PID_FILE="$pid_file" \
	"$launcher" --config /tmp/server.toml
cat >"$tmp/expected.agent.args" <<EOF
<--activation>
<$tmp/sdwan/candidate/activation-v1.json>
<--activation-ready>
<$tmp/sdwan/activation-ready-v1.json>
<--core>
<$fake_core>
<--ordinary-config>
</tmp/server.toml>
<--socket>
</run/candy-netd/netd.sock>
<run>
EOF
cmp "$tmp/expected.agent.args" "$agent_args" >/dev/null ||
	fail "authenticated server activation did not use the frozen agent contract"
[ "$(grep -Fc '<validate-activation>' "$agent_calls")" -eq 1 ] ||
	fail "server activation was not validated exactly once"
[ "$(grep -Fc '<run>' "$agent_calls")" -eq 1 ] ||
	fail "server activation did not start exactly one transaction agent"
[ ! -s "$args_file" ] || fail "launcher started an ordinary Core before the server-role agent"

printf '%s\n' "{\"schema_version\":1,\"activation_id\":\"$activation_id\",\"candidate_target\":\"activations/$activation_id\",\"generation\":1,\"agent_pid\":1,\"state\":\"rejected\",\"error_code\":\"core_exit\"}" >"$tmp/sdwan/activation-ready-v1.json"
: >"$args_file"
CANDY_CORE_BINARY="$fake_core" CANDY_SDWAN_AGENT="$fake_agent" \
	CANDY_SDWAN_STATE_ROOT="$tmp/sdwan" \
	CANDY_SDWAN_ACTIVATION_LINK="$tmp/sdwan/candidate" \
	FAKE_AGENT_ARGS="$agent_args" FAKE_AGENT_CALLS="$agent_calls" \
	FAKE_ARGS_FILE="$args_file" FAKE_PID_FILE="$pid_file" \
	"$launcher" --config /tmp/server.toml 2>"$tmp/rejected-activation.err"
grep -F 'already rejected; starting ordinary Candy only' "$tmp/rejected-activation.err" >/dev/null ||
	fail "rejected activation did not produce an actionable warning"
grep -Fx '</tmp/server.toml>' "$args_file" >/dev/null ||
	fail "rejected activation did not preserve the ordinary server"
[ "$(grep -Fc '<run>' "$agent_calls")" -eq 1 ] ||
	fail "rejected activation was submitted to the agent again"
rm -f "$tmp/sdwan/activation-ready-v1.json"

rm -f "$tmp/sdwan/candidate"
CANDY_CORE_BINARY="$fake_core" CANDY_SDWAN_AGENT="$fake_agent" \
	CANDY_SDWAN_STATE_ROOT="$tmp/sdwan" \
	CANDY_SDWAN_ACTIVATION_LINK="$tmp/sdwan/candidate" \
	FAKE_AGENT_ARGS="$agent_args" FAKE_AGENT_CALLS="$agent_calls" \
	FAKE_ARGS_FILE="$args_file" FAKE_PID_FILE="$pid_file" \
	"$launcher" --config /tmp/server.toml
grep -Fx '</tmp/server.toml>' "$args_file" >/dev/null ||
	fail "Cloud activation withdrawal did not preserve the ordinary server"

ln -s "$tmp/outside-activation.json" "$tmp/sdwan/candidate"
printf '%s\n' '{"schema_version":1,"core_role":"server"}' >"$tmp/outside-activation.json"
CANDY_CORE_BINARY="$fake_core" CANDY_SDWAN_AGENT="$fake_agent" \
	CANDY_SDWAN_STATE_ROOT="$tmp/sdwan" \
	CANDY_SDWAN_ACTIVATION_LINK="$tmp/sdwan/candidate" \
	FAKE_AGENT_ARGS="$agent_args" FAKE_AGENT_CALLS="$agent_calls" \
	FAKE_ARGS_FILE="$args_file" FAKE_PID_FILE="$pid_file" \
	"$launcher" --config /tmp/server.toml 2>"$tmp/invalid-activation.err"
grep -F 'ignored an invalid SD-WAN activation pointer' "$tmp/invalid-activation.err" >/dev/null ||
	fail "invalid activation did not produce an actionable warning"
grep -Fx '</tmp/server.toml>' "$args_file" >/dev/null ||
	fail "invalid activation prevented ordinary server startup"
rm -f "$tmp/sdwan/candidate"

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
