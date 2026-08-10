#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
runtime=$root/linux/common/apps/candy-sdwan-runtime/candy-sdwan-runtime
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-sdwan-runtime-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() { printf '%s\n' "candy_sdwan_runtime_test: $*" >&2; exit 1; }

state=$tmp/state
run=$tmp/run
activation=$tmp/activation
printf '%s\n' 'join-secret-must-not-be-stored' >"$activation"

run_runtime() {
	CANDY_SDWAN_TEST_MODE=1 CANDY_SDWAN_STATE_DIR="$state" CANDY_SDWAN_RUN_DIR="$run" \
		CANDY_SDWAN_CONFIG_CACHE="$state/config-v1.json" \
		CANDY_SDWAN_STATUS_CACHE="$state/status-v1.json" \
		CANDY_SDWAN_STATUS_FILE="$run/sdwan-status.json" "$runtime" "$@"
}

run_runtime join https://cloud.example.test "$activation"
[ -f "$state/config-v1.json" ] || fail "join did not atomically create config cache"
[ "$(grep -o 'join-pending' "$state/config-v1.json")" = join-pending ] || fail "join state is not pending"
if grep -F 'join-secret-must-not-be-stored' "$state/config-v1.json" "$state/status-v1.json" "$run/sdwan-status.json" >/dev/null; then
	fail "activation credential leaked into Runtime cache"
fi

status_before=$(cat "$run/sdwan-status.json")
case "$status_before" in
	*'"schema_version":1'*'"site":null'*'"path":null'*) ;;
	*) fail "unregistered status fabricated live SD-WAN data: $status_before" ;;
esac
config_mode=$(stat -f '%Lp' "$state/config-v1.json" 2>/dev/null || stat -c '%a' "$state/config-v1.json")
[ "$config_mode" = 600 ] || fail "config cache mode is $config_mode, expected 600"
CANDY_SDWAN_STATE_DIR="$state" CANDY_SDWAN_RUN_DIR="$run" \
	CANDY_SDWAN_CONFIG_CACHE="$state/config-v1.json" \
	CANDY_SDWAN_STATUS_CACHE="$state/status-v1.json" \
	CANDY_SDWAN_STATUS_FILE="$run/sdwan-status.json" "$runtime" status >/dev/null ||
	fail "read-only status unexpectedly requires root"
inode_before=$(stat -f '%i' "$run/sdwan-status.json" 2>/dev/null || stat -c '%i' "$run/sdwan-status.json")
run_runtime reconnect
inode_after=$(stat -f '%i' "$run/sdwan-status.json" 2>/dev/null || stat -c '%i' "$run/sdwan-status.json")
[ "$inode_before" != "$inode_after" ] || fail "status replacement was not atomic"
grep -F '"state":"reconnecting"' "$run/sdwan-status.json" >/dev/null || fail "reconnect state missing"

run_runtime fail-open core-exit
grep -F '"state":"fail-open"' "$run/sdwan-status.json" >/dev/null || fail "fail-open state missing"
[ -f "$state/config-v1.json" ] || fail "fail-open removed durable enrollment intent"

if run_runtime join 'http://insecure.example.test' "$activation" >/dev/null 2>&1; then
	fail "insecure Cloud address was accepted"
fi
dd if=/dev/zero of="$tmp/oversized" bs=4096 count=2 >/dev/null 2>&1
if run_runtime join https://cloud.example.test "$tmp/oversized" >/dev/null 2>&1; then
	fail "oversized activation input was accepted"
fi

run_runtime leave
grep -F '"state":"unregistered"' "$run/sdwan-status.json" >/dev/null || fail "leave did not publish unregistered state"
[ ! -e "$state/config-v1.json" ] || fail "leave retained enrollment intent"

fake_runtime=$tmp/fake-runtime
fake_calls=$tmp/fake-runtime.calls
fake_bin=$tmp/bin
mkdir -p "$fake_bin"
cat >"$fake_runtime" <<'EOF'
#!/bin/sh
printf '<%s>' "$@" >>"$FAKE_RUNTIME_CALLS"
printf '\n' >>"$FAKE_RUNTIME_CALLS"
[ "${1:-}" != status ] || printf '%s\n' '{"schema_version":1,"registration":{"state":"unregistered"}}'
EOF
cat >"$fake_bin/systemctl" <<'EOF'
#!/bin/sh
exit "${FAKE_SYSTEMCTL_EXIT:-0}"
EOF
chmod 0755 "$fake_runtime" "$fake_bin/systemctl"
product=$root/linux/client/apps/candy/candy
FAKE_RUNTIME_CALLS="$fake_calls" CANDY_SDWAN_RUNTIME="$fake_runtime" PATH="$fake_bin:$PATH" \
	"$product" join --cloud https://cloud.example.test --activation-file "$activation" >"$tmp/join.out"
grep -F '<join><https://cloud.example.test>' "$fake_calls" >/dev/null || fail "public candy join did not use Runtime boundary"
FAKE_RUNTIME_CALLS="$fake_calls" CANDY_SDWAN_RUNTIME="$fake_runtime" PATH="$fake_bin:$PATH" \
	"$product" sdwan status >"$tmp/status.out"
grep -F '"schema_version":1' "$tmp/status.out" >/dev/null || fail "public candy status did not return V1 Runtime state"
if FAKE_RUNTIME_CALLS="$fake_calls" CANDY_SDWAN_RUNTIME="$fake_runtime" FAKE_SYSTEMCTL_EXIT=1 PATH="$fake_bin:$PATH" \
	"$product" sdwan reconnect >"$tmp/reconnect.out" 2>&1; then
	fail "failed reconnect unexpectedly succeeded"
fi
grep -F '<fail-open><reconnect failed; Candy-owned network state removed>' "$fake_calls" >/dev/null ||
	fail "failed reconnect did not invoke fail-open"
if grep -R -F 'candy-core' "$tmp/join.out" "$tmp/status.out" "$tmp/reconnect.out" >/dev/null; then
	fail "public candy output exposed the internal executable"
fi

printf '%s\n' "Candy SD-WAN Runtime cache behavior passed"
