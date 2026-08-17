#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
runtime=$root/linux/common/apps/candy-sdwan-runtime/candy-sdwan-runtime
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-sdwan-runtime-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() { printf '%s\n' "candy_sdwan_runtime_test: $*" >&2; exit 1; }

state=$tmp/state
run=$tmp/run
bootstrap=$tmp/candy-node-bootstrap.json
cat >"$bootstrap" <<'EOF'
{"schema_version":1,"cloud_address":"https://cloud.example.test","bootstrap_code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":"2030-01-01T00:00:00Z"}
EOF
chmod 0600 "$bootstrap"
fake_enroll=$tmp/fake-enroll
cat >"$fake_enroll" <<'EOF'
#!/bin/sh
set -eu
state_dir=
bootstrap_file=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--state-dir) shift; state_dir=$1 ;;
		--bootstrap-file) shift; bootstrap_file=$1 ;;
		--expected-platform) shift; expected_platform=$1 ;;
		--expected-architecture) shift; expected_architecture=$1 ;;
	esac
	shift
done
[ -n "$state_dir" ]
[ -n "$bootstrap_file" ]
[ -f "$bootstrap_file" ]
[ "${expected_platform:-}" = LINUX ]
[ -n "${expected_architecture:-}" ]
[ "$(stat -c '%a' "$bootstrap_file" 2>/dev/null || stat -f '%Lp' "$bootstrap_file")" = 600 ]
if [ "${FAKE_ENROLL_FAIL:-0}" = 1 ]; then
	exit 1
fi
mkdir -p "$state_dir"
chmod 0700 "$state_dir"
printf '%s\n' '{"schema_version":1,"cloud_address":"https://cloud.example.test","organization_id":"00000000-0000-0000-0000-000000000001","device_id":"00000000-0000-0000-0000-000000000002","device_key_id":"00000000-0000-0000-0000-000000000003","not_after":"2030-01-01T00:00:00Z"}' >"$state_dir/device-identity-v1.json"
printf '%s\n' private >"$state_dir/operational-key.pem"
printf '%s\n' certificate >"$state_dir/device-cert.pem"
printf '%s\n' candy-persistent-installation >"$state_dir/installation-instance-id"
chmod 0600 "$state_dir"/*
printf '%s\n' '{"schema_version":1,"state":"registered"}'
EOF
chmod 0755 "$fake_enroll"

run_runtime() {
	CANDY_SDWAN_TEST_MODE=1 CANDY_CLOUD_ENROLL_PLATFORM=LINUX CANDY_SDWAN_STATE_DIR="$state" CANDY_SDWAN_RUN_DIR="$run" \
		CANDY_SDWAN_CONFIG_CACHE="$state/config-v1.json" \
		CANDY_SDWAN_STATUS_CACHE="$state/status-v1.json" \
		CANDY_SDWAN_STATUS_FILE="$run/sdwan-status.json" \
		CANDY_CLOUD_ENROLL_CLIENT="$fake_enroll" "$runtime" "$@"
}

run_runtime bootstrap "$bootstrap"
[ -f "$state/config-v1.json" ] || fail "join did not atomically create config cache"
[ "$(grep -o 'registered' "$state/config-v1.json" | head -1)" = registered ] || fail "join state is not registered"
if grep -F 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$state/config-v1.json" "$state/status-v1.json" "$run/sdwan-status.json" "$state/identity"/* >/dev/null; then
	fail "activation credential leaked into Runtime cache"
fi
if run_runtime bootstrap "$bootstrap" >/dev/null 2>&1; then
	fail "registered identity was replaceable without leaving the Cloud"
fi

status_before=$(cat "$run/sdwan-status.json")
case "$status_before" in
	*'"schema_version":1'*'"state":"registered"'*'"site":null'*'"path":null'*) ;;
	*) fail "unregistered status fabricated live SD-WAN data: $status_before" ;;
esac
config_mode=$(stat -c '%a' "$state/config-v1.json" 2>/dev/null || stat -f '%Lp' "$state/config-v1.json")
[ "$config_mode" = 600 ] || fail "config cache mode is $config_mode, expected 600"
CANDY_SDWAN_STATE_DIR="$state" CANDY_SDWAN_RUN_DIR="$run" \
	CANDY_SDWAN_CONFIG_CACHE="$state/config-v1.json" \
	CANDY_SDWAN_STATUS_CACHE="$state/status-v1.json" \
	CANDY_SDWAN_STATUS_FILE="$run/sdwan-status.json" "$runtime" status >/dev/null ||
	fail "read-only status unexpectedly requires root"
inode_before=$(stat -c '%i' "$run/sdwan-status.json" 2>/dev/null || stat -f '%i' "$run/sdwan-status.json")
run_runtime reconnect
inode_after=$(stat -c '%i' "$run/sdwan-status.json" 2>/dev/null || stat -f '%i' "$run/sdwan-status.json")
[ "$inode_before" != "$inode_after" ] || fail "status replacement was not atomic"
grep -F '"state":"reconnecting"' "$run/sdwan-status.json" >/dev/null || fail "reconnect state missing"

run_runtime stopped
grep -F '"state":"stopped"' "$run/sdwan-status.json" >/dev/null || fail "stopped state missing"

run_runtime fail-open core-exit
grep -F '"state":"fail-open"' "$run/sdwan-status.json" >/dev/null || fail "fail-open state missing"
[ -f "$state/config-v1.json" ] || fail "fail-open removed durable enrollment intent"

run_runtime leave
FAKE_ENROLL_FAIL=1 run_runtime bootstrap "$bootstrap" >/dev/null 2>&1 &&
	fail "failed Cloud enrollment unexpectedly succeeded"
grep -F '"state":"join-pending"' "$run/sdwan-status.json" >/dev/null || fail "failed enrollment did not remain diagnosable"
grep -F '"state":"stopped"' "$run/sdwan-status.json" >/dev/null || fail "failed enrollment changed the network runtime state"

insecure=$tmp/insecure.json
sed 's#https://cloud.example.test#http://insecure.example.test#' "$bootstrap" >"$insecure"
chmod 0600 "$insecure"
if run_runtime bootstrap "$insecure" >/dev/null 2>&1; then
	fail "insecure Cloud address was accepted"
fi
dd if=/dev/zero of="$tmp/oversized" bs=4096 count=2 >/dev/null 2>&1
chmod 0600 "$tmp/oversized"
if run_runtime bootstrap "$tmp/oversized" >/dev/null 2>&1; then
	fail "oversized bootstrap input was accepted"
fi

run_runtime leave
grep -F '"state":"unregistered"' "$run/sdwan-status.json" >/dev/null || fail "leave did not publish unregistered state"
[ ! -e "$state/config-v1.json" ] || fail "leave retained enrollment intent"
[ ! -e "$state/identity/device-identity-v1.json" ] || fail "leave retained Cloud device identity material"
[ "$(cat "$state/identity/installation-instance-id")" = candy-persistent-installation ] || fail "leave removed the persistent installation identity"

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
if FAKE_RUNTIME_CALLS="$fake_calls" CANDY_SDWAN_RUNTIME="$fake_runtime" PATH="$fake_bin:$PATH" \
	"$product" join --cloud https://cloud.example.test >"$tmp/join.out" 2>&1; then
	fail "removed candy join command unexpectedly succeeded"
fi
grep -F 'bootstrap FILE' "$tmp/join.out" >/dev/null || fail "removed join failure did not show bootstrap workflow"
if "$product" --help | grep -E 'join --cloud|activation-file|join-code-stdin' >/dev/null; then
	fail "public help exposes a removed enrollment path"
fi
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
