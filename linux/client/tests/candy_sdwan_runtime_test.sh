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
fake_sync_init=$tmp/fake-cloud-sync-init
fake_sync_calls=$tmp/fake-cloud-sync.calls
cat >"$fake_sync_init" <<'EOF'
#!/bin/sh
printf '%s\n' "$1" >>"$FAKE_SYNC_CALLS"
EOF
chmod 0755 "$fake_sync_init"

run_runtime() {
	CANDY_SDWAN_TEST_MODE=1 CANDY_CLOUD_ENROLL_PLATFORM=LINUX CANDY_SDWAN_STATE_DIR="$state" CANDY_SDWAN_RUN_DIR="$run" \
		CANDY_SDWAN_CONFIG_CACHE="$state/config-v1.json" \
		CANDY_SDWAN_STATUS_CACHE="$state/status-v1.json" \
		CANDY_SDWAN_STATUS_FILE="$run/sdwan-status.json" \
		CANDY_CLOUD_ENROLL_CLIENT="$fake_enroll" CANDY_CLOUD_SYNC_INIT="$fake_sync_init" \
		FAKE_SYNC_CALLS="$fake_sync_calls" "$runtime" "$@"
}

run_runtime bootstrap "$bootstrap"
[ "$(sed -n '1p' "$fake_sync_calls")" = enable ] || fail "join did not enable Cloud synchronization across reboot"
[ "$(sed -n '2p' "$fake_sync_calls")" = restart ] || fail "join did not start Cloud synchronization immediately"
[ -f "$state/config-v1.json" ] || fail "join did not atomically create config cache"
grep -F '"action":"join","outcome":"completed"' "$state/events-v1.log" >/dev/null || fail "completed enrollment was not durably audited"
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

chmod 0770 "$run"
run_runtime stopped
run_mode=$(stat -c '%a' "$run" 2>/dev/null || stat -f '%Lp' "$run")
[ "$run_mode" = 770 ] || fail "stopped changed existing runtime directory mode to $run_mode"

run_runtime fail-open core-exit
grep -F '"state":"fail-open"' "$run/sdwan-status.json" >/dev/null || fail "fail-open state missing"
[ -f "$state/config-v1.json" ] || fail "fail-open removed durable enrollment intent"
run_mode=$(stat -c '%a' "$run" 2>/dev/null || stat -f '%Lp' "$run")
[ "$run_mode" = 770 ] || fail "fail-open changed existing runtime directory mode to $run_mode"

mkdir -p "$state/generations/test-generation"
mkdir -p "$state/activations/test-activation" "$state/grants/test-pool"
printf '%s\n' profile >"$state/profile-v1.json"
printf '%s\n' sync >"$state/sync-state-v1.json"
printf '%s\n' status >"$state/cloud-sync-status-v1.json"
printf '%s\n' transport >"$state/transport-identity-state-v1.json"
printf '%s\n' receipt >"$state/activation-ready-v1.json"
printf '%s\n' proof >"$state/active-activation-v1.json"
printf '%s\n' target >"$state/reconcile-target-v1"
ln -s generations/test-generation "$state/configuration"
ln -s activations/test-activation "$state/candidate"
ln -s activations/test-activation "$state/active"
mkdir -p "$tmp/busybox-bin"
cat >"$tmp/busybox-bin/find" <<'EOF'
#!/bin/sh
# OpenWrt BusyBox find intentionally has no GNU -delete/-mindepth options.
printf '%s\n' "find must not be used by leave cleanup" >&2
exit 99
EOF
chmod 0755 "$tmp/busybox-bin/find"
PATH="$tmp/busybox-bin:$PATH" run_runtime leave
rm -rf "$tmp/busybox-bin"
grep -Fx stop "$fake_sync_calls" >/dev/null || fail "leave did not stop Cloud synchronization"
grep -Fx disable "$fake_sync_calls" >/dev/null || fail "leave did not disable Cloud synchronization"
[ ! -e "$state/profile-v1.json" ] || fail "leave retained Cloud profile"
[ ! -e "$state/sync-state-v1.json" ] || fail "leave retained Cloud synchronization state"
[ ! -e "$state/cloud-sync-status-v1.json" ] || fail "leave retained Cloud synchronization status"
[ ! -e "$state/configuration" ] || fail "leave retained active Cloud configuration pointer"
[ ! -e "$state/candidate" ] || fail "leave retained candidate activation pointer"
[ ! -e "$state/active" ] || fail "leave retained active activation pointer"
[ ! -e "$state/transport-identity-state-v1.json" ] || fail "leave retained Cloud transport identity state"
[ ! -e "$state/activation-ready-v1.json" ] || fail "leave retained activation receipt"
[ ! -e "$state/active-activation-v1.json" ] || fail "leave retained active activation proof"
[ ! -e "$state/reconcile-target-v1" ] || fail "leave retained reconciliation target"
[ ! -e "$state/activations" ] || fail "leave retained immutable Cloud activations"
[ ! -e "$state/grants" ] || fail "leave retained Cloud Grant cache"
[ -f "$state/events-v1.log" ] || fail "leave removed the durable lifecycle audit"
grep -F '"action":"leave","outcome":"completed"' "$state/events-v1.log" >/dev/null || fail "local identity removal was not durably audited"
[ ! -e "$state/generations" ] || fail "leave retained immutable Cloud generations"
FAKE_ENROLL_FAIL=1 run_runtime bootstrap "$bootstrap" >/dev/null 2>&1 &&
	fail "failed Cloud enrollment unexpectedly succeeded"
grep -F '"action":"join","outcome":"failed"' "$state/events-v1.log" >/dev/null || fail "failed enrollment was not durably audited"
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

privileged_bin=$tmp/privileged-bin
privileged_state=$tmp/root-owned-state
privileged_run=$tmp/root-owned-run
privileged_calls=$tmp/privileged.calls
compatibility_root=$privileged_state/activations/test/compatibility-generations/generation-3
compatibility_peers=$compatibility_root/peer-projections
mkdir -p "$privileged_bin" "$privileged_state/identity" "$compatibility_peers"
printf '%s\n' legacy >"$privileged_state/identity/device-identity-v1.json"
printf '%s\n' segment >"$compatibility_root/segment.snapshot"
printf '%s\n' projection >"$compatibility_peers/peer.projection"
printf '%s\n' outside >"$tmp/outside-state"
ln -s "$tmp/outside-state" "$privileged_state/outside-link"
chmod 0755 "$privileged_state" "$privileged_state/identity"
chmod 0644 "$privileged_state/identity/device-identity-v1.json" "$tmp/outside-state"
chmod 0700 "$compatibility_root" "$compatibility_peers"
chmod 0600 "$compatibility_root/segment.snapshot" "$compatibility_peers/peer.projection"
cat >"$privileged_bin/id" <<'EOF'
#!/bin/sh
case "${1:-}" in
	-u) printf '%s\n' 0 ;;
	*) exit 0 ;;
esac
EOF
cat >"$privileged_bin/chown" <<'EOF'
#!/bin/sh
printf '<%s>' "$@" >>"$FAKE_PRIVILEGED_CALLS"
printf '\n' >>"$FAKE_PRIVILEGED_CALLS"
EOF
chmod 0755 "$privileged_bin/id" "$privileged_bin/chown"
PATH="$privileged_bin:$PATH" FAKE_PRIVILEGED_CALLS="$privileged_calls" \
	CANDY_SDWAN_TEST_MODE=0 CANDY_SDWAN_SERVICE_USER=candy-service \
	CANDY_SDWAN_SERVICE_GROUP=candy-service CANDY_SDWAN_STATE_DIR="$privileged_state" \
	CANDY_SDWAN_RUN_DIR="$privileged_run" "$runtime" stopped
[ "$(stat -c '%a' "$privileged_state/identity" 2>/dev/null || stat -f '%Lp' "$privileged_state/identity")" = 700 ] ||
	fail "legacy SD-WAN state directory was not restored to mode 0700"
[ "$(stat -c '%a' "$privileged_state/identity/device-identity-v1.json" 2>/dev/null || stat -f '%Lp' "$privileged_state/identity/device-identity-v1.json")" = 600 ] ||
	fail "legacy SD-WAN state file was not restored to mode 0600"
[ "$(stat -c '%a' "$compatibility_root" 2>/dev/null || stat -f '%Lp' "$compatibility_root")" = 500 ] ||
	fail "compatibility generation directory was not kept read-only"
[ "$(stat -c '%a' "$compatibility_root/segment.snapshot" 2>/dev/null || stat -f '%Lp' "$compatibility_root/segment.snapshot")" = 400 ] ||
	fail "compatibility segment snapshot was not kept read-only"
[ "$(stat -c '%a' "$compatibility_peers/peer.projection" 2>/dev/null || stat -f '%Lp' "$compatibility_peers/peer.projection")" = 400 ] ||
	fail "compatibility peer projection was not kept read-only"
[ "$(stat -c '%a' "$tmp/outside-state" 2>/dev/null || stat -f '%Lp' "$tmp/outside-state")" = 644 ] ||
	fail "state delegation followed a symbolic link outside the state root"
grep -F '<candy-service:candy-service>' "$privileged_calls" >/dev/null ||
	fail "root-owned SD-WAN state was not delegated to the configured service identity"
chmod -R u+w "$privileged_state"

systemd_bin=$tmp/systemd-bin
systemd_state=$tmp/systemd-state
systemd_calls=$tmp/systemd.calls
status_inspector_calls=$tmp/status-inspector.calls
mkdir -p "$systemd_bin" "$systemd_state"
cat >"$systemd_bin/systemctl" <<'EOF'
#!/bin/sh
set -eu
action=${1:-}
service=
for argument in "$@"; do service=$argument; done
case "$action" in
	is-active) [ -f "$FAKE_SYSTEMD_STATE/$service" ] ;;
	start|restart|stop)
		printf '%s %s\n' "$action" "$service" >>"$FAKE_SYSTEMD_CALLS"
		[ "${FAKE_SYSTEMD_FAIL_ACTION:-}" != "$action" ] || exit 1
		case "$action" in
			start|restart) : >"$FAKE_SYSTEMD_STATE/$service" ;;
			stop) rm -f "$FAKE_SYSTEMD_STATE/$service" ;;
		esac
		;;
	*) exit 64 ;;
esac
EOF
chmod 0755 "$systemd_bin/systemctl"
fake_status_inspector=$tmp/fake-status-inspector
cat >"$fake_status_inspector" <<'EOF'
#!/bin/sh
set -eu
[ "${1:-}" = --state-dir ]
[ "${3:-}" = --run-dir ]
[ "${5:-}" = project-local-runtime-status ]
printf '%s\n' "$*" >>"$FAKE_STATUS_INSPECTOR_CALLS"
[ "${FAKE_STATUS_INSPECTOR_FAIL:-0}" != 1 ] || exit 1
printf '%s\n' "${FAKE_VERIFIED_RUNTIME_STATE:-reconnecting}"
EOF
chmod 0755 "$fake_status_inspector"
run_reconcile() {
	role_state=$1
	service=$2
	shift 2
	PATH="$systemd_bin:$PATH" FAKE_SYSTEMD_STATE="$systemd_state" \
		FAKE_SYSTEMD_CALLS="$systemd_calls" CANDY_SDWAN_TEST_MODE=1 \
		FAKE_STATUS_INSPECTOR_CALLS="$status_inspector_calls" \
		CANDY_SDWAN_STATE_DIR="$role_state" CANDY_SDWAN_RUN_DIR="$tmp/reconcile-run" \
		CANDY_SDWAN_STATUS_INSPECTOR="$fake_status_inspector" \
		"$@" "$runtime" reconcile "$service"
}

client_reconcile=$tmp/client-reconcile
mkdir -p "$client_reconcile/activations"
run_reconcile "$client_reconcile" candy-sdwan.service env >/dev/null
[ ! -s "$systemd_calls" ] || fail "empty initial candidate changed the Linux client service"
activation_a=$(printf 'a%.0s' $(seq 1 64))
mkdir "$client_reconcile/activations/$activation_a"
ln -s "activations/$activation_a" "$client_reconcile/candidate"
run_reconcile "$client_reconcile" candy-sdwan.service env >/dev/null
grep -Fx 'start candy-sdwan.service' "$systemd_calls" >/dev/null || fail "new candidate did not start the Linux client"
calls_before=$(wc -l <"$systemd_calls")
run_reconcile "$client_reconcile" candy-sdwan.service env FAKE_VERIFIED_RUNTIME_STATE=running >/dev/null
[ "$(wc -l <"$systemd_calls")" -eq "$calls_before" ] || fail "unchanged candidate restarted the Linux client"
grep -F 'project-local-runtime-status' "$status_inspector_calls" >/dev/null ||
	fail "unchanged candidate did not request verified product status projection"
if run_reconcile "$client_reconcile" candy-sdwan.service env FAKE_STATUS_INSPECTOR_FAIL=1 >/dev/null 2>&1; then
	fail "failed Core status verification unexpectedly reconciled"
fi
grep -F '"state":"fail-open"' "$tmp/reconcile-run/sdwan-status.json" >/dev/null ||
	fail "failed Core status verification was not projected as fail-open"
rm -f "$systemd_state/candy-sdwan.service"
run_reconcile "$client_reconcile" candy-sdwan.service env >/dev/null
[ "$(tail -n 1 "$systemd_calls")" = 'start candy-sdwan.service' ] || fail "inactive client was not restored for an unchanged candidate"

activation_b=$(printf 'b%.0s' $(seq 1 64))
mkdir "$client_reconcile/activations/$activation_b"
ln -sfn "activations/$activation_b" "$client_reconcile/candidate"
if run_reconcile "$client_reconcile" candy-sdwan.service env FAKE_SYSTEMD_FAIL_ACTION=restart >/dev/null 2>&1; then
	fail "failed candidate restart unexpectedly succeeded"
fi
[ "$(cat "$client_reconcile/reconcile-target-v1")" = "activations/$activation_a" ] ||
	fail "failed restart committed the new reconciliation marker"
run_reconcile "$client_reconcile" candy-sdwan.service env >/dev/null
[ "$(cat "$client_reconcile/reconcile-target-v1")" = "activations/$activation_b" ] ||
	fail "successful retry did not commit the replacement candidate marker"
rm -f "$client_reconcile/candidate"
if run_reconcile "$client_reconcile" candy-sdwan.service env FAKE_SYSTEMD_FAIL_ACTION=stop >/dev/null 2>&1; then
	fail "failed candidate withdrawal unexpectedly succeeded"
fi
[ "$(cat "$client_reconcile/reconcile-target-v1")" = "activations/$activation_b" ] ||
	fail "failed stop committed the withdrawal marker"
run_reconcile "$client_reconcile" candy-sdwan.service env >/dev/null
[ "$(tail -n 1 "$systemd_calls")" = 'stop candy-sdwan.service' ] || fail "candidate withdrawal did not stop the Linux client"
calls_before=$(wc -l <"$systemd_calls")
run_reconcile "$client_reconcile" candy-sdwan.service env >/dev/null
[ "$(wc -l <"$systemd_calls")" -eq "$calls_before" ] || fail "stable withdrawal repeated a Linux client lifecycle action"

activation_c=$(printf 'c%.0s' $(seq 1 64))
mkdir "$client_reconcile/activations/$activation_c"
ln -s "activations/$activation_c" "$client_reconcile/candidate"
run_reconcile "$client_reconcile" candy-sdwan.service env >/dev/null
rm -f "$systemd_state/candy-sdwan.service"
printf '%s\n' "{\"activation_id\":\"$activation_c\",\"state\":\"rejected\"}" >"$client_reconcile/activation-ready-v1.json"
calls_before=$(wc -l <"$systemd_calls")
run_reconcile "$client_reconcile" candy-sdwan.service env >/dev/null
run_reconcile "$client_reconcile" candy-sdwan.service env >/dev/null
[ "$(wc -l <"$systemd_calls")" -eq "$calls_before" ] || fail "rejected candidate was started again"

server_reconcile=$tmp/server-reconcile
mkdir -p "$server_reconcile/activations"
: >"$systemd_state/candy-server.service"
calls_before=$(wc -l <"$systemd_calls")
run_reconcile "$server_reconcile" candy-server.service env >/dev/null
[ "$(wc -l <"$systemd_calls")" -eq "$calls_before" ] || fail "initial withdrawal restarted the ordinary server"
cold_server_reconcile=$tmp/cold-server-reconcile
mkdir -p "$cold_server_reconcile/activations"
rm -f "$systemd_state/candy-server.service"
run_reconcile "$cold_server_reconcile" candy-server.service env >/dev/null
[ "$(tail -n 1 "$systemd_calls")" = 'start candy-server.service' ] || fail "initial sync did not restore an inactive ordinary server"
: >"$systemd_state/candy-server.service"
activation_d=$(printf 'd%.0s' $(seq 1 64))
mkdir "$server_reconcile/activations/$activation_d"
ln -s "activations/$activation_d" "$server_reconcile/candidate"
run_reconcile "$server_reconcile" candy-server.service env >/dev/null
[ "$(tail -n 1 "$systemd_calls")" = 'restart candy-server.service' ] || fail "server candidate did not restart the unified service"
calls_before=$(wc -l <"$systemd_calls")
run_reconcile "$server_reconcile" candy-server.service env >/dev/null
[ "$(wc -l <"$systemd_calls")" -eq "$calls_before" ] || fail "unchanged server candidate caused a restart"
rm -f "$systemd_state/candy-server.service"
run_reconcile "$server_reconcile" candy-server.service env >/dev/null
[ "$(tail -n 1 "$systemd_calls")" = 'start candy-server.service' ] || fail "inactive merged server was not restored"
rm -f "$server_reconcile/candidate"
run_reconcile "$server_reconcile" candy-server.service env >/dev/null
[ "$(tail -n 1 "$systemd_calls")" = 'restart candy-server.service' ] || fail "server withdrawal did not restore ordinary Candy"
calls_before=$(wc -l <"$systemd_calls")
run_reconcile "$server_reconcile" candy-server.service env >/dev/null
[ "$(wc -l <"$systemd_calls")" -eq "$calls_before" ] || fail "stable server withdrawal repeated a restart"
rm -f "$systemd_state/candy-server.service"
run_reconcile "$server_reconcile" candy-server.service env >/dev/null
[ "$(tail -n 1 "$systemd_calls")" = 'start candy-server.service' ] || fail "inactive ordinary server was not restored"

if [ -n "${CANDY_SDWAN_AGENT_BINARY:-}" ]; then
	agent=$CANDY_SDWAN_AGENT_BINARY
	[ -x "$agent" ] || fail "configured SD-WAN agent binary is not executable"
else
	command -v cargo >/dev/null 2>&1 || fail "cargo is required to verify the real SD-WAN agent CLI contract"
	cargo build --quiet --manifest-path "$root/Cargo.toml" --package candy-sdwan-agent
	agent=$root/target/debug/candy-sdwan-agent
fi
if "$agent" run --core "$tmp/missing-core" --activation "$tmp/missing-candidate" >"$tmp/documented-agent-order.out" 2>&1; then
	fail "agent unexpectedly accepted a missing activation"
fi
if grep -F 'unexpected argument' "$tmp/documented-agent-order.out" >/dev/null; then
	fail "documented run-first agent argument order is incompatible with the real CLI"
fi
grep -F 'inspect activation pointer' "$tmp/documented-agent-order.out" >/dev/null ||
	fail "real agent did not parse the documented run-first contract"
if "$agent" --core "$tmp/missing-core" --activation "$tmp/missing-candidate" run >"$tmp/new-agent-order.out" 2>&1; then
	fail "agent unexpectedly accepted a missing activation"
fi
if grep -F 'unexpected argument' "$tmp/new-agent-order.out" >/dev/null; then
	fail "Runtime service argument order is incompatible with the real agent CLI"
fi
grep -F 'inspect activation pointer' "$tmp/new-agent-order.out" >/dev/null ||
	fail "real agent did not parse the activation-first run contract"

printf '%s\n' "Candy SD-WAN Runtime cache behavior passed"
