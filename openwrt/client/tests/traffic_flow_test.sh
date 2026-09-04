#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail() { printf '%s\n' "traffic_flow_test: $*" >&2; exit 1; }

# Source the init functions without invoking an init command.
CANDY_DIRECT_COMMAND=__test__ . "$root/packages/candy-client/candy.init"

RUNTIME_DIR="$tmp/run/candy"
CANDY_TRAFFIC_PATH_FILE="$RUNTIME_DIR/traffic-path-v1.json"
LOG_FILE="$tmp/candy.log"
mkdir -p "$RUNTIME_DIR"

assert_path() {

	state=$1
	source=$2
	reason=$3

	json=$(cat "$CANDY_TRAFFIC_PATH_FILE")
	printf '%s\n' "$json" | grep -Fq '"state":"'"$state"'"' || fail "expected state=$state, got $json"
	printf '%s\n' "$json" | grep -Fq '"source":"'"$source"'"' || fail "expected source=$source, got $json"
	printf '%s\n' "$json" | grep -Fq '"reason":"'"$reason"'"' || fail "expected reason=$reason, got $json"
}

# SD-WAN active with selective site routes: unmatched traffic remains Proxy.
candy_process_running() { return 0; }
current_readiness() { return 0; }
sdwan_remote_egress_configured() { return 1; }
write_fallback_traffic_path sdwan_policy_unmatched
assert_path active candy_proxy sdwan_policy_unmatched

# An explicit Cloud remote-egress policy is the only case that owns 0/0.
sdwan_remote_egress_configured() { return 0; }
write_active_traffic_path_state
assert_path active sdwan cloud_policy_active

# SD-WAN failure withdraws only its own state; healthy Proxy remains active.
sdwan_remote_egress_configured() { return 1; }
write_fallback_traffic_path sdwan_failure
assert_path active candy_proxy sdwan_failure

# Proxy is independently unhealthy: final fallback is local WAN.
current_readiness() { return 1; }
write_fallback_traffic_path proxy_unavailable
assert_path degraded local_wan proxy_unavailable

# With SD-WAN inactive, the same Proxy/local-WAN decision still applies.
write_fallback_traffic_path sdwan_inactive
assert_path degraded local_wan sdwan_inactive

printf '%s\n' 'runtime traffic flow contract passed'
