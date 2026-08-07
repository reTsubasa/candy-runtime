#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../packages" && pwd)
runtime_dir=$(mktemp -d)
trap 'rm -rf "$runtime_dir"' EXIT

fail() {
  printf '%s\n' "openwrt_candy_init_config_test: $*" >&2
  exit 1
}

grep -F -- '--platform openwrt' "$repo_root/candy-client/candy.init" >/dev/null ||
  fail "OpenWrt Candy client command must select the openwrt transport profile"

controller=$repo_root/luci-app-candy/root/usr/lib/lua/luci/controller/candy.lua
grep -F 'validate_rules_text(uci, normalized)' "$controller" >/dev/null || fail "rules import must validate targets"
grep -F 'last_kind ~= "MATCH"' "$controller" >/dev/null || fail "rules import must require a final MATCH"
grep -F 'merge_multi_node_status(status)' "$controller" >/dev/null || fail "status endpoint must merge multi-node metrics"
! grep -Eq 'action_(link|cdn)_probe|candy-link-probe|candy-node-probes' "$controller" || fail "legacy probe controller remains"

CONFIG_ROOT=$runtime_dir/etc/config
INIT_ROOT=$runtime_dir/etc/init.d
mkdir -p "$CONFIG_ROOT" "$INIT_ROOT"

config_get() {
	var=$1
	section=$2
	option=$3
	default=${4:-}
	value=$default
	case "$section:$option" in
    client:enabled) value='1' ;;
    client:mode) value='rule' ;;
    client:runtime_mode) value='fallback' ;;
    client:selected_group) value='Proxy' ;;
    client:selected_node) value='hk-1' ;;
    client:dns_remote) value='1' ;;
    client:dns_mode) value='smart' ;;
    client:dns_split) value='1' ;;
    client:dns_unknown_strategy) value='parallel-validate' ;;
    client:dns_answer_geo_validate) value='1' ;;
    client:dns_domestic_resolvers) value='system,223.5.5.5:53,119.29.29.29:53' ;;
    client:dns_foreign_strategy) value='through-selected-node' ;;
    client:dns_egress_resolver) value='9.9.9.9:53' ;;
    client:dns_bootstrap_resolvers) value='system,223.5.5.5:53' ;;
    client:dns_cache) value='1' ;;
    client:dns_cache_max_entries) value='64' ;;
    client:dns_bind_answers_to_route) value='1' ;;
    client:dns_ttl_cap_seconds) value='180' ;;
    client:dns_negative_ttl_seconds) value='30' ;;
    client:performance_mode) value='auto' ;;
    client:lanes) value='auto' ;;
    client:udp_client_multiplier) value='2' ;;
    client:udp_server_multiplier) value='3' ;;
    client:dns_capture_lan) value='1' ;;
    client:filter_aaaa) value='1' ;;
    client:bypass_china_ip) value='1' ;;
    client:geo_update_url) value='file:///tmp/cn-ip.cidr' ;;
    client:geo_auto_update) value='0' ;;
    client:geo_update_interval_hours) value='24' ;;
    client:gfwlist_update_url) value='file:///tmp/gfwlist.txt' ;;
    client:gfwlist_auto_update) value='0' ;;
    client:gfwlist_update_interval_hours) value='24' ;;
    client:auto_firewall) value='1' ;;
    client:redirect_tcp) value='1' ;;
    client:redirect_udp) value='1' ;;
    client:block_quic) value='1' ;;
    client:transparent_tcp_port) value='12345' ;;
    client:transparent_udp_port) value='12346' ;;
    client:tproxy_mark) value='100' ;;
		sdwan:enabled) value='0' ;;
    hk-1:enabled) value='1' ;;
    hk-1:name) value='Hong Kong 1' ;;
    hk-1:server) value='104.243.28.153:18443' ;;
    hk-1:server_name) value='node.example.test' ;;
    hk-1:server_pin) value='sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789' ;;
    hk-1:auth) value='node-secret-with-"quote"-and-\slash' ;;
    hk-1:port_hopping_interval_seconds) value='120' ;;
    backup:enabled) value='1' ;;
    backup:name) value='Backup' ;;
    backup:server) value='198.51.100.20:18443' ;;
    backup:server_name) value='backup.example.test' ;;
    backup:server_pin) value='sha256:1111111111111111111111111111111111111111111111111111111111111111' ;;
    backup:auth) value='backup-secret-long' ;;
    Proxy:type) value='load-balance' ;;
    Fast:type) value='url-test' ;;
    Fast:url_test_url) value='http://www.gstatic.com/generate_204' ;;
    Fast:url_test_interval_seconds) value='60' ;;
    Fast:url_test_timeout_ms) value='3000' ;;
    Fast:url_test_validity_seconds) value='180' ;;
    Fast:url_test_tolerance_ms) value='20' ;;
    rule_geo:value) value='GEOIP,CN,DIRECT,no-resolve' ;;
    rule_match:value) value='MATCH,Proxy' ;;
  esac
	eval "$var=\$value"
}

config_get_bool() {
  config_get "$@"
}

config_list_foreach() {
	local section=$1 option=$2 callback=$3
  case "$section:$option" in
    Proxy:node)
      "$callback" hk-1
      "$callback" backup
      ;;
    Fast:node)
      "$callback" backup
      "$callback" hk-1
      ;;
    hk-1:port_hopping_port)
      "$callback" 10443
      "$callback" 20443
      ;;
  esac
}

config_foreach() {
	local callback=$1 type=$2
  case "$type" in
    node)
      "$callback" backup
      "$callback" hk-1
      ;;
    group)
      "$callback" Proxy
      "$callback" Fast
      ;;
    rule)
      "$callback" rule_geo
      "$callback" rule_match
      ;;
    forward)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

config_load() {
  test "$1" = candy
}

procd_open_instance() { printf '%s\n' "procd_open_instance" >> "$runtime_dir/procd.log"; }
procd_set_param() { printf '%s\n' "procd_set_param $*" >> "$runtime_dir/procd.log"; }
procd_close_instance() { printf '%s\n' "procd_close_instance" >> "$runtime_dir/procd.log"; }
iptables() { printf '%s\n' "iptables $*" >> "$runtime_dir/fw.log"; }
nft() { printf '%s\n' "nft $*" >> "$runtime_dir/fw.log"; }
fw4() { printf '%s\n' "fw4 $*" >> "$runtime_dir/fw.log"; }
service() { printf '%s\n' "service $*" >> "$runtime_dir/fw.log"; }
ip() {
  printf '%s\n' "ip $*" >> "$runtime_dir/fw.log"
  if [ "$1" = rule ] && [ "$2" = show ]; then
    return 0
  fi
  if [ "$1" = route ] && [ "$2" = show ]; then
    return 0
  fi
  case "$1 $2 $3 $5" in
    "rule del fwmark table")
      count_file="$runtime_dir/ip-rule-del-count-$4"
      count=0
      [ -f "$count_file" ] && count=$(cat "$count_file")
      count=$((count + 1))
      printf '%s\n' "$count" > "$count_file"
      [ "$count" -le 2 ] && return 0
      return 1
      ;;
  esac
  return 0
}
command() {
  if [ "$1" = "-v" ] && { [ "$2" = iptables ] || [ "$2" = iptables-save ] || [ "$2" = ip ]; }; then
    return 0
  fi
  if [ "$1" = "-v" ] && [ "$2" = ping ]; then
    return 0
  fi
  if [ "$1" = "-v" ] && [ "$2" = service ]; then
    return 0
  fi
  return 1
}

ping() {
  printf '%s\n' "ping $*" >> "$runtime_dir/ping.log"
  printf '%s\n' '64 bytes from 104.243.28.153: seq=0 ttl=49 time=24.7 ms'
}

test -f "$repo_root/candy-client/candy.init"
init_source=$repo_root/candy-client/candy.init
for direct_write in \
  '} > "$RUNTIME_CONFIG"' \
  '} > "$NODE_STATUS_FILE"' \
  '} > "$CANDY_LIFECYCLE_FILE"' \
  '} > "$dir/$DNSMASQ_CANDY_CONF"' \
  '} > "$FW4_INCLUDE"'; do
  if grep -F "$direct_write" "$init_source" >/dev/null; then
    fail "direct non-atomic write remains: $direct_write"
  fi
done
grep -F 'CANDY_READY_FILE=' "$init_source" >/dev/null || fail "missing readiness file"
grep -F 'logger -t candy -- "level=$level event=$event pid=$$ $*"' "$init_source" >/dev/null || fail "structured service lifecycle logs are not forwarded to syslog"
grep -F 'rotate_log_file "$LOG_FILE"' "$init_source" >/dev/null || fail "service log is not bounded by rotation"
! grep -F ': > "$LOG_FILE"' "$init_source" >/dev/null || fail "service log is erased during start"
grep -F 'rotate_log_file "$TRAFFIC_LOG_FILE" 2097152 5' "$init_source" >/dev/null || fail "traffic log does not retain bounded history"
! grep -F ': > "$TRAFFIC_LOG_FILE"' "$init_source" >/dev/null || fail "traffic history is erased during start"
grep -F '>>"$update_log" 2>&1' "$init_source" >/dev/null || fail "provider update history is overwritten"
grep -F 'service_failed()' "$init_source" >/dev/null || fail "missing procd service failure log hook"
grep -F 'rejected PROCESS-NAME because OpenWrt transparent routing has no trustworthy process identity' "$init_source" >/dev/null || fail "unsupported PROCESS-NAME rules are not rejected"
grep -F 'CANDY_CONFIG_RULE_ERROR' "$init_source" >/dev/null || fail "rule validation errors do not abort runtime config generation"
grep -F 'scheduling immediate fail-open' "$init_source" >/dev/null || fail "client crash supervisor does not schedule fail-open"
grep -F '! write_lock_process_identity "$CANDY_SERVICE_LOCK_DIR" "$$"' "$init_source" >/dev/null || fail "service lifecycle lock accepts missing process identity"
grep -F '! write_lock_process_identity "$NETWORK_APPLY_LOCK_DIR" "$$"' "$init_source" >/dev/null || fail "network policy lock accepts missing process identity"
! sed -n '/^with_service_lifecycle_lock()/,/^}/p' "$init_source" | grep -F 'rm -rf' >/dev/null || fail "service lifecycle lock uses recursive deletion"
grep -F 'Never infer ownership from the configured/default mark' "$init_source" >/dev/null || fail "firewall cleanup can delete an unowned policy mark"
grep -F 'log_msg "restart completed"' "$init_source" >/dev/null || fail "restart completion is not logged"
grep -F 'wait_for_current_readiness()' "$init_source" >/dev/null || fail "missing readiness wait"
grep -F 'service_started()' "$init_source" >/dev/null || fail "missing post-procd readiness hook"
grep -F 'if ! wait_for_current_readiness' "$init_source" >/dev/null || fail "start does not gate network apply on readiness"
grep -F 'rollback_network_policy_apply' "$init_source" >/dev/null || fail "missing partial apply rollback"
grep -F 'CANDY_SKIP_NETWORK_CLEANUP:-0' "$init_source" >/dev/null || fail "restart cannot preserve active network policy"
grep -F 'CANDY_NETWORK_CLEANUP_STATE="$cleanup_state" network_cleanup; then' "$init_source" >/dev/null || fail "stop can report stopped after cleanup failure"
grep -F 'CANDY_CLIENT_BIN=${CANDY_CLIENT_BIN:-/usr/bin/candy-client}' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'CANDY_DNS_LISTEN=${CANDY_DNS_LISTEN:-127.0.0.1:15353}' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'CANDY_RELEASE=${CANDY_RELEASE:-1}' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'run_client()' "$repo_root/candy-client/candy.init" >/dev/null
sed -n '/^run_client()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'ensure_no_existing_candy_client_before_start;' >/dev/null || fail "run_client can terminate another supervised client"
sed -n '/^start_service()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'ensure_no_existing_candy_client_before_start 1;' >/dev/null || fail "start_service cannot safely take over an old supervised client"
grep -F '[ "${CANDY_PROCD_START:-0}" != 1 ]' "$repo_root/candy-client/candy.init" >/dev/null || fail "ordinary start enters procd before the idempotency guard"
sed -n '/^start()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'start skipped: Candy service is already healthy' >/dev/null || fail "repeated healthy start can disrupt the active Candy service"
sed -n '/^start_service()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'start skipped: Candy service is already healthy' >/dev/null && fail "procd start transaction can return without submitting an instance"
grep -F 'CANDY_PASSIVE_STATUS_FILE=${CANDY_PASSIVE_STATUS_FILE:-$RUNTIME_DIR/passive-status.json}' "$repo_root/candy-client/candy.init" >/dev/null
grep -F -- '--passive-status-path "$CANDY_PASSIVE_STATUS_FILE"' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'clear_passive_status()' "$repo_root/candy-client/candy.init" >/dev/null
for lifecycle in run_client start_service cleanup_failed_start stop_service stop; do
  sed -n "/^$lifecycle()/,/^}/p" "$repo_root/candy-client/candy.init" | grep -F 'clear_passive_status' >/dev/null || fail "$lifecycle does not clear passive status"
done
grep -F 'procd_set_param command "$CANDY_INIT_SELF" run_client' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'procd_set_param user root' "$repo_root/candy-client/candy.init" >/dev/null || fail "Candy client does not retain the privileges required for transparent routing and QUIC socket buffers"
provider_updater_block=$(sed -n '/^start_provider_updater()/,/^}/p' "$repo_root/candy-client/candy.init")
printf '%s\n' "$provider_updater_block" | grep -F 'procd_set_param respawn 3600 10 5' >/dev/null ||
  fail "provider updater is not supervised after an unexpected scheduler exit"
provider_loop_block=$(sed -n '/^provider_update_loop()/,/^}/p' "$repo_root/candy-client/candy.init")
! printf '%s\n' "$provider_loop_block" | grep -F 'exit 0' >/dev/null ||
  fail "provider updater exits permanently after its first successful update"
grep -F 'migrate_reserved_dns_forward' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'forward local listen conflicts with reserved Candy DNS listener' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'CANDY_FAST_STATUS_ACTION' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'case "${action:-${1:-}}" in' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'status|running|enabled|stop|provider_update_once|provider_update_loop|network_apply|network_cleanup|reload_runtime|restart_queued|fail_open|health_watchdog|congestion_test|run_client|run_sdwan|run_netd)' "$repo_root/candy-client/candy.init" >/dev/null
grep -F -- '--control-socket-path "$CANDY_CONTROL_SOCKET"' "$repo_root/candy-client/candy.init" >/dev/null
grep -F -- '--active "$RUNTIME_CONFIG"' "$repo_root/candy-client/candy.init" >/dev/null || fail "runtime reload does not request atomic active-config promotion"
grep -F 'reload_service()' "$repo_root/candy-client/candy.init" >/dev/null
sed -n '/^reload_service()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'reload_runtime' >/dev/null
sed -n '/^apply_firewall()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'elif command -v nft' >/dev/null || fail "fw4 apply branch is missing"
sed -n '/^restart_queued_locked()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'CANDY_SKIP_NETWORK_CLEANUP=1' >/dev/null || fail "restart still reloads fw4 during stop"
sed -n '/^restart_queued_locked()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'CANDY_RESTART_IN_PROGRESS=1' >/dev/null || fail "restart does not preserve restarting status"
sed -n '/^stop()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'refresh_node_status_fast "starting"' >/dev/null || fail "restart is displayed as stopped"
sed -n '/^status_service()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'current_lifecycle_transition' >/dev/null || fail "status ignores active lifecycle transition"
grep -F 'CANDY_LIFECYCLE_TTL_SECONDS=${CANDY_LIFECYCLE_TTL_SECONDS:-10}' "$repo_root/candy-client/candy.init" >/dev/null || fail "lifecycle transition status has no expiry"
grep -F 'EXTRA_COMMANDS="$EXTRA_COMMANDS status running"' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'USE_PROCD=' "$repo_root/candy-client/candy.init" >/dev/null
! grep -F 'schedule_status_probe "running"' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'sent SIGHUP to dnsmasq' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'restarted dnsmasq and cleared cached DNS answers' "$repo_root/candy-client/candy.init" >/dev/null
sed -n '/^apply_dns()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'cmp -s "$temporary" "$destination"' >/dev/null || fail "DNS policy apply does not detect unchanged configuration"
sed -n '/^apply_dns()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'restart_dnsmasq || return 1' >/dev/null || fail "changed DNS policy does not clear dnsmasq cache"
grep -F 'procd_kill candy >/dev/null 2>&1 || true' "$repo_root/candy-client/candy.init" >/dev/null
! grep -F "procd_kill candy '*'" "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'CANDY_NETWORK_CLEANUP_STATE="$cleanup_state" network_cleanup' "$repo_root/candy-client/candy.init" >/dev/null
! grep -F 'CANDY_NETWORK_CLEANUP_STATE=stopped network_cleanup' "$repo_root/candy-client/candy.init" >/dev/null
sed -n '/^reload_runtime_locked()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'if ! apply_firewall; then' >/dev/null || fail "runtime reload does not refresh firewall policy"
sed -n '/^reload_runtime_locked()/,/^}/p' "$repo_root/candy-client/candy.init" | grep -F 'if ! apply_dns; then' >/dev/null || fail "runtime reload does not refresh dnsmasq policy"
grep -F 'chown root:root /var/lib/candy' "$repo_root/candy-client/candy.init" >/dev/null || fail "netd journal parent is not retained by root"
grep -F 'chown -R candy-sdwan:candy-sdwan "$CANDY_EPOCH_DIRECTORY"' "$repo_root/candy-client/candy.init" >/dev/null || fail "SD-WAN epoch directory is not delegated narrowly"
grep -F -- '--probe-socket "$CANDY_NETD_SOCKET"' "$repo_root/candy-client/candy.init" >/dev/null || fail "netd readiness does not perform a live socket probe"
grep -F 'verify_promoted_runtime_candidate "$candidate_sha"' "$repo_root/candy-client/candy.init" >/dev/null || fail "successful reload does not verify daemon promotion"
grep -F 'config_load candy 2>/dev/null || true' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'procd_set_param env CANDY_TRAFFIC_LOG="$TRAFFIC_LOG_FILE" CANDY_READY_FILE="$CANDY_READY_FILE" CANDY_PASSIVE_STATUS_FILE="$CANDY_PASSIVE_STATUS_FILE"' "$repo_root/candy-client/candy.init" >/dev/null
! grep -F 'log_traffic_msg "traffic decision log started for this boot"' "$repo_root/candy-client/candy.init" >/dev/null ||
  fail "service lifecycle markers still pollute the user traffic log"
! grep -F 'log_traffic_msg "service disabled; traffic capture is not active"' "$repo_root/candy-client/candy.init" >/dev/null ||
  fail "service state still pollutes the user traffic log"
! grep -F 'procd_set_param env CANDY_TRAFFIC_LOG="$TRAFFIC_LOG_FILE" CANDY_TRAFFIC_LOG_CONTROL=' "$repo_root/candy-client/candy.init" >/dev/null ||
  fail "traffic decision logging is still tied to the LuCI page lifetime"
test "$(grep -Fc 'procd_set_param respawn 3600 10 5' "$repo_root/candy-client/candy.init")" -eq 3 ||
  fail "long-running Candy procd instances must stop after a bounded crash loop"
! grep -F 'procd_set_param respawn 3600 10 0' "$repo_root/candy-client/candy.init" >/dev/null ||
  fail "Candy procd instances still retry forever"
grep -F 'procd_add_reload_trigger "candy"' "$repo_root/candy-client/candy.init" >/dev/null
grep -F 'logread 2>/dev/null | grep -i candy' "$repo_root/candy-client/candy.init" >/dev/null
grep -F -- '--check-config' "$repo_root/candy-client/candy.init" >/dev/null
grep -F "option enabled '0'" "$repo_root/candy-client/candy.config" >/dev/null || fail "bootstrap node must default disabled"
grep -F 'validate_node_profile_placeholders' "$repo_root/candy-client/candy.init" >/dev/null || fail "placeholder node validation is missing"
grep -F 'update Core to 0.3.7 or newer' "$repo_root/candy-client/candy.init" >/dev/null || fail "congestion test compatibility message is stale"
. "$repo_root/candy-client/candy.init"
TEST_CANDY_PROC_ROOT=$runtime_dir/proc
CANDY_PROC_ROOT=$TEST_CANDY_PROC_ROOT
mkdir -p "$CANDY_PROC_ROOT/$$" "$CANDY_PROC_ROOT/sys/kernel/random"
printf '%s\n' test-boot-id > "$CANDY_PROC_ROOT/sys/kernel/random/boot_id"
printf '%s\n' "$$ (candy-test) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345" > "$CANDY_PROC_ROOT/$$/stat"
DNSMASQ_RESTART_LOG=$runtime_dir/dnsmasq-restart.log
restart_dnsmasq() {
  printf '%s\n' restart >> "$DNSMASQ_RESTART_LOG"
}
pidof() {
  if [ "$1" = dnsmasq ]; then
    printf '%s\n' "$$"
    return 0
  fi
  return 1
}
kill() {
  if [ "$1" = -HUP ]; then
    return 0
  fi
  /bin/kill "$@"
}
rm -f /tmp/candy-json-injected
json_adversarial='node-$(touch /tmp/candy-json-injected)-`id`-'"'"'";line1
line2'
json_encoded=$(json_string "$json_adversarial")
case "$json_encoded" in
  *'\n'*) ;;
  *) fail "json_string did not escape embedded newline" ;;
esac
test ! -e /tmp/candy-json-injected || fail "json field command expansion executed"
RUNTIME_DIR=$runtime_dir/run/candy
RUNTIME_CONFIG=$RUNTIME_DIR/runtime.json
CANDY_FIREWALL_STATE_FILE=$RUNTIME_DIR/firewall.state
LOG_FILE=$runtime_dir/candy.log
NODE_STATUS_FILE=$runtime_dir/candy.nodes
NETWORK_APPLY_LOCK_DIR=$runtime_dir/candy-network-apply.lock
STATUS_PROBE_LOCK_DIR=$runtime_dir/candy-status-probe.lock
CANDY_CLIENT_BIN=$runtime_dir/candy-client-ok
CANDY_INIT_SELF=$repo_root/candy-client/candy.init
CANDY_BACKGROUND_INLINE=1
CONFIG_FILE=$CONFIG_ROOT/candy
LEGACY_CONFIG_FILE=$CONFIG_ROOT/carrier
GEO_ETC_RULESETS_DIR=$runtime_dir/etc/candy/rulesets
GEO_SHARE_RULESETS_DIR=$runtime_dir/usr/share/candy/rulesets
GEO_RUNTIME_RULESETS_DIR=$RUNTIME_DIR/rulesets
DNS_ETC_RULESETS_DIR=$runtime_dir/etc/candy/rulesets
DNS_SHARE_RULESETS_DIR=$runtime_dir/usr/share/candy/rulesets
DNS_RUNTIME_RULESETS_DIR=$RUNTIME_DIR/rulesets
mkdir -p "$GEO_SHARE_RULESETS_DIR"
printf '%s\n' '1.0.1.0/24' > "$GEO_SHARE_RULESETS_DIR/cn-ip.cidr"
printf '%s\n' 'google.com' 'youtube.com' 'googlevideo.com' > "$DNS_SHARE_RULESETS_DIR/gfwlist.domains"
cat > "$CANDY_CLIENT_BIN" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$CANDY_CLIENT_CALLS"
if [ "$1" = geo ] && [ "$2" = validate ]; then
  if [ "$(awk 'NF { n++ } END { print n + 0 }' "$5")" -gt 1 ]; then exit 0; fi
  printf '%s\n' 'Core provider validation unavailable' >&2
  exit 1
fi
if [ "$1" = dns ] && [ "$2" = validate ]; then
  if [ "$(awk 'NF { n++ } END { print n + 0 }' "$5")" -gt 1 ]; then exit 0; fi
  printf '%s\n' 'Core provider validation unavailable' >&2
  exit 1
fi
if [ "$1" = "status" ] && [ "$2" = "--path" ]; then
  cat "$3"
fi
exit 0
EOF
chmod +x "$CANDY_CLIENT_BIN"
export CANDY_CLIENT_CALLS=$runtime_dir/candy-client.calls
touch "$CANDY_CLIENT_CALLS"
CANDY_PASSIVE_STATUS_FILE=$RUNTIME_DIR/passive-status.json

test_placeholder_node_rejected() {
  ! validate_node_profile_placeholders sample '127.0.0.1:8443' localhost sample 'sha256:replace-me' 'change-me-long-random-secret' ||
    fail "enabled placeholder node was accepted"
}

test_placeholder_node_rejected

(
  provider_fallback_dir=$(mktemp -d)
  RUNTIME_DIR=$provider_fallback_dir/run/candy
  GEO_ETC_RULESETS_DIR=$provider_fallback_dir/etc/candy/rulesets
  GEO_SHARE_RULESETS_DIR=$provider_fallback_dir/usr/share/candy/rulesets
  GEO_RUNTIME_RULESETS_DIR=$RUNTIME_DIR/rulesets
  DNS_ETC_RULESETS_DIR=$GEO_ETC_RULESETS_DIR
  DNS_SHARE_RULESETS_DIR=$GEO_SHARE_RULESETS_DIR
  DNS_RUNTIME_RULESETS_DIR=$RUNTIME_DIR/rulesets
  LOG_FILE=$provider_fallback_dir/candy.log
  mkdir -p "$GEO_ETC_RULESETS_DIR" "$GEO_SHARE_RULESETS_DIR"
  printf '%s\n' '1.0.1.0/24' > "$GEO_ETC_RULESETS_DIR/cn-ip.cidr"
  printf '%s\n' '1.0.1.0/24' '2409:8000::/20' > "$GEO_SHARE_RULESETS_DIR/cn-ip.cidr"
  printf '%s\n' 'google.com' > "$DNS_ETC_RULESETS_DIR/gfwlist.domains"
  printf '%s\n' 'google.com' 'youtube.com' > "$DNS_SHARE_RULESETS_DIR/gfwlist.domains"

  refresh_runtime_geo_provider
  refresh_runtime_gfwlist_provider

  [ "$(grep -Fxc "geo validate cn-ip --candidate $GEO_ETC_RULESETS_DIR/cn-ip.cidr" "$CANDY_CLIENT_CALLS")" -eq 1 ] ||
    fail "China IP refresh repeated Core validation for one candidate"
  [ "$(grep -Fxc "dns validate gfwlist --candidate $DNS_ETC_RULESETS_DIR/gfwlist.domains" "$CANDY_CLIENT_CALLS")" -eq 1 ] ||
    fail "GFWList refresh repeated Core validation for one candidate"

  cmp -s "$GEO_SHARE_RULESETS_DIR/cn-ip.cidr" "$GEO_RUNTIME_RULESETS_DIR/cn-ip.cidr" ||
    fail "incomplete local China IP provider did not fall back to packaged bootstrap"
  cmp -s "$DNS_SHARE_RULESETS_DIR/gfwlist.domains" "$DNS_RUNTIME_RULESETS_DIR/gfwlist.domains" ||
    fail "incomplete local GFWList provider did not fall back to packaged bootstrap"
  [ -z "$GEO_LAST_ERROR" ] || fail "successful China IP fallback was reported as an error"
  [ -z "$GFWLIST_LAST_ERROR" ] || fail "successful GFWList fallback was reported as an error"
  [ "$GEO_ACTIVE_SOURCE" = bootstrap ] || fail "China IP fallback source was not exposed"
  [ "$GFWLIST_ACTIVE_SOURCE" = bootstrap ] || fail "GFWList fallback source was not exposed"
  printf '%s' "$GEO_LAST_WARNING" | grep -Fq 'Core provider validation unavailable' ||
    fail "China IP rejection did not expose Core validation failure"
  printf '%s' "$GFWLIST_LAST_WARNING" | grep -Fq 'Core provider validation unavailable' ||
    fail "GFWList rejection did not expose Core validation failure"
  grep -q 'provider=cn-ip source=local result=rejected' "$LOG_FILE"
  grep -q 'provider=gfwlist source=local result=rejected' "$LOG_FILE"
)

(
  provider_retention_dir=$(mktemp -d)
  GEO_ETC_RULESETS_DIR=$provider_retention_dir/etc
  GEO_SHARE_RULESETS_DIR=$provider_retention_dir/share
  DNS_ETC_RULESETS_DIR=$GEO_ETC_RULESETS_DIR
  DNS_SHARE_RULESETS_DIR=$GEO_SHARE_RULESETS_DIR
  mkdir -p "$GEO_ETC_RULESETS_DIR" "$GEO_SHARE_RULESETS_DIR"
  for index in 1 2 3 4 5 6 7 8 9 10; do
    printf '10.0.%s.0/24\n' "$index" >> "$GEO_SHARE_RULESETS_DIR/cn-ip.cidr"
    printf '2409:8000:%s::/48\n' "$index" >> "$GEO_SHARE_RULESETS_DIR/cn-ip.cidr"
    printf 'domain%s.example\n' "$index" >> "$DNS_SHARE_RULESETS_DIR/gfwlist.domains"
    if [ "$index" -lt 10 ]; then
      printf '10.0.%s.0/24\n' "$index" >> "$GEO_ETC_RULESETS_DIR/cn-ip.cidr"
      printf '2409:8000:%s::/48\n' "$index" >> "$GEO_ETC_RULESETS_DIR/cn-ip.cidr"
      printf 'domain%s.example\n' "$index" >> "$DNS_ETC_RULESETS_DIR/gfwlist.domains"
    fi
  done
  geo_provider_valid "$GEO_ETC_RULESETS_DIR/cn-ip.cidr" ||
    fail "legitimate China IP count drift was rejected"
  domain_provider_valid "$DNS_ETC_RULESETS_DIR/gfwlist.domains" ||
    fail "legitimate GFWList count drift was rejected"
)

generate_config

test -f "$RUNTIME_CONFIG"
test "$(stat -c %a "$RUNTIME_CONFIG" 2>/dev/null || stat -f %Lp "$RUNTIME_CONFIG")" = 600
grep -q '"name":"candy-openwrt"' "$RUNTIME_CONFIG"
grep -q '"mode":"rule"' "$RUNTIME_CONFIG"
! grep -q '"runtime_mode"' "$RUNTIME_CONFIG"
! grep -q '"selected_group"' "$RUNTIME_CONFIG"
! grep -q '"selected_node"' "$RUNTIME_CONFIG"
grep -Fq '"dns":{"remote":true,"mode":"smart","cache":{"enabled":true,"max_entries":64' "$RUNTIME_CONFIG"
grep -Fq '"split":{"enabled":true,"unknown_strategy":"parallel-validate","answer_geo_validate":true,"bind_answers_to_route":true,"ttl_cap_seconds":180,"negative_ttl_seconds":30' "$RUNTIME_CONFIG"
! grep -Fq 'stale_while_revalidate' "$RUNTIME_CONFIG"
! grep -Fq '"ecs"' "$RUNTIME_CONFIG"
! grep -Fq 'cname_classify' "$RUNTIME_CONFIG"
grep -Fq '"domestic_resolvers":["system","223.5.5.5:53","119.29.29.29:53"]' "$RUNTIME_CONFIG"
grep -Fq '"foreign_strategy":"through-selected-node"' "$RUNTIME_CONFIG"
grep -Fq '"egress_resolver":"9.9.9.9:53"' "$RUNTIME_CONFIG"
grep -Fq '"bootstrap_resolvers":["system","223.5.5.5:53"]' "$RUNTIME_CONFIG"
! grep -Fq 'dns-query' "$RUNTIME_CONFIG"
grep -Fq '"performance":{"mode":"auto"' "$RUNTIME_CONFIG"
grep -Fq '"lanes":"auto"' "$RUNTIME_CONFIG"
grep -Fq '"udp_redundancy":{"client_multiplier":2,"server_multiplier":3}' "$RUNTIME_CONFIG"
grep -Fq '"geo":{"bypass_china_ip":true,"providers":[{"name":"cn-ip","kind":"ip-cidr","path":' "$RUNTIME_CONFIG"
grep -Fq '"fallback_path":' "$RUNTIME_CONFIG"
grep -Fq '{"name":"Hong Kong 1"' "$RUNTIME_CONFIG"
grep -q '"server":"104.243.28.153:18443"' "$RUNTIME_CONFIG"
grep -q '"server_name":"node.example.test"' "$RUNTIME_CONFIG"
grep -q '"pin":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"' "$RUNTIME_CONFIG"
! grep -q '"server_pin"' "$RUNTIME_CONFIG"
grep -q '"auth":"node-secret-with-\\"quote\\"-and-\\\\slash"' "$RUNTIME_CONFIG"
grep -Fq '"port_hopping":{"ports":[10443,20443],"interval_seconds":120}' "$RUNTIME_CONFIG"
grep -q '"type":"load-balance"' "$RUNTIME_CONFIG"
grep -q '"nodes":\["Hong Kong 1","Backup"\]' "$RUNTIME_CONFIG"
grep -Fq '"name":"Fast","type":"url-test","nodes":["Backup","Hong Kong 1"],"url_test":{"url":"http://www.gstatic.com/generate_204","interval_seconds":60,"timeout_ms":3000,"validity_seconds":180,"tolerance_ms":20}' "$RUNTIME_CONFIG"
grep -q '"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"' "$RUNTIME_CONFIG"
grep -q '"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve"' "$RUNTIME_CONFIG"
grep -q '"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"' "$RUNTIME_CONFIG"
grep -q '"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve"' "$RUNTIME_CONFIG"
grep -q '"GEOIP,CN,DIRECT,no-resolve"' "$RUNTIME_CONFIG"
[ "$(grep -o '"GEOIP,CN,DIRECT,no-resolve"' "$RUNTIME_CONFIG" | wc -l | tr -d ' ')" = 1 ]
grep -q '"MATCH,Proxy"' "$RUNTIME_CONFIG"
grep -Fq '"forwards":[{"network":"udp","local":"127.0.0.1:15353","target":"9.9.9.9:53"}]' "$RUNTIME_CONFIG"
grep -Fq '"transparent_tcp":[{"local":"0.0.0.0:12345"}]' "$RUNTIME_CONFIG"
! grep -Fq '"transparent_udp":[{"local":"0.0.0.0:12346"}]' "$RUNTIME_CONFIG"
test -f "$GEO_RUNTIME_RULESETS_DIR/cn-ip.cidr"
refresh_node_status_fast "starting"
test -f "$NODE_STATUS_FILE"
grep -q '"nodes":\[' "$NODE_STATUS_FILE"
grep -q '"version":"0.4.0"' "$NODE_STATUS_FILE"
grep -q '"release":"1"' "$NODE_STATUS_FILE"
! grep -q '"build_id"' "$NODE_STATUS_FILE"
grep -q '"runtime":{"mode":"fallback","performance":{"mode":"auto","lanes":"auto"' "$NODE_STATUS_FILE"
grep -q '"configured_congestion":"candy-bbr"' "$NODE_STATUS_FILE"
grep -q '"configured_candy_bbr_preset":"current"' "$NODE_STATUS_FILE"
grep -q '"automatic_bbr_fallback":false' "$NODE_STATUS_FILE"
grep -q '"udp_client_multiplier":2,"udp_server_multiplier":3' "$NODE_STATUS_FILE"
grep -q '"id":"hk-1"' "$NODE_STATUS_FILE"
grep -q '"name":"Hong Kong 1"' "$NODE_STATUS_FILE"
grep -q '"state":"down"' "$NODE_STATUS_FILE"
grep -Fq '"groups":["Proxy","Fast"]' "$NODE_STATUS_FILE"
grep -q '"active_tcp_flows":0' "$NODE_STATUS_FILE"
grep -q '"url_test":{"status":"not-run","latency_ms":null' "$NODE_STATUS_FILE"
! grep -Eq '"selected"|"video_score"|"cdn_score"|"probe_source"|"ttfb_ms"' "$NODE_STATUS_FILE"
grep -q '"last_error":""' "$NODE_STATUS_FILE"
grep -q '"dns":{' "$NODE_STATUS_FILE"
grep -q '"geo":{' "$NODE_STATUS_FILE"
grep -q '"gfwlist":{' "$NODE_STATUS_FILE"
grep -q '"geo":{[^}]*"updated_at":"' "$NODE_STATUS_FILE"
grep -q '"gfwlist":{[^}]*"updated_at":"' "$NODE_STATUS_FILE"
grep -q '"diagnostics":{' "$NODE_STATUS_FILE"
grep -q '"udp_redundancy":{"client_multiplier":2,"server_multiplier":3' "$NODE_STATUS_FILE"
grep -q '"dns_trace":{"domain":"","status":"not-run"' "$NODE_STATUS_FILE"
grep -q '"connection":{"last_error":""' "$NODE_STATUS_FILE"
grep -q '"reconnect_policy":{"enabled":true,"initial_delay_ms":1000,"max_delay_ms":30000,"max_attempts":null}' "$NODE_STATUS_FILE"
! grep -Eq 'link probe|cdn probe|youtube.com|candy-link-probe|candy-node-probes' "$repo_root/candy-client/candy.init"
grep -q 'candy-client dns trace --config .*/runtime.json --format candy-json --egress-dns 9.9.9.9:53' "$NODE_STATUS_FILE"
! grep -q '"security_smoke"' "$NODE_STATUS_FILE"
! grep -q '"provider_freshness"' "$NODE_STATUS_FILE"
grep -q '"bypass_china_ip":true' "$NODE_STATUS_FILE"
grep -q '"active_path":".*/cn-ip.cidr"' "$NODE_STATUS_FILE"
grep -q '"entry_count":1' "$NODE_STATUS_FILE"
grep -q '"remote":true' "$NODE_STATUS_FILE"
grep -q '"capture_lan":true' "$NODE_STATUS_FILE"
grep -q '"filter_aaaa":true' "$NODE_STATUS_FILE"
grep -q '"applied":false' "$NODE_STATUS_FILE"

cat > "$CANDY_PASSIVE_STATUS_FILE" <<'EOF'
{"schema_version":2,"nodes":{"Hong Kong 1":{"state":"ready","groups":["Proxy","Fast"],"active_tcp_flows":2,"active_udp_flows":1,"reconnects":3,"url_test":{"status":"ok","latency_ms":42,"checked_unix_ms":17,"error":""},"passive":{"smoothed_rtt_micros":12500},"last_error":""}},"process":{"cpu_percent":2.5,"resident_memory_bytes":4096},"updated_unix_ms":17}
EOF
: > "$CANDY_CLIENT_CALLS"
refresh_node_status_fast "running"
grep -Fq '"multi_node":{"schema_version":2' "$NODE_STATUS_FILE"
grep -Fq '"active_tcp_flows":2' "$NODE_STATUS_FILE"
! grep -Eq 'link probe|cdn probe' "$CANDY_CLIENT_CALLS"
rm -f "$CANDY_PASSIVE_STATUS_FILE"
refresh_node_status_fast "running"
! grep -Fq '"multi_node":' "$NODE_STATUS_FILE"

apply_firewall
grep -q 'iptables -t nat -N CANDY' "$runtime_dir/fw.log"
grep -q 'iptables -t nat -A CANDY -d 104.243.28.153 -j RETURN' "$runtime_dir/fw.log"
grep -q 'iptables -t nat -A CANDY -d 198.51.100.20 -j RETURN' "$runtime_dir/fw.log"
grep -q 'iptables -t nat -A PREROUTING -p tcp -j CANDY' "$runtime_dir/fw.log"
grep -q 'iptables -A FORWARD -i br-lan -p udp --dport 443 -j REJECT' "$runtime_dir/fw.log"
grep -q 'iptables -t nat -A PREROUTING -i br-lan -p udp --dport 53 -j REDIRECT --to-ports 53' "$runtime_dir/fw.log"
grep -q 'iptables -t nat -A PREROUTING -i br-lan -p tcp --dport 53 -j REDIRECT --to-ports 53' "$runtime_dir/fw.log"
! grep -q 'iptables -t mangle -A PREROUTING -i br-lan -p udp --dport 443 -j TPROXY --on-port 12346 --tproxy-mark 100/100' "$runtime_dir/fw.log"
! grep -q 'ip rule add fwmark 100 table 100' "$runtime_dir/fw.log"
cleanup_firewall
grep -q 'iptables -t nat -D PREROUTING -p tcp -j CANDY' "$runtime_dir/fw.log"
grep -q 'iptables -D FORWARD -i br-lan -p udp --dport 443 -j REJECT' "$runtime_dir/fw.log"
grep -q 'iptables -t nat -D PREROUTING -i br-lan -p udp --dport 53 -j REDIRECT --to-ports 53' "$runtime_dir/fw.log"
grep -q 'iptables -t nat -D PREROUTING -i br-lan -p tcp --dport 53 -j REDIRECT --to-ports 53' "$runtime_dir/fw.log"

config_get() {
  var=$1
  section=$2
  option=$3
  default=${4:-}
  value=$default
  case "$section:$option" in
    client:auto_firewall) value='0' ;;
    client:transparent_udp_port) value='12346' ;;
    client:tproxy_mark) value='100' ;;
  esac
  eval "$var=\$value"
}
cleanup_firewall
count_cleanup_disabled=$(grep -c 'iptables -t nat -D PREROUTING -p tcp -j CANDY' "$runtime_dir/fw.log")
[ "$count_cleanup_disabled" -ge 2 ]

config_get() {
  var=$1
  section=$2
  option=$3
  default=${4:-}
  value=$default
  case "$section:$option" in
    client:enabled) value='1' ;;
    client:mode) value='rule' ;;
    client:runtime_mode) value='stable' ;;
    client:selected_group) value='Proxy' ;;
    client:selected_node) value='hk-1' ;;
    client:dns_remote) value='1' ;;
    client:dns_capture_lan) value='1' ;;
    client:filter_aaaa) value='1' ;;
    client:bypass_china_ip) value='1' ;;
    client:geo_update_url) value='file:///tmp/cn-ip.cidr' ;;
    client:geo_auto_update) value='0' ;;
    client:geo_update_interval_hours) value='24' ;;
    client:gfwlist_update_url) value='file:///tmp/gfwlist.txt' ;;
    client:gfwlist_auto_update) value='0' ;;
    client:gfwlist_update_interval_hours) value='24' ;;
    client:auto_firewall) value='1' ;;
    client:redirect_tcp) value='1' ;;
    client:redirect_udp) value='1' ;;
    client:block_quic) value='1' ;;
    client:transparent_tcp_port) value='12345' ;;
    client:transparent_udp_port) value='12346' ;;
    client:tproxy_mark) value='100' ;;
    hk-1:enabled) value='1' ;;
    hk-1:name) value='Hong Kong 1' ;;
    hk-1:server) value='104.243.28.153:18443' ;;
    hk-1:server_name) value='node.example.test' ;;
    hk-1:server_pin) value='sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789' ;;
    hk-1:auth) value='node-secret-with-"quote"-and-\slash' ;;
    backup:enabled) value='1' ;;
    backup:name) value='Backup' ;;
    backup:server) value='198.51.100.20:18443' ;;
    backup:server_name) value='backup.example.test' ;;
    backup:server_pin) value='sha256:1111111111111111111111111111111111111111111111111111111111111111' ;;
    backup:auth) value='backup-secret-long' ;;
    Proxy:type) value='select' ;;
    rule_match:value) value='MATCH,Proxy' ;;
  esac
  eval "$var=\$value"
}

fw_runtime_dir=$(mktemp -d)
runtime_dir=$fw_runtime_dir
RUNTIME_DIR=$runtime_dir/run/candy
RUNTIME_CONFIG=$RUNTIME_DIR/runtime.json
CANDY_FIREWALL_STATE_FILE=$RUNTIME_DIR/firewall.state
LOG_FILE=$runtime_dir/candy.log
NODE_STATUS_FILE=$runtime_dir/candy.nodes
NETWORK_APPLY_LOCK_DIR=$runtime_dir/candy-network-apply.lock
FW4_INCLUDE_DIR=$runtime_dir/nftables.d
FW4_INCLUDE=$FW4_INCLUDE_DIR/90-candy.nft
DNSMASQ_CONF_GLOB=$runtime_dir/dnsmasq.conf.*
GEO_ETC_RULESETS_DIR=$runtime_dir/etc/candy/rulesets
GEO_SHARE_RULESETS_DIR=$runtime_dir/usr/share/candy/rulesets
GEO_RUNTIME_RULESETS_DIR=$RUNTIME_DIR/rulesets
DNS_ETC_RULESETS_DIR=$runtime_dir/etc/candy/rulesets
DNS_SHARE_RULESETS_DIR=$runtime_dir/usr/share/candy/rulesets
DNS_RUNTIME_RULESETS_DIR=$RUNTIME_DIR/rulesets
mkdir -p "$runtime_dir/dnsmasq.test.d" "$FW4_INCLUDE_DIR"
mkdir -p "$GEO_SHARE_RULESETS_DIR"
printf '%s\n' '1.0.1.0/24' > "$GEO_SHARE_RULESETS_DIR/cn-ip.cidr"
printf '%s\n' 'google.com' 'github.com' 'youtube.com' 'googlevideo.com' > "$DNS_SHARE_RULESETS_DIR/gfwlist.domains"
printf '%s\n' "conf-dir=$runtime_dir/dnsmasq.test.d" > "$runtime_dir/dnsmasq.conf.test"
trap 'rm -rf "$runtime_dir" "$fw_runtime_dir"' EXIT

command() {
  if [ "$1" = "-v" ] && [ "$2" = iptables ]; then
    return 1
  fi
  if [ "$1" = "-v" ] && { [ "$2" = nft ] || [ "$2" = fw4 ] || [ "$2" = ip ]; }; then
    return 0
  fi
  if [ "$1" = "-v" ] && [ "$2" = service ]; then
    return 0
  fi
  return 1
}

apply_firewall
test -f "$FW4_INCLUDE"
grep -q 'chain candy_prerouting' "$FW4_INCLUDE"
! grep -q 'set candy_cn_v4' "$FW4_INCLUDE"
! grep -q 'ip daddr @candy_cn_v4 counter return' "$FW4_INCLUDE"
grep -q 'chain candy_forward' "$FW4_INCLUDE"
grep -q 'udp dport 443 counter reject' "$FW4_INCLUDE"
! grep -q 'chain candy_tproxy' "$FW4_INCLUDE"
! grep -q 'udp dport 443 tproxy to :12346 meta mark set 100 accept' "$FW4_INCLUDE"
grep -q 'udp dport 53 counter redirect to 53' "$FW4_INCLUDE"
grep -q 'tcp dport 53 counter redirect to 53' "$FW4_INCLUDE"
grep -q 'ip daddr 104.243.28.153 counter return' "$FW4_INCLUDE"
grep -q 'counter redirect to 12345' "$FW4_INCLUDE"
apply_dns
grep -q 'no-resolv' "$runtime_dir/dnsmasq.test.d/candy.conf"
grep -q 'server=127.0.0.1#15353' "$runtime_dir/dnsmasq.test.d/candy.conf"
grep -q 'filter-AAAA' "$runtime_dir/dnsmasq.test.d/candy.conf"
grep -q '"applied":true' "$NODE_STATUS_FILE"
grep -q '"config_path":".*/candy.conf"' "$NODE_STATUS_FILE"
cleanup_firewall
test ! -f "$FW4_INCLUDE"
grep -q 'nft delete chain inet fw4 candy_prerouting' "$runtime_dir/fw.log"
grep -q 'nft delete chain inet fw4 candy_forward' "$runtime_dir/fw.log"
grep -q 'nft delete chain inet fw4 candy_tproxy' "$runtime_dir/fw.log"
grep -q 'nft delete chain inet fw4 carrier_prerouting' "$runtime_dir/fw.log"
cleanup_dns
test ! -f "$runtime_dir/dnsmasq.test.d/candy.conf"
grep -q '"applied":false' "$NODE_STATUS_FILE"

config_get() {
  var=$1
  section=$2
  option=$3
  default=${4:-}
  value=$default
  case "$section:$option" in
    client:dns_remote) value='0' ;;
    client:filter_aaaa) value='1' ;;
    client:dns_capture_lan) value='1' ;;
    backup:enabled) value='0' ;;
    rule_google:value) value='DOMAIN-SUFFIX,example.com,Proxy' ;;
    rule_baidu:value) value='DOMAIN-SUFFIX,baidu.com,DIRECT' ;;
    rule_match:value) value='MATCH,Proxy' ;;
  esac
  eval "$var=\$value"
}

config_foreach() {
  callback=$1
  type=$2
  case "$type" in
    node)
      "$callback" hk-1
      "$callback" backup
      ;;
    group)
      "$callback" Proxy
      ;;
    rule)
      "$callback" rule_google
      "$callback" rule_baidu
      "$callback" rule_match
      ;;
    forward)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

apply_dns
grep -q 'filter-AAAA' "$runtime_dir/dnsmasq.test.d/candy.conf"
grep -q '^server=/google.com/127.0.0.1#15353$' "$runtime_dir/dnsmasq.test.d/candy.conf"
grep -q '^server=/example.com/127.0.0.1#15353$' "$runtime_dir/dnsmasq.test.d/candy.conf"
! grep -q '^server=/baidu.com/127.0.0.1#15353$' "$runtime_dir/dnsmasq.test.d/candy.conf"
! grep -q '^no-resolv$' "$runtime_dir/dnsmasq.test.d/candy.conf"
! grep -q '^server=127.0.0.1#15353$' "$runtime_dir/dnsmasq.test.d/candy.conf"

config_get() {
  var=$1
  section=$2
  option=$3
  default=${4:-}
  value=$default
  case "$section:$option" in
    client:dns_remote) value='0' ;;
    client:filter_aaaa) value='0' ;;
    client:dns_capture_lan) value='1' ;;
    backup:enabled) value='0' ;;
    rule_match:value) value='MATCH,Proxy' ;;
  esac
  eval "$var=\$value"
}

apply_dns
! grep -q 'filter-AAAA' "$runtime_dir/dnsmasq.test.d/candy.conf"
grep -q '^server=/google.com/127.0.0.1#15353$' "$runtime_dir/dnsmasq.test.d/candy.conf"
! grep -q '^no-resolv$' "$runtime_dir/dnsmasq.test.d/candy.conf"

config_get() {
  var=$1
  section=$2
  option=$3
  default=${4:-}
  value=$default
  case "$section:$option" in
    client:dns_remote) value='0' ;;
    client:dns_split) value='0' ;;
    client:filter_aaaa) value='0' ;;
    client:dns_capture_lan) value='1' ;;
    backup:enabled) value='0' ;;
    rule_google:value) value='DOMAIN-SUFFIX,example.com,Proxy' ;;
    rule_baidu:value) value='DOMAIN-SUFFIX,baidu.com,DIRECT' ;;
    rule_match:value) value='MATCH,Proxy' ;;
  esac
  eval "$var=\$value"
}

apply_dns
! grep -q '^server=/google.com/127.0.0.1#15353$' "$runtime_dir/dnsmasq.test.d/candy.conf"
! grep -q '^server=/github.com/127.0.0.1#15353$' "$runtime_dir/dnsmasq.test.d/candy.conf"
grep -q '^server=/example.com/127.0.0.1#15353$' "$runtime_dir/dnsmasq.test.d/candy.conf"
! grep -q '^server=/baidu.com/127.0.0.1#15353$' "$runtime_dir/dnsmasq.test.d/candy.conf"

config_get() {
  var=$1
  section=$2
  option=$3
  default=${4:-}
  value=$default
  case "$section:$option" in
    client:enabled) value='1' ;;
    client:mode) value='rule' ;;
    client:runtime_mode) value='performance' ;;
    client:selected_group) value='Proxy' ;;
    client:selected_node) value='hk-1' ;;
    client:dns_remote) value='0' ;;
    client:dns_capture_lan) value='0' ;;
    client:filter_aaaa) value='0' ;;
    client:bypass_china_ip) value='1' ;;
    client:geo_update_url) value='file:///tmp/cn-ip.cidr' ;;
    client:geo_auto_update) value='0' ;;
    client:geo_update_interval_hours) value='24' ;;
    client:gfwlist_update_url) value='file:///tmp/gfwlist.txt' ;;
    client:gfwlist_auto_update) value='0' ;;
    client:gfwlist_update_interval_hours) value='24' ;;
    client:auto_firewall) value='1' ;;
    client:redirect_tcp) value='1' ;;
    client:udp_client_multiplier) value='3' ;;
    client:udp_server_multiplier) value='3' ;;
    client:redirect_udp) value='1' ;;
    client:block_quic) value='0' ;;
    client:transparent_tcp_port) value='12345' ;;
    client:transparent_udp_port) value='12346' ;;
    client:tproxy_mark) value='100' ;;
    hk-1:enabled) value='1' ;;
    hk-1:name) value='Hong Kong 1' ;;
    hk-1:server) value='104.243.28.153:18443' ;;
    hk-1:server_name) value='node.example.test' ;;
    hk-1:server_pin) value='sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789' ;;
    hk-1:auth) value='node-secret-long-value' ;;
    backup:enabled) value='0' ;;
    Proxy:type) value='select' ;;
    rule_match:value) value='MATCH,Proxy' ;;
  esac
  eval "$var=\$value"
}

runtime_dir=$(mktemp -d)
RUNTIME_DIR=$runtime_dir/run/candy
RUNTIME_CONFIG=$RUNTIME_DIR/runtime.json
CANDY_FIREWALL_STATE_FILE=$RUNTIME_DIR/firewall.state
LOG_FILE=$runtime_dir/candy.log
NODE_STATUS_FILE=$runtime_dir/candy.nodes
FW4_INCLUDE_DIR=$runtime_dir/nftables.d
FW4_INCLUDE=$FW4_INCLUDE_DIR/90-candy.nft
DNSMASQ_CONF_GLOB=$runtime_dir/dnsmasq.conf.*
GEO_ETC_RULESETS_DIR=$runtime_dir/etc/candy/rulesets
GEO_SHARE_RULESETS_DIR=$runtime_dir/usr/share/candy/rulesets
GEO_RUNTIME_RULESETS_DIR=$RUNTIME_DIR/rulesets
DNS_ETC_RULESETS_DIR=$runtime_dir/etc/candy/rulesets
DNS_SHARE_RULESETS_DIR=$runtime_dir/usr/share/candy/rulesets
DNS_RUNTIME_RULESETS_DIR=$RUNTIME_DIR/rulesets
mkdir -p "$runtime_dir/dnsmasq.test.d" "$FW4_INCLUDE_DIR"
mkdir -p "$GEO_SHARE_RULESETS_DIR"
printf '%s\n' '1.0.1.0/24' > "$GEO_SHARE_RULESETS_DIR/cn-ip.cidr"
printf '%s\n' 'google.com' > "$DNS_SHARE_RULESETS_DIR/gfwlist.domains"
printf '%s\n' "conf-dir=$runtime_dir/dnsmasq.test.d" > "$runtime_dir/dnsmasq.conf.test"
generate_config
! grep -q '"runtime_mode"' "$RUNTIME_CONFIG"
[ "$(runtime_mode_value)" = performance ]
grep -Fq '"udp_redundancy":{"client_multiplier":3,"server_multiplier":3}' "$RUNTIME_CONFIG"
grep -Fq '"transparent_udp":[{"local":"0.0.0.0:12346"}]' "$RUNTIME_CONFIG"
apply_firewall
grep -q 'chain candy_tproxy' "$FW4_INCLUDE"
! grep -q 'set candy_cn_v4' "$FW4_INCLUDE"
! grep -q 'ip daddr @candy_cn_v4 counter return' "$FW4_INCLUDE"
grep -q 'udp dport 443 counter tproxy to :12346 meta mark set 100 accept' "$FW4_INCLUDE"
! grep -q 'udp dport 443 reject' "$FW4_INCLUDE"
! grep -q 'udp dport 53 redirect to 53' "$FW4_INCLUDE"
! grep -q 'tcp dport 53 redirect to 53' "$FW4_INCLUDE"

(
  applied_state_dir=$(mktemp -d)
  runtime_dir=$applied_state_dir
  RUNTIME_DIR=$runtime_dir/run/candy
  CANDY_FIREWALL_STATE_FILE=$RUNTIME_DIR/firewall.state
  FW4_INCLUDE_DIR=$runtime_dir/nftables.d
  FW4_INCLUDE=$FW4_INCLUDE_DIR/90-candy.nft
  LOG_FILE=$runtime_dir/candy.log
  mkdir -p "$RUNTIME_DIR" "$FW4_INCLUDE_DIR"
  : > "$runtime_dir/fw.log"
  : > "$LOG_FILE"

  ip() {
    printf '%s\n' "ip $*" >> "$runtime_dir/fw.log"
    if [ "$1" = rule ] && [ "$2" = show ]; then
      if [ ! -f "$runtime_dir/ip-rule-del-count-100" ]; then
        printf '%s\n' '100: from all fwmark 0x64 lookup 100'
      fi
      return 0
    fi
    if [ "$1" = route ] && [ "$2" = show ]; then
      return 0
    fi
    case "$1 $2 $3 $5" in
      "rule del fwmark table")
        count_file="$runtime_dir/ip-rule-del-count-$4"
        count=0
        [ -f "$count_file" ] && count=$(cat "$count_file")
        count=$((count + 1))
        printf '%s\n' "$count" > "$count_file"
        [ "$count" -eq 1 ] && return 0
        return 1
        ;;
    esac
    return 0
  }
  iptables() { printf '%s\n' "iptables $*" >> "$runtime_dir/fw.log"; }
  fw4() { printf '%s\n' "fw4 $*" >> "$runtime_dir/fw.log"; }
  nft() { printf '%s\n' "nft $*" >> "$runtime_dir/fw.log"; }

  config_load() { return 0; }
  config_foreach() { return 0; }
  config_get_bool() {
    case "$2:$3" in
      client:auto_firewall) eval "$1=1" ;;
      client:dns_capture_lan) eval "$1=1" ;;
      *) eval "$1=\${4:-0}" ;;
    esac
  }
  config_get() {
    case "$2:$3" in
      client:runtime_mode) eval "$1=performance" ;;
      client:transparent_tcp_port) eval "$1=12345" ;;
      client:transparent_udp_port) eval "$1=22346" ;;
      client:tproxy_mark) eval "$1=200" ;;
      *) eval "$1=\${4:-}" ;;
    esac
  }

  persist_applied_firewall_state iptables 12346 100
  command() {
    [ "$1" = -v ] && { [ "$2" = iptables ] || [ "$2" = ip ]; }
  }
  cleanup_firewall
  grep -Fq 'iptables -t mangle -D PREROUTING -i br-lan -p udp --dport 443 -j TPROXY --on-port 12346 --tproxy-mark 100/100' "$runtime_dir/fw.log"
  ! grep -Fq -- '--on-port 22346 --tproxy-mark 200/200' "$runtime_dir/fw.log"
  grep -Fq 'ip rule del fwmark 100 table 100' "$runtime_dir/fw.log"
  ! grep -Fq 'ip rule del fwmark 200 table 200' "$runtime_dir/fw.log"

  : > "$runtime_dir/fw.log"
  persist_applied_firewall_state fw4 12346 100
  command() {
    if [ "$1" = -v ] && [ "$2" = iptables ]; then return 1; fi
    [ "$1" = -v ] && { [ "$2" = fw4 ] || [ "$2" = nft ] || [ "$2" = ip ]; }
  }
  apply_firewall
  grep -Fq 'ip rule add fwmark 200 table 200' "$runtime_dir/fw.log"
  test "$(grep -Fc 'fw4 reload' "$runtime_dir/fw.log")" -eq 1
  grep -Fx 'backend=fw4' "$CANDY_FIREWALL_STATE_FILE" >/dev/null
  grep -Fx 'transparent_udp_port=22346' "$CANDY_FIREWALL_STATE_FILE" >/dev/null
  grep -Fx 'tproxy_mark=200' "$CANDY_FIREWALL_STATE_FILE" >/dev/null
  firewall_restart_can_skip_cleanup
)

(
  ownership_dir=$(mktemp -d)
  RUNTIME_DIR=$ownership_dir/run/candy
  CANDY_FIREWALL_STATE_FILE=$RUNTIME_DIR/firewall.state
  FW4_INCLUDE_DIR=$ownership_dir/nftables.d
  FW4_INCLUDE=$FW4_INCLUDE_DIR/90-candy.nft
  LOG_FILE=$ownership_dir/candy.log
  mkdir -p "$RUNTIME_DIR" "$FW4_INCLUDE_DIR"
  : > "$ownership_dir/fw.log"
  ip() { printf '%s\n' "ip $*" >> "$ownership_dir/fw.log"; return 0; }
  iptables() { printf '%s\n' "iptables $*" >> "$ownership_dir/fw.log"; return 1; }
  command() {
    [ "$1" = -v ] && { [ "$2" = iptables ] || [ "$2" = ip ]; }
  }
  config_load() { return 0; }
  config_get() { eval "$1=\${4:-}"; }
  config_get_bool() { eval "$1=\${4:-0}"; }
  config_foreach() { return 0; }
  cleanup_firewall || true
  ! grep -F 'ip rule del fwmark' "$ownership_dir/fw.log" >/dev/null || fail "cleanup deleted an unowned policy rule"
)

(
  crash_dir=$(mktemp -d)
  RUNTIME_DIR=$crash_dir/run/candy
  CANDY_READY_FILE=$RUNTIME_DIR/client.ready
  CANDY_PASSIVE_STATUS_FILE=$RUNTIME_DIR/passive-status.json
  CANDY_CLIENT_BIN=$crash_dir/candy-client
  LOG_FILE=$crash_dir/candy.log
  mkdir -p "$RUNTIME_DIR"
  printf '%s\n' '#!/bin/sh' 'exit 42' > "$CANDY_CLIENT_BIN"
  chmod 0755 "$CANDY_CLIENT_BIN"
  config_load() { return 0; }
  config_get() {
    case "$2:$3" in
      client:congestion) eval "$1=\${4:-candy-bbr}" ;;
      client:candy_bbr_preset) eval "$1=\${4:-current}" ;;
      *) eval "$1=\${4:-}" ;;
    esac
  }
  config_get_bool() { config_get "$@"; }
  run_detached_direct_command() { printf '%s %s\n' "$1" "${2:-}" > "$crash_dir/fail-open"; }
  if run_client; then
    fail "abnormal Candy client exit was reported as success"
  fi
  grep -F 'fail_open core_exit:42' "$crash_dir/fail-open" >/dev/null || fail "abnormal Candy client exit did not schedule fail-open"
)

(
  promotion_dir=$(mktemp -d)
  RUNTIME_DIR=$promotion_dir/run/candy
  RUNTIME_CONFIG=$RUNTIME_DIR/runtime.json
  RUNTIME_NEXT_CONFIG=$RUNTIME_DIR/runtime.next.json
  LOG_FILE=$promotion_dir/candy.log
  mkdir -p "$RUNTIME_DIR"
  : > "$LOG_FILE"

  printf '%s\n' '{"generation":2}' > "$RUNTIME_NEXT_CONFIG"
  promoted_sha=$(sha256sum "$RUNTIME_NEXT_CONFIG" | awk '{print $1}')
  mv -f "$RUNTIME_NEXT_CONFIG" "$RUNTIME_CONFIG"
  chmod 0644 "$RUNTIME_CONFIG"
  verify_promoted_runtime_candidate "$promoted_sha"
  test "$(stat -c %a "$RUNTIME_CONFIG" 2>/dev/null || stat -f %Lp "$RUNTIME_CONFIG")" = 600

  printf '%s\n' '{"not":"consumed"}' > "$RUNTIME_NEXT_CONFIG"
  if verify_promoted_runtime_candidate "$promoted_sha"; then
    fail "reload promotion verification accepted an unconsumed candidate"
  fi
  rm -f "$RUNTIME_NEXT_CONFIG"
  if verify_promoted_runtime_candidate 0000000000000000000000000000000000000000000000000000000000000000; then
    fail "reload promotion verification accepted an active SHA mismatch"
  fi
)

preflight_dir=$(mktemp -d)
runtime_dir=$preflight_dir
RUNTIME_DIR=$runtime_dir/run/candy
RUNTIME_CONFIG=$RUNTIME_DIR/runtime.json
LOG_FILE=$runtime_dir/candy.log
NODE_STATUS_FILE=$runtime_dir/candy.nodes
FW4_INCLUDE_DIR=$runtime_dir/nftables.d
FW4_INCLUDE=$FW4_INCLUDE_DIR/90-candy.nft
DNSMASQ_CONF_GLOB=$runtime_dir/dnsmasq.conf.*
CANDY_CLIENT_BIN=$runtime_dir/candy-client-fail
mkdir -p "$runtime_dir/dnsmasq.test.d" "$FW4_INCLUDE_DIR"
printf '%s\n' "conf-dir=$runtime_dir/dnsmasq.test.d" > "$runtime_dir/dnsmasq.conf.test"
cat > "$CANDY_CLIENT_BIN" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$CANDY_CLIENT_CALLS"
exit 23
EOF
chmod +x "$CANDY_CLIENT_BIN"
export CANDY_CLIENT_CALLS=$runtime_dir/candy-client.calls
start_service || true
grep -Fq -- "--check-config" "$CANDY_CLIENT_CALLS"
grep -q 'runtime config preflight failed' "$LOG_FILE"
for _ in 1 2 3 4 5; do
  grep -q 'network policy cleaned' "$LOG_FILE" && break
  sleep 1
done
grep -q 'cleaned firewall rules' "$LOG_FILE"
grep -q 'network policy cleaned' "$LOG_FILE"
test ! -f "$FW4_INCLUDE"
test ! -f "$runtime_dir/dnsmasq.test.d/candy.conf"
grep -q '"state":"down"' "$NODE_STATUS_FILE"
! grep -q 'applied fw4 nftables firewall rules' "$LOG_FILE"
! grep -q 'applied dnsmasq DNS policy' "$LOG_FILE"
test ! -f "$runtime_dir/procd.log"

lifecycle_dir=$(mktemp -d)
runtime_dir=$lifecycle_dir
RUNTIME_DIR=$runtime_dir/run/candy
RUNTIME_CONFIG=$RUNTIME_DIR/runtime.json
LOG_FILE=$runtime_dir/candy.log
TRAFFIC_LOG_FILE=$runtime_dir/candy-traffic.log
NODE_STATUS_FILE=$runtime_dir/candy.nodes
NETWORK_APPLY_LOCK_DIR=$runtime_dir/candy-network-apply.lock
STATUS_PROBE_LOCK_DIR=$runtime_dir/candy-status-probe.lock
FW4_INCLUDE_DIR=$runtime_dir/nftables.d
FW4_INCLUDE=$FW4_INCLUDE_DIR/90-candy.nft
DNSMASQ_CONF_GLOB=$runtime_dir/dnsmasq.conf.*
GEO_ETC_RULESETS_DIR=$runtime_dir/etc/candy/rulesets
GEO_SHARE_RULESETS_DIR=$runtime_dir/usr/share/candy/rulesets
GEO_RUNTIME_RULESETS_DIR=$RUNTIME_DIR/rulesets
DNS_ETC_RULESETS_DIR=$runtime_dir/etc/candy/rulesets
DNS_SHARE_RULESETS_DIR=$runtime_dir/usr/share/candy/rulesets
DNS_RUNTIME_RULESETS_DIR=$RUNTIME_DIR/rulesets
CANDY_CLIENT_BIN=$runtime_dir/candy-client-ok
CANDY_SERVICE_WAIT_SECONDS=0
CANDY_LISTENER_WAIT_SECONDS=2
CANDY_READY_FILE=$runtime_dir/candy.ready
CANDY_LIFECYCLE_FILE=$runtime_dir/candy.lifecycle
mkdir -p "$runtime_dir/dnsmasq.test.d" "$FW4_INCLUDE_DIR" "$GEO_SHARE_RULESETS_DIR" "$DNS_SHARE_RULESETS_DIR"
printf '%s\n' "conf-dir=$runtime_dir/dnsmasq.test.d" > "$runtime_dir/dnsmasq.conf.test"
printf '%s\n' '1.0.1.0/24' > "$GEO_SHARE_RULESETS_DIR/cn-ip.cidr"
printf '%s\n' 'google.com' > "$DNS_SHARE_RULESETS_DIR/gfwlist.domains"
cat > "$CANDY_CLIENT_BIN" <<'EOF'
#!/bin/sh
if [ "${CANDY_STALE_CLIENT:-0}" = 1 ]; then
  sleep 30
  exit 0
fi
case "$*" in
  *--check-config*) exit 0 ;;
esac
exit 0
EOF
chmod +x "$CANDY_CLIENT_BIN"
procd_close_instance() {
  printf '%s\n' procd_close_instance >> "$runtime_dir/procd.log"
}
network_apply() {
  printf '%s\n' network-apply >> "$runtime_dir/lifecycle.events"
  return 0
}
CANDY_STALE_CLIENT=1 "$CANDY_CLIENT_BIN" geo update cn-ip &
provider_client_pid=$!
sleep 1
if candy_process_running || [ -n "$(candy_client_pids)" ]; then
  kill "$provider_client_pid" 2>/dev/null || true
  wait "$provider_client_pid" 2>/dev/null || true
  fail "provider updater was mistaken for the Candy service"
fi
kill "$provider_client_pid" 2>/dev/null || true
wait "$provider_client_pid" 2>/dev/null || true
CANDY_STALE_CLIENT=1 "$CANDY_CLIENT_BIN" --config "$RUNTIME_CONFIG" --format candy-json &
stale_client_pid=$!
start_service
test ! -e "$runtime_dir/lifecycle.events" || fail "network policy applied before procd submission"
printf '{"pid":%s,"listeners":["127.0.0.1:12345"]}\n' "$$" > "$CANDY_READY_FILE"
service_started
if kill -0 "$stale_client_pid" 2>/dev/null; then
  kill "$stale_client_pid" 2>/dev/null || true
  wait "$stale_client_pid" 2>/dev/null || true
  false
fi
grep -q 'existing candy-client process still running before start:' "$LOG_FILE"
grep -q 'terminated stale candy-client process before start:' "$LOG_FILE"
wait "$stale_client_pid" 2>/dev/null || true
grep -Fq 'procd_set_param command '"$CANDY_INIT_SELF"' run_client' "$runtime_dir/procd.log"

reserved_forward_dir=$(mktemp -d)
runtime_dir=$reserved_forward_dir
RUNTIME_DIR=$runtime_dir/run/candy
RUNTIME_CONFIG=$RUNTIME_DIR/runtime.json
LOG_FILE=$runtime_dir/candy.log
NODE_STATUS_FILE=$runtime_dir/candy.nodes
GEO_ETC_RULESETS_DIR=$runtime_dir/etc/candy/rulesets
GEO_SHARE_RULESETS_DIR=$runtime_dir/usr/share/candy/rulesets
GEO_RUNTIME_RULESETS_DIR=$RUNTIME_DIR/rulesets
DNS_ETC_RULESETS_DIR=$runtime_dir/etc/candy/rulesets
DNS_SHARE_RULESETS_DIR=$runtime_dir/usr/share/candy/rulesets
DNS_RUNTIME_RULESETS_DIR=$RUNTIME_DIR/rulesets
CANDY_CLIENT_BIN=$runtime_dir/candy-client-ok
mkdir -p "$GEO_SHARE_RULESETS_DIR" "$DNS_SHARE_RULESETS_DIR"
printf '%s\n' '1.0.1.0/24' > "$GEO_SHARE_RULESETS_DIR/cn-ip.cidr"
printf '%s\n' 'google.com' > "$DNS_SHARE_RULESETS_DIR/gfwlist.domains"
cat > "$CANDY_CLIENT_BIN" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$CANDY_CLIENT_BIN"
config_get() {
  var=$1
  section=$2
  option=$3
  default=${4:-}
  value=$default
  case "$section:$option" in
    client:enabled) value='1' ;;
    client:mode) value='rule' ;;
    client:runtime_mode) value='fallback' ;;
    client:selected_group) value='Proxy' ;;
    client:selected_node) value='hk-1' ;;
    client:bypass_china_ip) value='1' ;;
    hk-1:enabled) value='1' ;;
    hk-1:name) value='Hong Kong 1' ;;
    hk-1:server) value='104.243.28.153:18443' ;;
    hk-1:server_name) value='node.example.test' ;;
    hk-1:server_pin) value='sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789' ;;
    hk-1:auth) value='node-secret-long-value' ;;
    backup:enabled) value='0' ;;
    Proxy:type) value='select' ;;
    good_forward:network) value='tcp' ;;
    good_forward:local) value='127.0.0.1:18080' ;;
    good_forward:target) value='127.0.0.1:8080' ;;
    dns_remote_forward:network) value='udp' ;;
    dns_remote_forward:local) value='127.0.0.1:15353' ;;
    dns_remote_forward:target) value='8.8.8.8:53' ;;
    rule_match:value) value='MATCH,Proxy' ;;
  esac
  eval "$var=\$value"
}
config_foreach() {
  callback=$1
  type=$2
  case "$type" in
    node) "$callback" hk-1 ;;
    group) "$callback" Proxy ;;
    rule) "$callback" rule_match ;;
    forward)
      "$callback" dns_remote_forward
      "$callback" good_forward
      ;;
    *) return 1 ;;
  esac
}
generate_config
grep -Fq '"network":"udp","local":"127.0.0.1:15353","target":"8.8.8.8:53"' "$RUNTIME_CONFIG"
grep -Fq '"network":"tcp","local":"127.0.0.1:18080","target":"127.0.0.1:8080"' "$RUNTIME_CONFIG"
grep -q 'forward local listen conflicts with reserved Candy DNS listener: dns_remote_forward udp 127.0.0.1:15353' "$LOG_FILE"

migration_dir=$(mktemp -d)
runtime_dir=$migration_dir
RUNTIME_DIR=$runtime_dir/run/candy
RUNTIME_CONFIG=$RUNTIME_DIR/runtime.json
LOG_FILE=$runtime_dir/candy.log
NODE_STATUS_FILE=$runtime_dir/candy.nodes
CONFIG_FILE=$runtime_dir/etc/config/candy
LEGACY_CONFIG_FILE=$runtime_dir/etc/config/carrier
mkdir -p "$runtime_dir/etc/config"
cat > "$LEGACY_CONFIG_FILE" <<'EOF'
config carrier 'client'
	option enabled '1'
	option server 'legacy.example.test:8443'
	option server_name 'legacy.example.test'
	option server_pin 'sha256:legacy-pin'
	option secret 'legacy-secret'
	option selected_node 'legacy'
	option auto_firewall '1'
	option redirect_tcp '1'
	option redirect_udp '1'
	option block_quic '0'
	option transparent_tcp_port '23456'
	option transparent_udp_port '23457'
	option tproxy_mark '200'

config node 'legacy'
	option enabled '1'
	option label 'Legacy Node'
	option server '198.51.100.10:18443'
	option server_name 'legacy-node.example.test'
	option server_pin 'sha256:legacy-node-pin'
	option secret 'legacy-node-secret'

config forward
	option network 'tcp'
	option local '127.0.0.1:18080'
	option target '127.0.0.1:8080'
EOF
migrate_legacy_config
test -f "$CONFIG_FILE"
test -f "$LEGACY_CONFIG_FILE"
grep -q "config candy 'client'" "$CONFIG_FILE"
! grep -q "option selected_node" "$CONFIG_FILE"
grep -q "option type 'fallback'" "$CONFIG_FILE"
grep -q "option runtime_mode 'fallback'" "$CONFIG_FILE"
grep -q "option udp_client_multiplier '1'" "$CONFIG_FILE"
grep -q "option udp_server_multiplier '1'" "$CONFIG_FILE"
grep -q "option gfwlist_auto_update '1'" "$CONFIG_FILE"
grep -q "option geo_update_url 'https://gaoyifan.github.io/china-operator-ip/china46.txt'" "$CONFIG_FILE"
grep -q "option geo_auto_update '1'" "$CONFIG_FILE"
grep -q "config node 'legacy'" "$CONFIG_FILE"
grep -q "option auth 'legacy-node-secret'" "$CONFIG_FILE"
grep -q "option redirect_tcp '1'" "$CONFIG_FILE"
grep -q "option block_quic '0'" "$CONFIG_FILE"
grep -q "option transparent_tcp_port '23456'" "$CONFIG_FILE"
grep -q "option transparent_udp_port '23457'" "$CONFIG_FILE"
grep -q "option tproxy_mark '200'" "$CONFIG_FILE"
grep -q "migrated legacy carrier config to candy" "$LOG_FILE"
! grep -q "legacy-secret" "$LOG_FILE"
! grep -q "legacy-node-secret" "$LOG_FILE"

(
  migration_fixture=$(mktemp -d)
  CONFIG_FILE=$migration_fixture/candy
  LOG_FILE=$migration_fixture/candy.log
  UCI_MIGRATION_LOG=$migration_fixture/uci.log
  touch "$CONFIG_FILE"
  config_load() { [ "$1" = candy ]; }
  config_get() {
    local output=$1 section_id=$2 option_id=$3 fallback=${4:-} result
    result=$fallback
    case "$section_id:$option_id" in
      node_a:name) result='Hong Kong 1' ;;
      Proxy:name) result='Proxy' ;;
      rule_direct:value) result='DOMAIN-SUFFIX,example.com,Hong Kong 1' ;;
    esac
    eval "$output=\$result"
  }
  config_foreach() {
    local callback=$1 type=$2
    case "$type" in
      node) "$callback" node_a ;;
      group) "$callback" Proxy ;;
      rule) "$callback" rule_direct ;;
    esac
  }
  command() { [ "$1" = -v ] && [ "$2" = uci ]; }
  uci() {
    case "$*" in
      '-q get candy.node_route_node_a') return 1 ;;
    esac
    printf '%s\n' "$*" >> "$UCI_MIGRATION_LOG"
  }
  migrate_candy_node_rule_targets
  grep -Fq -- '-q set candy.node_route_node_a=group' "$UCI_MIGRATION_LOG"
  grep -Fq -- '-q set candy.node_route_node_a.name=node-node_a' "$UCI_MIGRATION_LOG"
  grep -Fq -- '-q set candy.node_route_node_a.type=fallback' "$UCI_MIGRATION_LOG"
  grep -Fq -- '-q add_list candy.node_route_node_a.node=node_a' "$UCI_MIGRATION_LOG"
  grep -Fq -- '-q set candy.rule_direct.value=DOMAIN-SUFFIX,example.com,node-node_a' "$UCI_MIGRATION_LOG"
  grep -Fq -- '-q commit candy' "$UCI_MIGRATION_LOG"
)

provider_security_dir=$(mktemp -d)
CANDY_CLIENT_BIN=$provider_security_dir/candy-client
GEO_ETC_RULESETS_DIR=$provider_security_dir/rulesets
PROVIDER_ARGV_LOG=$provider_security_dir/argv
export PROVIDER_ARGV_LOG
cat > "$CANDY_CLIENT_BIN" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" >> "$PROVIDER_ARGV_LOG"
exit 0
EOF
chmod +x "$CANDY_CLIENT_BIN"
if run_geo_provider_update 'http://example.test/provider'; then
  fail "production provider update accepted http"
fi
if run_geo_provider_update 'file:///tmp/provider'; then
  fail "production provider update accepted local file URL"
fi
if run_geo_provider_update 'https://example.test/line1
line2'; then
  fail "production provider update accepted newline URL"
fi
test ! -e "$PROVIDER_ARGV_LOG" || fail "rejected provider URL reached candy-client"
provider_url='https://example.test/a$(touch${IFS}/tmp/candy-provider-injected);`id`-'"'"'"'
run_geo_provider_update "$provider_url"
grep -Fx "$provider_url" "$PROVIDER_ARGV_LOG" >/dev/null || fail "https provider argument changed"
test ! -e /tmp/candy-provider-injected || fail "provider URL command expansion executed"
CANDY_ALLOW_LOCAL_PROVIDER_URLS=1 run_geo_provider_update 'file:///tmp/provider'
grep -Fx 'file:///tmp/provider' "$PROVIDER_ARGV_LOG" >/dev/null || fail "explicit local test provider was not passed"

(
  failure_dir=$(mktemp -d)
  LOG_FILE=$failure_dir/candy.log
  FW4_INCLUDE=$failure_dir/90-candy.nft
  CANDY_FIREWALL_STATE_FILE=$failure_dir/firewall.state
  touch "$LOG_FILE" "$FW4_INCLUDE"
  pidof() {
    [ "$1" = dnsmasq ] && printf '%s\n' 4242
  }
  kill() {
    return 1
  }
  if reload_dnsmasq; then
    fail "dnsmasq signal failure was reported as success"
  fi

  config_load() {
    return 1
  }
  if apply_dns; then
    fail "DNS apply continued after config_load failure"
  fi

  config_load() {
    return 0
  }
  config_get() {
    eval "$1=\${4:-}"
  }
  cleanup_tproxy_policy() {
    return 0
  }
  command() {
    [ "$1" = -v ] && { [ "$2" = fw4 ] || [ "$2" = nft ]; }
  }
  run_with_timeout() {
    return 1
  }
  nft() {
    return 1
  }
  if cleanup_firewall; then
    fail "fw4 cleanup reload failure was reported as success"
  fi

  run_with_timeout() {
    return 0
  }
  nft() {
    [ "$1" = list ] && return 0
    return 1
  }
  if cleanup_firewall; then
    fail "nft chain deletion failure was reported as success"
  fi
)

lock_race_dir=$(mktemp -d)
NETWORK_APPLY_LOCK_DIR=$lock_race_dir/network.lock
LOG_FILE=$lock_race_dir/candy.log
touch "$LOG_FILE"
mkdir -p "$NETWORK_APPLY_LOCK_DIR"
(
  sleep 1
  rm -rf "$NETWORK_APPLY_LOCK_DIR"
) &
lock_holder_pid=$!
printf '%s\n' "$lock_holder_pid" > "$NETWORK_APPLY_LOCK_DIR/pid"
printf '%s\n' apply > "$NETWORK_APPLY_LOCK_DIR/action"
cleanup_network_policy_now() {
  printf '%s\n' cleanup-ran >> "$lock_race_dir/events"
}
network_cleanup
wait "$lock_holder_pid"
grep -q '^cleanup-ran$' "$lock_race_dir/events" || fail "cleanup skipped while apply lock was held"
! grep -q 'network policy cleanup skipped' "$LOG_FILE" || fail "cleanup reported success after being skipped"

apply_lock_dir=$(mktemp -d)
NETWORK_APPLY_LOCK_DIR=$apply_lock_dir/network.lock
LOG_FILE=$apply_lock_dir/candy.log
touch "$LOG_FILE"
mkdir -p "$NETWORK_APPLY_LOCK_DIR"
(
  sleep 1
  rm -rf "$NETWORK_APPLY_LOCK_DIR"
) &
apply_lock_holder_pid=$!
printf '%s\n' "$apply_lock_holder_pid" > "$NETWORK_APPLY_LOCK_DIR/pid"
printf '%s\n' apply > "$NETWORK_APPLY_LOCK_DIR/action"
apply_after_wait() {
  printf '%s\n' apply-ran >> "$apply_lock_dir/events"
}
CANDY_NETWORK_LOCK_WAIT_SECONDS=3 with_network_apply_lock apply apply_after_wait
wait "$apply_lock_holder_pid"
grep -q '^apply-ran$' "$apply_lock_dir/events" || fail "apply lock owner returned success without executing the requested apply"

mkdir -p "$NETWORK_APPLY_LOCK_DIR"
printf '%s\n' "$$" > "$NETWORK_APPLY_LOCK_DIR/pid"
printf '%s\n' apply > "$NETWORK_APPLY_LOCK_DIR/action"
if CANDY_NETWORK_LOCK_WAIT_SECONDS=0 with_network_apply_lock apply apply_after_wait; then
  fail "apply lock timeout reported success"
fi
rm -rf "$NETWORK_APPLY_LOCK_DIR"

service_identity_dir=$(mktemp -d)
CANDY_PROC_ROOT=$service_identity_dir/proc
CANDY_SERVICE_LOCK_DIR=$service_identity_dir/service.lock
CANDY_SERVICE_LOCK_WAIT_SECONDS=0
mkdir -p "$CANDY_PROC_ROOT/$$" "$CANDY_PROC_ROOT/sys/kernel/random" "$CANDY_SERVICE_LOCK_DIR"
printf '%s\n' test-boot-id > "$CANDY_PROC_ROOT/sys/kernel/random/boot_id"
printf '%s\n' "$$ (candy-test) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345" > "$CANDY_PROC_ROOT/$$/stat"
printf '%s\n' "$$" > "$CANDY_SERVICE_LOCK_DIR/pid"
printf '%s\n' 99999 > "$CANDY_SERVICE_LOCK_DIR/starttime"
printf '%s\n' test-boot-id > "$CANDY_SERVICE_LOCK_DIR/boot_id"
service_lock_action() {
  printf '%s\n' acquired > "$service_identity_dir/result"
}
with_service_lifecycle_lock service_lock_action
grep -q '^acquired$' "$service_identity_dir/result" || fail "PID-reused service lifecycle lock was not recovered"
test ! -e "$CANDY_SERVICE_LOCK_DIR" || fail "service lifecycle lock survived successful action"

identity_failure_dir=$(mktemp -d)
CANDY_PROC_ROOT=$identity_failure_dir/proc
CANDY_SERVICE_LOCK_DIR=$identity_failure_dir/service.lock
mkdir -p "$CANDY_PROC_ROOT/$$"
printf '%s\n' "$$ (candy-test) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345" > "$CANDY_PROC_ROOT/$$/stat"
if with_service_lifecycle_lock service_lock_action; then
  fail "service lifecycle lock succeeded without a boot identity"
fi
test ! -e "$CANDY_SERVICE_LOCK_DIR" || fail "failed identity acquisition left a stale service lock"
CANDY_PROC_ROOT=$TEST_CANDY_PROC_ROOT

network_identity_failure_dir=$(mktemp -d)
CANDY_PROC_ROOT=$network_identity_failure_dir/proc
NETWORK_APPLY_LOCK_DIR=$network_identity_failure_dir/network.lock
mkdir -p "$CANDY_PROC_ROOT/$$"
printf '%s\n' "$$ (candy-test) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345" > "$CANDY_PROC_ROOT/$$/stat"
if CANDY_NETWORK_LOCK_WAIT_SECONDS=0 with_network_apply_lock apply apply_after_wait; then
  fail "network policy lock succeeded without a boot identity"
fi
test ! -e "$NETWORK_APPLY_LOCK_DIR" || fail "failed network identity acquisition left a stale lock"
CANDY_PROC_ROOT=$TEST_CANDY_PROC_ROOT

(
  reused_pid_dir=$(mktemp -d)
  CANDY_PROC_ROOT=$reused_pid_dir/proc
  NETWORK_APPLY_LOCK_DIR=$reused_pid_dir/network.lock
  LOG_FILE=$reused_pid_dir/candy.log
  mkdir -p "$CANDY_PROC_ROOT/4242" "$CANDY_PROC_ROOT/sys/kernel/random" "$NETWORK_APPLY_LOCK_DIR"
  printf '%s\n' test-boot-id > "$CANDY_PROC_ROOT/sys/kernel/random/boot_id"
  printf '%s\n' '4242 (unrelated) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345' > "$CANDY_PROC_ROOT/4242/stat"
  printf '%s\n' 4242 > "$NETWORK_APPLY_LOCK_DIR/pid"
  printf '%s\n' 99999 > "$NETWORK_APPLY_LOCK_DIR/starttime"
  printf '%s\n' test-boot-id > "$NETWORK_APPLY_LOCK_DIR/boot_id"
  kill() {
    printf '%s\n' "$*" >> "$reused_pid_dir/signals"
    return 0
  }
  if stop_network_policy_worker_for_fail_open; then
    fail "fail-open trusted a PID-reused network policy lock"
  fi
  ! grep -Eq -- '-TERM|-KILL' "$reused_pid_dir/signals" || fail "fail-open signaled an unrelated PID-reuse process"
)

grep -F 'chmod 0711 "$lock_parent"' "$repo_root/candy-client/candy.init" >/dev/null ||
  fail "network lock acquisition can revoke SD-WAN traversal of /var/lib/candy"

rollback_dir=$(mktemp -d)
LOG_FILE=$rollback_dir/candy.log
apply_firewall() {
  : > "$rollback_dir/firewall"
}
apply_dns() {
  : > "$rollback_dir/dns-partial"
  return 1
}
cleanup_firewall() {
  rm -f "$rollback_dir/firewall"
  printf '%s\n' firewall-cleaned >> "$rollback_dir/events"
}
cleanup_dns() {
  rm -f "$rollback_dir/dns-partial"
  printf '%s\n' dns-cleaned >> "$rollback_dir/events"
}
refresh_node_status_fast() { :; }
if apply_network_policy_now; then
  fail "partial network apply unexpectedly succeeded"
fi
test ! -e "$rollback_dir/firewall" || fail "firewall artifact survived rollback"
test ! -e "$rollback_dir/dns-partial" || fail "dns artifact survived rollback"
grep -q '^firewall-cleaned$' "$rollback_dir/events"
grep -q '^dns-cleaned$' "$rollback_dir/events"

(
  stale_runtime_dir=$(mktemp -d)
  RUNTIME_DIR=$stale_runtime_dir/run/candy
  RUNTIME_CONFIG=$RUNTIME_DIR/runtime.json
  LOG_FILE=$stale_runtime_dir/candy.log
  TRAFFIC_LOG_FILE=$stale_runtime_dir/candy-traffic.log
  CANDY_READY_FILE=$stale_runtime_dir/candy.ready
  CANDY_LIFECYCLE_FILE=$stale_runtime_dir/candy.lifecycle
  mkdir -p "$RUNTIME_DIR"
  printf '%s\n' '{"stale":true}' > "$RUNTIME_CONFIG"
  : > "$LOG_FILE"

  migrate_legacy_config() { :; }
  migrate_reserved_dns_forward() { :; }
  config_load() { :; }
  config_get_bool() { eval "$1=1"; }
  generate_config() { return 1; }
  validate_runtime_config() { return 0; }
  ensure_no_existing_candy_client_before_start() { return 0; }
  procd_open_instance() { : > "$stale_runtime_dir/procd-opened"; }
  procd_set_param() { :; }
  procd_close_instance() { :; }
  start_provider_updater() { :; }
  wait_for_current_readiness() { return 0; }
  network_apply() { : > "$stale_runtime_dir/network-applied"; }
  network_cleanup() { :; }
  refresh_node_status_fast() { :; }

  if start_service; then
    fail "start reused stale runtime after atomic config generation failure"
  fi
  test ! -e "$stale_runtime_dir/procd-opened" || fail "procd started after config generation failure"
  test ! -e "$stale_runtime_dir/network-applied" || fail "network policy applied after config generation failure"
  test ! -e "$RUNTIME_CONFIG" || fail "stale runtime survived config generation failure"
  grep -q 'runtime config generation failed' "$LOG_FILE" || fail "config generation failure was not logged"
)

(
  failed_cleanup_dir=$(mktemp -d)
  RUNTIME_DIR=$failed_cleanup_dir/run/candy
  RUNTIME_CONFIG=$RUNTIME_DIR/runtime.json
  LOG_FILE=$failed_cleanup_dir/candy.log
  TRAFFIC_LOG_FILE=$failed_cleanup_dir/candy-traffic.log
  CANDY_READY_FILE=$failed_cleanup_dir/candy.ready
  CANDY_LIFECYCLE_FILE=$failed_cleanup_dir/candy.lifecycle
  mkdir -p "$RUNTIME_DIR"
  : > "$LOG_FILE"

  migrate_legacy_config() { :; }
  migrate_reserved_dns_forward() { :; }
  config_load() { :; }
  config_get_bool() { eval "$1=1"; }
  generate_config() { printf '%s\n' '{}' > "$RUNTIME_CONFIG"; }
  validate_runtime_config() { return 0; }
  ensure_no_existing_candy_client_before_start() { return 0; }
  procd_open_instance() { :; }
  procd_set_param() { :; }
  procd_close_instance() { :; }
  start_provider_updater() { :; }
  wait_for_current_readiness() { return 1; }
  abort_failed_start() { : > "$failed_cleanup_dir/aborted"; }
  network_cleanup() { return 1; }
  refresh_node_status_fast() { :; }

  start_service
  if service_started; then
    fail "readiness failure with incomplete cleanup reported success"
  fi
  test -e "$failed_cleanup_dir/aborted" || fail "submitted client survived readiness failure"
  grep -q '"state":"stopping"' "$CANDY_LIFECYCLE_FILE" || fail "failed cleanup was reported as stopped"
  ! grep -q '"state":"stopped"' "$CANDY_LIFECYCLE_FILE" || fail "failed cleanup overwrote stopping state"
)

for early_stage in disabled generate validate stale-process; do
  (
    early_dir=$(mktemp -d)
    RUNTIME_DIR=$early_dir/run/candy
    RUNTIME_CONFIG=$RUNTIME_DIR/runtime.json
    LOG_FILE=$early_dir/candy.log
    TRAFFIC_LOG_FILE=$early_dir/candy-traffic.log
    CANDY_READY_FILE=$early_dir/candy.ready
    CANDY_LIFECYCLE_FILE=$early_dir/candy.lifecycle
    mkdir -p "$RUNTIME_DIR"
    printf '%s\n' '{"stale":true}' > "$RUNTIME_CONFIG"
    : > "$LOG_FILE"

    migrate_legacy_config() { :; }
    migrate_reserved_dns_forward() { :; }
    config_load() { :; }
    config_get_bool() {
      if [ "$early_stage" = disabled ]; then
        eval "$1=0"
      else
        eval "$1=1"
      fi
    }
    generate_config() {
      [ "$early_stage" != generate ] || return 1
      printf '%s\n' '{}' > "$RUNTIME_CONFIG"
    }
    validate_runtime_config() { [ "$early_stage" != validate ]; }
    ensure_no_existing_candy_client_before_start() { [ "$early_stage" != stale-process ]; }
    abort_failed_start() { : > "$early_dir/aborted"; rm -f "$CANDY_READY_FILE"; }
    network_cleanup() { return 1; }
    refresh_node_status_fast() { :; }
    wait_for_current_readiness() { : > "$early_dir/waited"; return 1; }
    procd_open_instance() { : > "$early_dir/procd-opened"; }
    procd_set_param() { :; }
    procd_close_instance() { :; }

    if start_service; then
      fail "$early_stage early failure reported success when cleanup failed"
    fi
    if service_started; then
      fail "$early_stage unsubmitted service reported started"
    fi
    grep -q '"state":"stopping"' "$CANDY_LIFECYCLE_FILE" || fail "$early_stage cleanup failure did not retain stopping"
    ! grep -q '"state":"stopped"' "$CANDY_LIFECYCLE_FILE" || fail "$early_stage cleanup failure published stopped"
    test ! -e "$early_dir/procd-opened" || fail "$early_stage failure reached procd"
    test ! -e "$early_dir/aborted" || fail "$early_stage failure reset an unsubmitted procd service"
    test ! -e "$early_dir/waited" || fail "$early_stage failure entered post-submission readiness"
    if [ "$early_stage" = generate ]; then
      test ! -e "$RUNTIME_CONFIG" || fail "generate failure retained stale runtime"
    fi
  )
done

(
  strict_fw_dir=$(mktemp -d)
	. "$repo_root/candy-client/candy.init"
  RUNTIME_DIR=$strict_fw_dir/run/candy
  CANDY_FIREWALL_STATE_FILE=$RUNTIME_DIR/firewall.state
  LOG_FILE=$strict_fw_dir/candy.log
  mkdir -p "$RUNTIME_DIR"
  : > "$LOG_FILE"
  config_load() { return 0; }
  config_foreach() { return 0; }
  config_get_bool() {
    case "$2:$3" in
      client:auto_firewall|client:dns_capture_lan) eval "$1=1" ;;
      *) eval "$1=\${4:-0}" ;;
    esac
  }
  config_get() {
    case "$2:$3" in
      client:runtime_mode) eval "$1=fallback" ;;
      *) eval "$1=\${4:-}" ;;
    esac
  }
  ip() { return 1; }
  iptables() {
    case "$*" in
      '-t nat -A PREROUTING -p tcp -j CANDY') return 1 ;;
      *) return 0 ;;
    esac
  }
  command() {
    [ "$1" = -v ] && { [ "$2" = iptables ] || [ "$2" = ip ]; }
  }
  if apply_firewall; then
    fail "iptables critical command failure was swallowed"
  fi
  test ! -e "$CANDY_FIREWALL_STATE_FILE" || fail "failed iptables apply persisted success state"
)

(
  fault_dir=$(mktemp -d)
	. "$repo_root/candy-client/candy.init"
  RUNTIME_DIR=$fault_dir/run/candy
  LOG_FILE=$fault_dir/candy.log
  CANDY_LIFECYCLE_FILE=$fault_dir/candy.lifecycle
  CANDY_FAULT_STATE_FILE=$fault_dir/runtime-fault.json
  CANDY_INIT_SELF=$fault_dir/candy-init
  mkdir -p "$RUNTIME_DIR"
  printf '%s\n' '#!/bin/sh' 'exit 0' > "$CANDY_INIT_SELF"
  chmod +x "$CANDY_INIT_SELF"
  : > "$LOG_FILE"
  config_load() { return 0; }
  candy_client_pids() { return 0; }
  wait_for_candy_client_exit() { return 0; }
  network_cleanup() { return 0; }
  fail_open_locked test_failure client
  grep -Fq '"reason":"test_failure"' "$CANDY_FAULT_STATE_FILE" || fail "fail-open did not persist its reason"
  grep -Fq '"cleanup":"completed"' "$CANDY_FAULT_STATE_FILE" || fail "successful fail-open was not persisted"

  network_cleanup() { return 1; }
  if fail_open_locked cleanup_failure client; then
    fail "incomplete fail-open cleanup reported success"
  fi
  grep -Fq '"cleanup":"failed"' "$CANDY_FAULT_STATE_FILE" || fail "incomplete fail-open cleanup was hidden"
  grep -Fq 'event=fail_open' "$LOG_FILE" || fail "fail-open lifecycle context was not logged"
)

(
  start_guard_dir=$runtime_dir/start-guard
  mkdir -p "$start_guard_dir"
  CANDY_INIT_SELF=$start_guard_dir/candy-init
  LOG_FILE=$start_guard_dir/candy.log
  printf '%s\n' \
    '#!/bin/sh' \
    'printf '\''%s\n'\'' "phase=${CANDY_PROCD_START:-0} args=$*" > "${CANDY_START_GUARD_MARKER:?}"' \
    > "$CANDY_INIT_SELF"
  chmod +x "$CANDY_INIT_SELF"
  CANDY_START_GUARD_MARKER=$start_guard_dir/second-phase
  export CANDY_START_GUARD_MARKER
  : > "$LOG_FILE"

  candy_process_running() { return 0; }
  current_readiness() { return 0; }
  start
  test ! -e "$CANDY_START_GUARD_MARKER" || fail "healthy repeated start entered a procd transaction"
  grep -Fq 'start skipped: Candy service is already healthy' "$LOG_FILE" ||
    fail "healthy repeated start was not recorded"

  candy_process_running() { return 1; }
  start regression-check
)
grep -Fq 'phase=1 args=start regression-check' "$runtime_dir/start-guard/second-phase" ||
  fail "unhealthy start did not enter the guarded procd phase"

printf '%s\n' "OpenWrt Candy init config generation test passed"
