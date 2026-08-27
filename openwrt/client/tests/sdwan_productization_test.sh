#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../packages" && pwd)
makefile="$root/candy-client/Makefile"
config="$root/candy-client/candy.config"
init="$root/candy-client/candy.init"
controller="$root/luci-app-candy/root/usr/lib/lua/luci/controller/candy.lua"
status="$root/luci-app-candy/root/usr/lib/lua/luci/view/candy/status.htm"
sdwan="$root/luci-app-candy/root/usr/lib/lua/luci/view/candy/sdwan.htm"
po="$root/luci-app-candy/po/zh-cn/candy.zh-cn.po"
cloud_sync_init="$root/candy-client/candy-cloud-sync.init"
cloud_sync_loop="$root/candy-client/candy-cloud-sync-loop"

fail() {
	printf 'openwrt_sdwan_productization_test: %s\n' "$*" >&2
	exit 1
}

if grep -E 'cargo|target/.*/release' "$makefile" >/dev/null; then
	fail "OpenWrt package still compiles or embeds Core"
fi
grep -F '$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-netd $(1)/usr/bin/candy-netd' "$makefile" >/dev/null || fail "candy-netd is not packaged as a Runtime binary"
grep -F '$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-sdwan-agent $(1)/usr/bin/candy-sdwan-agent' "$makefile" >/dev/null || fail "candy-sdwan-agent is not packaged as a Runtime binary"
grep -F '$(INSTALL_BIN) ./candy-sdwan $(1)/usr/bin/candy-sdwan' "$makefile" >/dev/null || fail "candy-sdwan Runtime launcher is not packaged"
grep -F '$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-sdwan-runtime $(1)/usr/libexec/candy-sdwan-runtime' "$makefile" >/dev/null || fail "Runtime SD-WAN V1 state helper is not packaged"
grep -F '$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-cloud-enroll $(1)/usr/libexec/candy-cloud-enroll' "$makefile" >/dev/null || fail "Cloud bootstrap exchange client is not packaged"
grep -F '$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-cloud-sync $(1)/usr/libexec/candy-cloud-sync' "$makefile" >/dev/null || fail "Cloud Runtime synchronizer is not packaged"
grep -F '$(INSTALL_BIN) ./candy-cloud-sync.init $(1)/etc/init.d/candy-cloud-sync' "$makefile" >/dev/null || fail "Cloud synchronization service is not packaged"
grep -F '$(INSTALL_BIN) ./candy-cloud-sync-loop $(1)/usr/libexec/candy-cloud-sync-loop' "$makefile" >/dev/null || fail "Cloud synchronization supervisor is not packaged"
grep -F 'procd_set_param command "$SYNC_LOOP"' "$cloud_sync_init" >/dev/null || fail "Cloud synchronization does not use the independent supervisor"
if grep -F 'procd_set_param command "$initscript"' "$cloud_sync_init" >/dev/null; then
	fail "Cloud synchronization still executes rc.common as a procd worker"
fi
grep -F 'start-stop-daemon -S -c "$RUN_USER" -x "$SYNC_BIN"' "$cloud_sync_loop" >/dev/null || fail "Cloud synchronization is not dropped to the dedicated user"
grep -F '"$CANDY_INIT" sdwan_reconcile' "$cloud_sync_loop" >/dev/null || fail "root supervisor does not retain activation reconciliation"
grep -F '"$(id -u 2>/dev/null || printf 1)" = 0' "$cloud_sync_loop" >/dev/null || fail "Cloud synchronization supervisor has no root boundary"
grep -F 'activation=unchanged' "$cloud_sync_loop" >/dev/null || fail "failed Cloud synchronization can disturb the last-good activation"
if grep -F 'sync-once 2>&1' "$cloud_sync_loop" >/dev/null; then
	fail "Cloud synchronization mixes Runtime stderr into its JSON result channel"
fi
grep -F 'sync_state_from_stdout "$output"' "$cloud_sync_loop" >/dev/null || fail "Cloud synchronization does not parse its explicit stdout result"
grep -F 'detail=$(printf' "$cloud_sync_loop" >/dev/null || fail "failed Cloud synchronization does not retain bounded diagnostic detail"
grep -F 'exec "$core_bin" client sdwan "$@"' "$root/candy-client/candy-sdwan" >/dev/null || fail "candy-sdwan does not use the Core process API"
grep -F 'runtime-api-version' "$root/candy-client/candy-sdwan" >/dev/null || fail "candy-sdwan does not bootstrap the Core process API"
if grep -F '/usr/lib/candy/cores/current/candy-' "$makefile" >/dev/null; then
	fail "Runtime executables are still linked from the Core directory"
fi
grep -F 'candy-core-manager' "$makefile" >/dev/null || fail "Core lifecycle manager is not installed"
grep -F 'candy-runtime-health-check' "$makefile" >/dev/null || fail "Core activation health check is not installed"
grep -F '+kmod-tun' "$makefile" >/dev/null || fail "TUN kernel dependency is missing"
grep -F 'config sdwan' "$config" >/dev/null || fail "SD-WAN UCI bootstrap is missing"
if sed -n '/^config sdwan /,/^$/p' "$config" | grep -Eq "option (enabled|mode) "; then
	fail "local UCI still controls Cloud SD-WAN activation"
fi

if grep -Eiq 'option[[:space:]]+(cidr|route|hub_candidate|attachment_epoch|route_generation)' "$config"; then
	fail "UCI exposes signed route or attachment authority"
fi
if grep -Eq 'option[[:space:]]+effective_mtu' "$config"; then
	fail "UCI exposes an unsigned MTU override that the signed SD-WAN policy does not consume"
fi
grep -F 'procd_open_instance sdwan-netd' "$init" >/dev/null || fail "netd procd instance is missing"
grep -F 'run_sdwan' "$init" >/dev/null || fail "unprivileged SD-WAN supervisor is missing"
grep -F 'procd_open_instance ordinary' "$init" >/dev/null || fail "ordinary Candy is not a named parallel instance"
grep -F 'procd_open_instance sdwan' "$init" >/dev/null || fail "SD-WAN is not an additive parallel instance"
grep -F 'run_detached_direct_command sdwan_fail_open' "$init" >/dev/null || fail "SD-WAN exit is not supervised"
sdwan_failure_body=$(sed -n '/^sdwan_fail_open()/,/^}/p' "$init")
printf '%s\n' "$sdwan_failure_body" | grep -F 'fail_open "sdwan:$reason"' >/dev/null || fail "SD-WAN failure does not enter full fail-open"
grep -F 'procd_set_param user candy-sdwan' "$init" >/dev/null || fail "SD-WAN supervisor is not unprivileged"
grep -F 'wait_for_sdwan_netd' "$init" >/dev/null || fail "client start does not wait for netd"
grep -F 'CANDY_SDWAN_CANDIDATE=${CANDY_SDWAN_CANDIDATE:-$CANDY_SDWAN_STATE_DIR/candidate}' "$init" >/dev/null || fail "Cloud activation candidate is not explicit"
grep -F 'CANDY_SDWAN_ACTIVE=${CANDY_SDWAN_ACTIVE:-$CANDY_SDWAN_STATE_DIR/active}' "$init" >/dev/null || fail "last-good activation pointer is not explicit"
grep -F 'load_sdwan_candidate' "$init" >/dev/null || fail "Cloud activation descriptor is not validated"
if grep -F 'sdwan_enabled()' "$init" >/dev/null; then
	fail "legacy UCI SD-WAN enable gate remains"
fi
grep -F 'sdwan_reconcile()' "$init" >/dev/null || fail "Cloud activation reconcile command is missing"
grep -F 'sdwan_refresh_runtime_state()' "$init" >/dev/null || fail "verified SD-WAN product status projection is missing"
grep -F 'project-local-runtime-status' "$init" >/dev/null || fail "SD-WAN status is not projected by the verified Rust aggregator"
grep -F 'start_sdwan_supervision' "$init" >/dev/null || fail "SD-WAN supervision is not independent from ordinary Candy"
grep -F 'ensure_sdwan_instance_id' "$init" >/dev/null || fail "SD-WAN instance identity is not bootstrapped"
grep -F 'hexdump -v -e' "$init" >/dev/null || fail "SD-WAN instance identity must use the OpenWrt-supported hexdump"
if grep -F ' | od ' "$init" >/dev/null; then
	 fail "SD-WAN init must not depend on od, which is absent from the base image"
fi
grep -F 'ensure_sdwan_generation' "$init" >/dev/null || fail "SD-WAN transaction generation is not persisted"
grep -F 'result=activation_in_progress' "$init" >/dev/null || fail "SD-WAN reconciliation does not preserve an in-flight data plane"
if grep -F 'promote_sdwan_active "$CANDY_SDWAN_CANDIDATE_TARGET"' "$init" >/dev/null; then
	fail "OpenWrt init must not promote a candidate before Cloud acknowledgement and durable proof publication"
fi
grep -F '"$CANDY_SDWAN_AGENT" --socket "$CANDY_NETD_SOCKET"' "$init" >/dev/null || fail "SD-WAN agent lifecycle contract is missing"
grep -F -- '--activation "$CANDY_SDWAN_CANDIDATE"' "$init" >/dev/null || fail "Cloud activation pointer is not passed to the agent"
grep -F 'core_status="$RUNTIME_DIR/sdwan-$attempted_hash.status.json"' "$init" >/dev/null || fail "SD-WAN Core status is not activation-specific"
grep -F -- '--status "$core_status"' "$init" >/dev/null || fail "SD-WAN agent does not receive the activation-specific Core status path"
if grep -F -- '--status "$CANDY_SDWAN_STATUS_FILE"' "$init" >/dev/null; then
	fail "Runtime product status is still shared with Core readiness"
fi
grep -F 'cleanup_stale_sdwan_core_statuses' "$init" >/dev/null || fail "root startup does not migrate stale Core status files"
supervision=$(sed -n '/^start_sdwan_supervision() {$/,/^}$/p' "$init")
prepare_line=$(printf '%s\n' "$supervision" | grep -n 'if ! prepare_sdwan_state; then' | cut -d: -f1)
cleanup_line=$(printf '%s\n' "$supervision" | grep -n 'if ! cleanup_stale_sdwan_core_statuses; then' | cut -d: -f1)
[ -n "$prepare_line" ] && [ -n "$cleanup_line" ] || fail "SD-WAN root startup ordering is incomplete"
[ "$prepare_line" -lt "$cleanup_line" ] || fail "SD-WAN runtime directory is prepared after stale status cleanup"
grep -F 'sdwan_uid=$(id -u candy-sdwan' "$init" >/dev/null || fail "netd caller UID is not dedicated"
grep -F -- '--allowed-uid "$sdwan_uid"' "$init" >/dev/null || fail "netd caller UID is not passed"
if grep -F -- '--client-args' "$init" >/dev/null || grep -F -- '--netd-socket' "$init" >/dev/null; then
	fail "legacy SD-WAN supervisor arguments remain"
fi
procd_tmp=$(mktemp -d)
trap 'rm -rf "$procd_tmp"' EXIT HUP INT TERM
mkdir -p "$procd_tmp/state/identity"
printf '%s\n' '{}' > "$procd_tmp/state/identity/device-identity-v1.json"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$procd_tmp/sync"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$procd_tmp/loop"
chmod 0755 "$procd_tmp/sync" "$procd_tmp/loop"
: > "$procd_tmp/procd.log"
procd_open_instance() { printf 'instance %s\n' "${1:-default}" >> "$procd_tmp/procd.log"; }
procd_set_param() { printf 'param %s\n' "$*" >> "$procd_tmp/procd.log"; }
procd_close_instance() { printf '%s\n' close >> "$procd_tmp/procd.log"; }
procd_add_reload_trigger() { :; }
CANDY_CLOUD_SYNC_BIN="$procd_tmp/sync"
CANDY_CLOUD_SYNC_LOOP="$procd_tmp/loop"
CANDY_SDWAN_STATE_DIR="$procd_tmp/state"
. "$cloud_sync_init"
start_service
grep -Fx "param command $procd_tmp/loop" "$procd_tmp/procd.log" >/dev/null || fail "procd command is not the independent Cloud supervisor"
if grep -Eq '^param (user|group) ' "$procd_tmp/procd.log"; then
	fail "root reconciliation supervisor was incorrectly demoted as a whole"
fi
rm -rf "$procd_tmp"
trap - EXIT HUP INT TERM
grep -F 'chown root:root /var/lib/candy' "$init" >/dev/null || fail "netd journal parent is not root-owned"
grep -F 'chmod 0770 "$RUNTIME_DIR"' "$init" >/dev/null || fail "SD-WAN application runtime is not writable by its dedicated user"
grep -F 'chmod 0750 "$CANDY_NETD_RUNTIME_DIR"' "$init" >/dev/null || fail "netd socket parent permits replacement by the SD-WAN caller"
grep -F 'chmod 0711 /var/lib/candy' "$init" >/dev/null || fail "durable root does not permit traversal to delegated state"
grep -F 'chmod 0700 "$CANDY_EPOCH_DIRECTORY"' "$init" >/dev/null || fail "delegated epoch state is not private"
if grep -E 'nft[^\n]*(add|create)[^\n]*(candy_sdwan_|table)' "$init"; then
	fail "shell lifecycle duplicates production netd nft ownership"
fi

grep -F 'read_sdwan_status(uci)' "$controller" >/dev/null || fail "LuCI status endpoint omits SD-WAN"
grep -F 'MAX_SDWAN_STATUS_BYTES = 65536' "$controller" >/dev/null || fail "SD-WAN status is unbounded"
grep -F 'contains_credential_field(status)' "$controller" >/dev/null || fail "SD-WAN status is not redaction checked"
grep -F 'safe_egress_object' "$controller" >/dev/null || fail "LuCI status projection drops configured egress state"
grep -F 'result.egress.remote = safe_egress_object(status.egress.remote)' "$controller" >/dev/null || fail "LuCI status projection omits remote egress state"
grep -F 'template("candy/sdwan")' "$controller" >/dev/null || fail "dedicated LuCI SD-WAN page is missing"
grep -F 'tonumber(parsed.schema_version) == 1' "$sdwan" >/dev/null || fail "LuCI SD-WAN page does not require formal V1 state"
grep -F 'profile-v1.json' "$sdwan" >/dev/null || fail "LuCI does not consume the synchronized Cloud profile"
grep -F 'Current site' "$sdwan" >/dev/null || fail "LuCI does not provide a human-safe Site fallback"
grep -F 'Current network' "$sdwan" >/dev/null || fail "LuCI does not provide a human-safe network fallback"
if grep -E 'Unnamed (site|network|peer)|short_id|String\(peer\.id\)\.slice' "$sdwan" >/dev/null; then
	fail "LuCI exposes internal SD-WAN identifiers as display names"
fi
for label in 'Site' 'Segment' 'Cloud' 'Full duplex' 'Peer' 'Direct' 'Relay' 'Local egress' 'Remote egress' 'Internal DNS'; do
	grep -F "$label" "$sdwan" >/dev/null || fail "SD-WAN page is missing $label"
done
for control in 'Node join file' 'Import and join' 'Reconnect' 'Leave current Profile'; do
	grep -F "$control" "$sdwan" >/dev/null || fail "SD-WAN page is missing $control control"
done
grep -F 'enctype="multipart/form-data"' "$sdwan" >/dev/null || fail "node bootstrap import is not multipart"
grep -F 'name="bootstrap_file"' "$sdwan" >/dev/null || fail "node bootstrap file control is missing"
grep -F 'action_sdwan_join' "$controller" >/dev/null || fail "LuCI join action is missing"
grep -F 'action_sdwan_reconnect' "$controller" >/dev/null || fail "LuCI reconnect action is missing"
if grep -F 'uci:get("candy", "sdwan", "enabled")' "$controller" >/dev/null; then
	fail "LuCI still treats a local UCI switch as Cloud SD-WAN authority"
fi
grep -F 'action_sdwan_leave' "$controller" >/dev/null || fail "LuCI leave action is missing"
grep -F 'MAX_SDWAN_BOOTSTRAP_BYTES = 16 * 1024' "$controller" >/dev/null || fail "node bootstrap upload is unbounded"
grep -F 'fs.chmod(temporary, "0600")' "$controller" >/dev/null || fail "node bootstrap upload is not private"
grep -F 'fs.unlink(temporary)' "$controller" >/dev/null || fail "temporary node bootstrap input is not removed"
grep -F '{ SDWAN_RUNTIME, "bootstrap", temporary }' "$controller" >/dev/null || fail "node bootstrap file is not passed to Runtime"
if grep -E 'join_code|Node join code|name="cloud"' "$controller" "$sdwan" >/dev/null; then
	fail "ordinary OpenWrt enrollment still exposes raw bootstrap credentials"
fi
if grep -Eiq 'grant|signature|route generation|attachment epoch|hash|queue|mtu|drop' "$sdwan"; then
	fail "ordinary SD-WAN page exposes Diagnostics evidence"
fi
if grep -Eiq 'v2|legacy|eBPF' "$sdwan" "$controller"; then
	fail "formal V1 product surface contains an obsolete contract label"
fi
grep -F 'state_label(registration_state)' "$sdwan" >/dev/null || fail "LuCI registration state is not presented independently"
if grep -F 'state_label(enabled and registration_state' "$sdwan" >/dev/null; then
	fail "LuCI still conflates Cloud registration with SD-WAN enablement"
fi
grep -F 'Cloud network profile' "$sdwan" >/dev/null || fail "LuCI does not present the enrolled Cloud profile"
grep -F 'Waiting for network configuration' "$sdwan" >/dev/null || fail "LuCI does not distinguish enrollment from network readiness"
grep -F 'no additional local settings are required' "$sdwan" >/dev/null || fail "LuCI does not explain the Cloud-managed activation flow"
grep -F 'Profile management' "$sdwan" >/dev/null || fail "LuCI Profile management is not explicit"
grep -F "The node record remains in Cloud until an administrator deletes it" "$sdwan" >/dev/null || fail "LuCI leave action misrepresents Cloud inventory state"
grep -F 'run_sdwan_lifecycle("stop", { "/etc/init.d/candy", "sdwan_stop", "user_leave" }' "$controller" >/dev/null || fail "LuCI can erase identity before fail-open completes"
grep -F 'run_sdwan_lifecycle("runtime", { SDWAN_RUNTIME, "leave" }' "$controller" >/dev/null || fail "LuCI does not run the profile cleanup lifecycle"
grep -F 'event=sdwan_leave phase=' "$controller" >/dev/null || fail "LuCI leave action does not write phase-specific logs"
network_ready_actions=$(sed -n '/<% if network_ready then %>/,/<% end %>/p' "$sdwan")
for action in sdwan_start sdwan_stop sdwan_reconnect; do
	printf '%s\n' "$network_ready_actions" | grep -F "$action" >/dev/null || fail "LuCI $action is not gated by a synchronized Cloud network profile"
done
if grep -F 'The node identity has joined Candy Cloud. The SD-WAN data plane is not enabled' "$sdwan" >/dev/null; then
	fail "LuCI still exposes the ambiguous data-plane-disabled message"
fi
if grep -E 'candy-sdwan-(generation|epoch|mtu|drops|failover)|Active Hub|Route generation|Attachment epoch|Effective MTU' "$status"; then
	fail "Overview duplicates professional SD-WAN evidence"
fi

grep -F '/etc/init.d/candy stop' "$makefile" >/dev/null || fail "uninstall does not stop owned steering"
grep -F 'epoch files are deliberately kept' "$makefile" >/dev/null || fail "durable epoch preservation is undocumented"
if sed -n '/define Package\/candy-client\/prerm/,/endef/p' "$makefile" | grep -E 'rm[[:space:]].*(epoch|journal|identity|policy-cache|grant-cache)'; then
	fail "uninstall deletes durable SD-WAN authority state"
fi

printf '%s\n' 'Candy OpenWrt SD-WAN productization static test passed'
