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
grep -F 'exec "$core_bin" client sdwan "$@"' "$root/candy-client/candy-sdwan" >/dev/null || fail "candy-sdwan does not use the Core process API"
grep -F 'runtime-api-version' "$root/candy-client/candy-sdwan" >/dev/null || fail "candy-sdwan does not bootstrap the Core process API"
if grep -F '/usr/lib/candy/cores/current/candy-' "$makefile" >/dev/null; then
	fail "Runtime executables are still linked from the Core directory"
fi
grep -F 'candy-core-manager' "$makefile" >/dev/null || fail "Core lifecycle manager is not installed"
grep -F 'candy-runtime-health-check' "$makefile" >/dev/null || fail "Core activation health check is not installed"
grep -F '+kmod-tun' "$makefile" >/dev/null || fail "TUN kernel dependency is missing"
grep -F 'config sdwan' "$config" >/dev/null || fail "SD-WAN UCI bootstrap is missing"
grep -F "option enabled '0'" "$config" >/dev/null || fail "SD-WAN must default off"
grep -F "option mode 'sdwan_tun'" "$config" >/dev/null || fail "SD-WAN mode is not explicit"

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
grep -F 'run_detached_direct_command sdwan_fail_open' "$init" >/dev/null || fail "SD-WAN exit still uses global fail-open"
sdwan_failure_body=$(sed -n '/^sdwan_fail_open()/,/^}/p' "$init")
printf '%s\n' "$sdwan_failure_body" | grep -F 'CANDY_NETD_JOURNAL' >/dev/null || fail "isolated SD-WAN fail-open does not recover netd state"
if printf '%s\n' "$sdwan_failure_body" | grep -E 'stop_candy_clients|network_cleanup|disable' >/dev/null; then
	fail "isolated SD-WAN fail-open can stop ordinary Candy"
fi
grep -F 'procd_set_param user candy-sdwan' "$init" >/dev/null || fail "SD-WAN supervisor is not unprivileged"
grep -F 'wait_for_sdwan_netd' "$init" >/dev/null || fail "client start does not wait for netd"
grep -F 'CANDY_SDWAN_CONFIG=${CANDY_SDWAN_CONFIG:-/etc/candy/sdwan.toml}' "$init" >/dev/null || fail "signed SD-WAN config path is not explicit"
grep -F 'ensure_sdwan_instance_id' "$init" >/dev/null || fail "SD-WAN instance identity is not bootstrapped"
grep -F 'ensure_sdwan_generation' "$init" >/dev/null || fail "SD-WAN transaction generation is not persisted"
grep -F '"$CANDY_SDWAN_AGENT" --socket "$CANDY_NETD_SOCKET"' "$init" >/dev/null || fail "SD-WAN agent lifecycle contract is missing"
grep -F -- '--status "$CANDY_SDWAN_STATUS_FILE"' "$init" >/dev/null || fail "SD-WAN agent does not pass the Core status path"
grep -F 'sdwan_uid=$(id -u candy-sdwan' "$init" >/dev/null || fail "netd caller UID is not dedicated"
grep -F -- '--allowed-uid "$sdwan_uid"' "$init" >/dev/null || fail "netd caller UID is not passed"
if grep -F -- '--client-args' "$init" >/dev/null || grep -F -- '--netd-socket' "$init" >/dev/null; then
	fail "legacy SD-WAN supervisor arguments remain"
fi
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
grep -F 'template("candy/sdwan")' "$controller" >/dev/null || fail "dedicated LuCI SD-WAN page is missing"
grep -F 'tonumber(parsed.schema_version) == 1' "$sdwan" >/dev/null || fail "LuCI SD-WAN page does not require formal V1 state"
for label in 'Site' 'Segment' 'Cloud' 'Full duplex' 'Peer' 'Direct' 'Relay' 'Local egress' 'Remote egress' 'Internal DNS'; do
	grep -F "$label" "$sdwan" >/dev/null || fail "SD-WAN page is missing $label"
done
for control in 'Cloud address' 'Activation code' 'Join' 'Reconnect' 'Leave'; do
	grep -F "$control" "$sdwan" >/dev/null || fail "SD-WAN page is missing $control control"
done
grep -F 'type="password"' "$sdwan" >/dev/null || fail "activation code is not protected as a password input"
grep -F 'action_sdwan_join' "$controller" >/dev/null || fail "LuCI join action is missing"
grep -F 'action_sdwan_reconnect' "$controller" >/dev/null || fail "LuCI reconnect action is missing"
grep -F 'action_sdwan_leave' "$controller" >/dev/null || fail "LuCI leave action is missing"
grep -F 'fs.unlink(temporary)' "$controller" >/dev/null || fail "temporary activation input is not removed"
grep -F '{ SDWAN_RUNTIME, "join", cloud, temporary }' "$controller" >/dev/null || fail "activation code is not passed through a private file"
if grep -F '{ SDWAN_RUNTIME, "join", cloud, activation }' "$controller" >/dev/null; then
	fail "activation code is exposed in the process argument list"
fi
if grep -Eiq 'grant|signature|route generation|attachment epoch|hash|queue|mtu|drop' "$sdwan"; then
	fail "ordinary SD-WAN page exposes Diagnostics evidence"
fi
if grep -Eiq 'v2|legacy|eBPF' "$sdwan" "$controller"; then
	fail "formal V1 product surface contains an obsolete contract label"
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
