#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../packages" && pwd)
makefile="$root/candy-client/Makefile"
config="$root/candy-client/candy.config"
init="$root/candy-client/candy.init"
controller="$root/luci-app-candy/root/usr/lib/lua/luci/controller/candy.lua"
status="$root/luci-app-candy/root/usr/lib/lua/luci/view/candy/status.htm"
po="$root/luci-app-candy/po/zh-cn/candy.zh-cn.po"

fail() {
	printf 'openwrt_sdwan_productization_test: %s\n' "$*" >&2
	exit 1
}

if grep -E 'cargo|target/.*/release' "$makefile" >/dev/null; then
	fail "OpenWrt package still compiles or embeds Core"
fi
grep -F '$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-netd $(1)/usr/bin/candy-netd' "$makefile" >/dev/null || fail "candy-netd is not packaged as a Runtime binary"
grep -F '$(INSTALL_BIN) ./candy-sdwan $(1)/usr/bin/candy-sdwan' "$makefile" >/dev/null || fail "candy-sdwan Runtime launcher is not packaged"
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
grep -F 'procd_set_param user candy-sdwan' "$init" >/dev/null || fail "SD-WAN supervisor is not unprivileged"
grep -F 'wait_for_sdwan_netd' "$init" >/dev/null || fail "client start does not wait for netd"
grep -F 'CANDY_SDWAN_CONFIG=${CANDY_SDWAN_CONFIG:-/etc/candy/sdwan.toml}' "$init" >/dev/null || fail "signed SD-WAN config path is not explicit"
grep -F '"$CANDY_SDWAN_BIN" --config "$CANDY_SDWAN_CONFIG" &' "$init" >/dev/null || fail "SD-WAN CLI contract is stale"
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
grep -F 'id="candy-sdwan-status"' "$status" >/dev/null || fail "SD-WAN status section cannot be visibility gated"
grep -F 'sdwan.enabled === true' "$status" >/dev/null || fail "SD-WAN status is not gated on runtime enablement"
grep -F 'sdwan.phase !== "unavailable"' "$status" >/dev/null || fail "unavailable SD-WAN status is visible"
for label in 'SD-WAN status' 'Active Hub' 'Route generation' 'Attachment epoch' 'Effective MTU' 'Last failover'; do
	grep -F "$label" "$status" >/dev/null || fail "LuCI is missing $label"
	grep -F "msgid \"$label\"" "$po" >/dev/null || fail "translation is missing $label"
done

grep -F '/etc/init.d/candy stop' "$makefile" >/dev/null || fail "uninstall does not stop owned steering"
grep -F 'epoch files are deliberately kept' "$makefile" >/dev/null || fail "durable epoch preservation is undocumented"
if sed -n '/define Package\/candy-client\/prerm/,/endef/p' "$makefile" | grep -E 'rm[[:space:]].*(epoch|journal|identity|policy-cache|grant-cache)'; then
	fail "uninstall deletes durable SD-WAN authority state"
fi

printf '%s\n' 'Candy OpenWrt SD-WAN productization static test passed'
