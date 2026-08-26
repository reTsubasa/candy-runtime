#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

fail() {
  printf '%s\n' "runtime_layout_test: $*" >&2
  exit 1
}

for directory in \
  linux/client \
  linux/server \
  linux/common \
  openwrt/client \
  openwrt/server \
  shared/contracts
do
  [ -d "$root/$directory" ] || fail "missing $directory"
done

for runtime_source in \
  Cargo.toml \
  Cargo.lock \
  linux/client/apps/candy-client/candy-client \
  linux/client/apps/candy/candy \
  linux/client/apps/candy-sdwan/candy-sdwan \
  linux/common/apps/candy-sdwan-runtime/candy-sdwan-runtime \
  linux/server/apps/candy-server/candy-server \
  linux/server/apps/candy-server/serverd-linux \
  linux/server/apps/candy-server/candy-core-manager \
  linux/server/apps/candy-server/candy-server-health-check \
  linux/common/apps/candy-netd/Cargo.toml \
  linux/common/apps/candy-sdwan-agent/Cargo.toml \
  linux/common/apps/candy-cloud-sync/Cargo.toml \
  linux/common/crates/candy-netd-client/Cargo.toml \
  linux/common/crates/candy-netd-proto/Cargo.toml \
  openwrt/client/packages/candy-client/Makefile \
  openwrt/client/packages/luci-app-candy/Makefile
do
  [ -f "$root/$runtime_source" ] || fail "missing $runtime_source"
done

if find "$root/linux/client" "$root/linux/server" -type f \( -name Cargo.toml -o -name '*.rs' \) | grep -q .; then
  fail "private Core Rust implementation remains under a Runtime role launcher"
fi
[ ! -e "$root/linux/common/crates/candy-runtime-linux" ] ||
  fail "obsolete Core-coupled candy-runtime-linux crate remains"

if rg -n 'candy-core|candy-proto|candy-tun|carrier-(client|crypto|runtime|server|transport)' \
  "$root" -g Cargo.toml >/dev/null 2>&1; then
  fail "Runtime Cargo workspace still references a private Core crate"
fi

for forbidden in crates/candy-core crates/candy-proto crates/carrier-crypto vendor/quinn-proto; do
  [ ! -e "$root/$forbidden" ] || fail "private Core source leaked into Runtime: $forbidden"
done

for obsolete in migration bindings platform; do
  [ ! -e "$root/$obsolete" ] || fail "obsolete repository content remains: $obsolete"
done

client_makefile="$root/openwrt/client/packages/candy-client/Makefile"
common_sync="$root/linux/common/apps/candy-cloud-sync/src/main.rs"
common_runtime="$root/linux/common/apps/candy-sdwan-runtime/candy-sdwan-runtime"
openwrt_init="$root/openwrt/client/packages/candy-client/candy.init"
openwrt_sync_loop="$root/openwrt/client/packages/candy-client/candy-cloud-sync-loop"
grep -Fq 'default_value = "/var/lib/candy/sdwan"' "$common_sync" ||
  fail "shared Linux Cloud sync default does not use the canonical Linux state root"
grep -Fq 'state_dir=${CANDY_SDWAN_STATE_DIR:-/var/lib/candy/sdwan}' "$common_runtime" ||
  fail "shared Linux lifecycle default does not use the canonical Linux state root"
grep -Fq 'CANDY_SDWAN_STATE_DIR=${CANDY_SDWAN_STATE_DIR:-/etc/candy/sdwan}' "$openwrt_init" ||
  fail "OpenWrt lifecycle does not use its persistent state root"
grep -Fq -- '--state-dir "$STATE_DIR"' "$openwrt_sync_loop" ||
  fail "OpenWrt Cloud sync does not explicitly pass its persistent state root"
grep -Fq '$(INSTALL_BIN) ./candy-client $(1)/usr/bin/candy-client' "$client_makefile" ||
  fail "OpenWrt client does not package its Runtime launcher"
grep -Fq '$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-netd' "$client_makefile" ||
  fail "OpenWrt client does not package runtime-owned candy-netd"
grep -Fq '$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-sdwan-agent' "$client_makefile" ||
  fail "OpenWrt client does not package runtime-owned candy-sdwan-agent"
grep -Fq '$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-sdwan-runtime $(1)/usr/libexec/candy-sdwan-runtime' "$client_makefile" ||
  fail "OpenWrt client does not package the Runtime-owned SD-WAN state helper"
grep -Fq '$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-cloud-sync $(1)/usr/libexec/candy-cloud-sync' "$client_makefile" ||
  fail "OpenWrt client does not package the Runtime-owned Cloud synchronizer"
if grep -Eq '/usr/lib/candy/cores/current/(candy-client|candy-netd|candy-sdwan)' "$client_makefile"; then
  fail "Runtime executable is still owned by a Core bundle"
fi

[ -f "$root/shared/contracts/core-process-api-v1.md" ] || fail "Core process API contract is missing"
[ ! -e "$root/shared/contracts/core-abi-v1.md" ] || fail "obsolete Core shared-library ABI contract remains"

manager="$root/openwrt/client/packages/candy-client/candy-core-manager"
linux_manager="$root/linux/server/apps/candy-server/candy-core-manager"
grep -Fq 'executable="$1/candy-core"' "$manager" || fail "OpenWrt manager does not consume the Core executable"
[ "$(grep -Fc 'tar -oxzf' "$manager")" -eq 2 ] ||
  fail "OpenWrt manager does not discard archive ownership at every extraction boundary"
[ "$(grep -Fc 'tar -oxzf' "$linux_manager")" -eq 1 ] ||
  fail "Linux manager does not discard archive ownership during installation"
if grep -Eq 'libcandy_core|CANDY_CORE_SRC|git (clone|checkout)' "$client_makefile" "$manager"; then
  fail "OpenWrt Runtime still compiles, fetches, or loads Core source/library artifacts"
fi

printf '%s\n' "Candy Runtime repository layout passed"
