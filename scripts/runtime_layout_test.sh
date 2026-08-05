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
  linux/client/apps/candy-sdwan/candy-sdwan \
  linux/server/apps/candy-server/serverd-linux \
  linux/server/apps/candy-server/candy-core-manager \
  linux/server/apps/candy-server/candy-server-health-check \
  linux/common/apps/candy-netd/Cargo.toml \
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
grep -Fq '$(INSTALL_BIN) ./candy-client $(1)/usr/bin/candy-client' "$client_makefile" ||
  fail "OpenWrt client does not package its Runtime launcher"
grep -Fq '$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-netd' "$client_makefile" ||
  fail "OpenWrt client does not package runtime-owned candy-netd"
if grep -Eq '/usr/lib/candy/cores/current/(candy-client|candy-netd|candy-sdwan)' "$client_makefile"; then
  fail "Runtime executable is still owned by a Core bundle"
fi

[ -f "$root/shared/contracts/core-process-api-v1.md" ] || fail "Core process API contract is missing"
[ ! -e "$root/shared/contracts/core-abi-v1.md" ] || fail "obsolete Core shared-library ABI contract remains"

manager="$root/openwrt/client/packages/candy-client/candy-core-manager"
grep -Fq 'executable="$1/candy-core"' "$manager" || fail "OpenWrt manager does not consume the Core executable"
if grep -Eq 'libcandy_core|CANDY_CORE_SRC|git (clone|checkout)' "$client_makefile" "$manager"; then
  fail "OpenWrt Runtime still compiles, fetches, or loads Core source/library artifacts"
fi

printf '%s\n' "Candy Runtime repository layout passed"
