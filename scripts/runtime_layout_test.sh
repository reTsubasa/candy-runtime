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
  linux/client/apps/candy-client/Cargo.toml \
  linux/client/apps/candy-sdwan/Cargo.toml \
  linux/server/apps/candy-server/Cargo.toml \
  linux/common/apps/candy-netd/Cargo.toml \
  linux/common/crates/candy-runtime-linux/Cargo.toml \
  openwrt/client/packages/candy-client/Makefile \
  openwrt/client/packages/luci-app-candy/Makefile
do
  [ -f "$root/$runtime_source" ] || fail "missing $runtime_source"
done

for forbidden in crates/candy-core crates/candy-proto crates/carrier-crypto vendor/quinn-proto; do
  [ ! -e "$root/$forbidden" ] || fail "private Core source leaked into Runtime: $forbidden"
done

for obsolete in migration bindings platform; do
  [ ! -e "$root/$obsolete" ] || fail "obsolete repository content remains: $obsolete"
done

client_makefile="$root/openwrt/client/packages/candy-client/Makefile"
grep -Fq '$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-client' "$client_makefile" ||
  fail "OpenWrt client does not package its Runtime binary"
if grep -Eq '/usr/lib/candy/cores/current/(candy-client|candy-netd|candy-sdwan)' "$client_makefile"; then
  fail "Runtime executable is still owned by a Core bundle"
fi

[ -f "$root/shared/contracts/core-abi-v1.md" ] || fail "Core ABI contract is missing"

printf '%s\n' "Candy Runtime repository layout passed"
