#!/bin/sh
set -eu

core=${1:-/usr/lib/candy/cores/current/candy-core}
runtime_root=${2:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}

fail() { printf 'runtime_preflight: %s\n' "$*" >&2; exit 1; }
[ -x "$core" ] || fail "Core binary is not executable: $core"
[ "$("$core" runtime-api-version 2>/dev/null)" = 1 ] || fail "unsupported Core process API"
manifest=$("$core" core-info 2>/dev/null) || fail "Core manifest unavailable"
printf '%s\n' "$manifest" | grep -F '"modules"' >/dev/null ||
  fail "Core manifest does not declare independent proxy/sdwan modules"
printf '%s\n' "$manifest" | grep -F '"proxy"' >/dev/null || fail "Proxy module missing from Core manifest"
printf '%s\n' "$manifest" | grep -F '"sdwan"' >/dev/null || fail "SD-WAN module missing from Core manifest"

init="$runtime_root/openwrt/client/packages/candy-client/candy.init"
product="$runtime_root/openwrt/client/tests/sdwan_productization_test.sh"
[ -f "$init" ] || fail "OpenWrt init is missing"
[ -f "$product" ] || fail "productization regression test is missing"

sdwan_body=$(sed -n '/^sdwan_fail_open_locked()/,/^}/p' "$init")
printf '%s\n' "$sdwan_body" | grep -F 'ordinary_client=preserved' >/dev/null ||
  fail "SD-WAN fail-open does not preserve Proxy"
if printf '%s\n' "$sdwan_body" | grep -F 'fail_open_locked sdwan' >/dev/null; then
  fail "SD-WAN fail-open still escalates to global Proxy fail-open"
fi
grep -F 'write_fallback_traffic_path' "$init" >/dev/null ||
  fail "fallback path is not readiness-aware"
grep -F 'proxy_data_plane.status(' "$runtime_root/../candy-core/crates/candy-carrier-client/src/lib.rs" >/dev/null ||
  fail "Proxy data-plane evidence is not exported"

(CDPATH= cd -- "$runtime_root" && sh openwrt/client/tests/sdwan_productization_test.sh)
printf '%s\n' 'runtime_preflight: PASS'
