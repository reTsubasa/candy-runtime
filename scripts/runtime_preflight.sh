#!/bin/sh
set -eu

core=${1:-/usr/lib/candy/cores/current/candy-core}
runtime_root=${2:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}

fail() { printf 'runtime_preflight: %s\n' "$*" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || fail "jq is required to validate the Core manifest"
[ -x "$core" ] || fail "Core binary is not executable: $core"
[ "$("$core" runtime-api-version 2>/dev/null)" = 1 ] || fail "unsupported Core process API"
manifest=$("$core" core-info 2>/dev/null) || fail "Core manifest unavailable"
# Check the executable's public contract, not the layout or formatting of a
# sibling Core source checkout. Slurping also rejects multiple JSON documents.
printf '%s\n' "$manifest" | jq -e -s '
  length == 1 and (.[0] |
    type == "object" and
    .schema_version == 1 and .core_api_version == 1 and .process_api_version == 1 and
    (.core_version | type == "string" and length > 0) and
    (.modules | type == "array" and all(.[]; type == "string") and
      index("proxy") != null and index("sdwan") != null) and
    (.roles | type == "array" and index("client") != null and index("server") != null)
  )' >/dev/null 2>&1 || fail "Core manifest is invalid or lacks supported proxy/sdwan process contracts"

init="$runtime_root/openwrt/client/packages/candy-client/candy.init"
product="$runtime_root/openwrt/client/tests/sdwan_productization_test.sh"
flow="$runtime_root/openwrt/client/tests/traffic_flow_test.sh"
[ -f "$init" ] || fail "OpenWrt init is missing"
[ -f "$product" ] || fail "productization regression test is missing"
[ -f "$flow" ] || fail "traffic-flow regression test is missing"

sdwan_body=$(sed -n '/^sdwan_fail_open_locked()/,/^}/p' "$init")
printf '%s\n' "$sdwan_body" | grep -F 'ordinary_client=preserved' >/dev/null ||
  fail "SD-WAN fail-open does not preserve Proxy"
if printf '%s\n' "$sdwan_body" | grep -F 'fail_open_locked sdwan' >/dev/null; then
  fail "SD-WAN fail-open still escalates to global Proxy fail-open"
fi
grep -F 'write_fallback_traffic_path' "$init" >/dev/null ||
  fail "fallback path is not readiness-aware"
(CDPATH= cd -- "$runtime_root" && sh openwrt/client/tests/sdwan_productization_test.sh)
(CDPATH= cd -- "$runtime_root" && sh openwrt/client/tests/traffic_flow_test.sh)
printf '%s\n' 'runtime_preflight: PASS'
