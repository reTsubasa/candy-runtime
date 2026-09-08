#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fake_core="$tmp/candy-core"
printf '%s\n' '#!/bin/sh' 'case "$1" in runtime-api-version) printf "%s" "${TEST_PROCESS_API:-1}" ;; core-info) printf "%s" "$TEST_CORE_MANIFEST" ;; *) exit 1 ;; esac' >"$fake_core"
chmod 0755 "$fake_core"

# Only Runtime files are present. A preflight must not inspect candy-core/.
isolated="$tmp/runtime"
mkdir -p "$isolated/openwrt/client"
cp -R "$root/openwrt/client/packages" "$root/openwrt/client/tests" "$isolated/openwrt/client/"
valid='{"schema_version":1,"core_api_version":1,"process_api_version":1,"core_version":"0.3.42","modules":["proxy","sdwan"],"roles":["client","server"]}'
TEST_CORE_MANIFEST=$valid
export TEST_CORE_MANIFEST
"$root/scripts/runtime_preflight.sh" "$fake_core" "$isolated" >/dev/null
TEST_CORE_MANIFEST=$(printf '%s\n' "$valid" | jq .)
"$root/scripts/runtime_preflight.sh" "$fake_core" "$isolated" >/dev/null

assert_rejected() {
  TEST_CORE_MANIFEST=$1
  if "$root/scripts/runtime_preflight.sh" "$fake_core" "$isolated" >"$tmp/output" 2>&1; then
    printf 'runtime_preflight_test: accepted invalid manifest: %s\n' "$1" >&2
    exit 1
  fi
  grep -F 'Core manifest is invalid' "$tmp/output" >/dev/null
}
assert_rejected '{"modules":["proxy","sdwan"]'
assert_rejected "$(printf '%s\n' "$valid" | jq 'del(.modules)')"
assert_rejected "$(printf '%s\n' "$valid" | jq '.modules = ["proxy"]')"
assert_rejected "$(printf '%s\n' "$valid" | jq '.modules = {"proxy":true,"sdwan":true}')"
assert_rejected "$(printf '%s\n' "$valid" | jq '.modules = [] | .description = "proxy sdwan"')"
assert_rejected "$(printf '%s\n' "$valid" | jq '.process_api_version = 2')"
assert_rejected "$valid $valid"
TEST_CORE_MANIFEST=$valid
export TEST_PROCESS_API=2
if "$root/scripts/runtime_preflight.sh" "$fake_core" "$isolated" >"$tmp/output" 2>&1; then
  printf '%s\n' 'runtime_preflight_test: accepted unsupported process API' >&2
  exit 1
fi
grep -F 'unsupported Core process API' "$tmp/output" >/dev/null
printf '%s\n' 'runtime_preflight_test: PASS'
