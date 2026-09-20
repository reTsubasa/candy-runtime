#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(tr -d '\r\n' < "$root/VERSION")
client_manifest="$root/openwrt/client/packages/candy-client/Makefile"
luci_manifest="$root/openwrt/client/packages/luci-app-candy/Makefile"
release_workflow="$root/.github/workflows/release-openwrt-client.yml"
client_version=$(sed -n 's/^PKG_VERSION:=//p' "$client_manifest")
luci_version=$(sed -n 's/^PKG_VERSION:=//p' "$luci_manifest")
client_revision=$(sed -n 's/^PKG_RELEASE:=//p' "$client_manifest")
luci_revision=$(sed -n 's/^PKG_RELEASE:=//p' "$luci_manifest")
workflow_revision=$(sed -n 's/^  CANDY_RELEASE_REVISION: "\([0-9][0-9]*\)"$/\1/p' "$release_workflow")

case "$version" in
  *[!0-9.]*|.*|*.|*..*)
    printf '%s\n' "VERSION must use Major.Minor.Patch: $version" >&2
    exit 1
    ;;
esac
[ "$(printf '%s' "$version" | awk -F. '{ print NF }')" -eq 3 ] || {
  printf '%s\n' "VERSION must use Major.Minor.Patch: $version" >&2
  exit 1
}
[ "$version" = "$client_version" ] && [ "$version" = "$luci_version" ] || {
  printf '%s\n' "version mismatch: VERSION=$version client=$client_version luci=$luci_version" >&2
  exit 1
}

case "$client_revision:$luci_revision" in
  *[!0-9:]*|:|*:|*::*|0:*|*:0)
    printf '%s\n' "OpenWrt revisions must be positive integers: client=$client_revision luci=$luci_revision" >&2
    exit 1
    ;;
esac
[ "$client_revision" = "$luci_revision" ] && [ "$client_revision" = "$workflow_revision" ] || {
  printf '%s\n' "revision mismatch: client=$client_revision luci=$luci_revision workflow=$workflow_revision" >&2
  exit 1
}

grep -Fq 'EXPECTED_CORE_API=${CANDY_EXPECTED_CORE_API:-1}' \
  "$root/openwrt/client/packages/candy-client/candy-core-manager" || {
  printf '%s\n' "Runtime must declare its supported Core API independently" >&2
  exit 1
}
grep -Fq 'EXPECTED_PROCESS_API=${CANDY_EXPECTED_CORE_PROCESS_API:-1}' \
  "$root/openwrt/client/packages/candy-client/candy-core-manager" || {
  printf '%s\n' "Runtime must declare its supported Core process API independently" >&2
  exit 1
}

printf '%s\n' "Candy Runtime version contract passed: $version (OpenWrt client r$client_revision, LuCI r$luci_revision, Process API 1, Core API 1)"
