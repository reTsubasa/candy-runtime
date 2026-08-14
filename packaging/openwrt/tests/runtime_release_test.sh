#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
prepare=$root/packaging/openwrt/build/prepare_runtime_release.sh
workflow=$root/.github/workflows/release-openwrt-client.yml
sdk_gate=$root/packaging/openwrt/build/sdk_container_gate.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-runtime-release-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() {
  printf '%s\n' "runtime_release_test: $*" >&2
  exit 1
}

version=$(tr -d '\r\n' < "$root/VERSION")
revision=$(sed -n 's/^PKG_RELEASE:=//p' "$root/openwrt/client/packages/candy-client/Makefile")
dist=$tmp/dist
mkdir -p "$dist"
printf '%s\n' client > "$dist/candy-client-$version-r$revision.apk"
printf '%s\n' luci > "$dist/luci-app-candy-$version-r$revision.apk"
cat > "$dist/BUILD-INFO" <<'EOF'
openwrt_release=25.12.4
gcc_version=14.3.0
profile=x86_64
package_format=apk
sdk_url=https://downloads.openwrt.org/releases/25.12.4/targets/x86/64/example.tar.zst
EOF

CANDY_RELEASE_VERSION="$version" \
  CANDY_RELEASE_REVISION="$revision" \
  CANDY_RELEASE_SOURCE_REPOSITORY=reTsubasa/candy-runtime \
  CANDY_RELEASE_SOURCE_COMMIT=0123456789abcdef0123456789abcdef01234567 \
  "$prepare" "$dist" >/dev/null

jq -e \
  --arg version "$version" \
  --argjson revision "$revision" \
  '.schema_version == 2 and .runtime.version == $version and .runtime.revision == $revision and
   .target.openwrt_release == "25.12.4" and .target.architecture == "x86_64" and
   (.artifacts | length) == 2' \
  "$dist/runtime-release-metadata.json" >/dev/null || fail "release metadata is incomplete"
grep -Fx "runtime_version=$version" "$dist/BUILD-INFO" >/dev/null || fail "BUILD-INFO lacks Runtime version"
grep -Fx "runtime_revision=$revision" "$dist/BUILD-INFO" >/dev/null || fail "BUILD-INFO lacks Runtime revision"
(cd "$dist" && sha256sum -c SHA256SUMS >/dev/null) || fail "release checksums do not verify"

printf '%s\n' extra > "$dist/unexpected.apk"
if CANDY_RELEASE_VERSION="$version" \
  CANDY_RELEASE_REVISION="$revision" \
  CANDY_RELEASE_SOURCE_COMMIT=0123456789abcdef0123456789abcdef01234567 \
  "$prepare" "$dist" >/dev/null 2>&1; then
  fail "release preparation accepted an extra APK"
fi
rm -f "$dist/unexpected.apk"

if CANDY_RELEASE_VERSION="$version" \
  CANDY_RELEASE_REVISION=$((revision + 1)) \
  CANDY_RELEASE_SOURCE_COMMIT=0123456789abcdef0123456789abcdef01234567 \
  "$prepare" "$dist" >/dev/null 2>&1; then
  fail "release preparation accepted the wrong package revision"
fi

[ -f "$workflow" ] || fail "OpenWrt client release workflow is missing"
grep -Fq 'push:' "$workflow" || fail "release workflow does not trigger automatically"
grep -Fq 'branches:' "$workflow" || fail "release workflow does not restrict automatic releases to main"
grep -Fq 'SOURCE_COMMIT: ${{ inputs.source_commit || github.sha }}' "$workflow" || fail "release workflow does not resolve an immutable automatic source commit"
grep -Fq 'ref: ${{ env.SOURCE_COMMIT }}' "$workflow" || fail "release workflow does not build the resolved immutable source commit"
grep -Fq 'source_commit:' "$workflow" || fail "release workflow does not require a source commit input"
grep -Fq 'test "$GITHUB_REPOSITORY" = reTsubasa/candy-runtime' "$workflow" || fail "release workflow accepts an unexpected source repository"
grep -Fq 'CANDY_RELEASE_VERSION: "0.4.0"' "$workflow" || fail "release workflow does not pin Runtime 0.4.0"
grep -Fq "CANDY_RELEASE_REVISION: \"$revision\"" "$workflow" || fail "release workflow does not pin package revision r$revision"
grep -Fq 'OPENWRT_RELEASE: "25.12.4"' "$workflow" || fail "release workflow does not pin OpenWrt 25.12.4"
grep -Fq 'secrets.CANDY_RELEASE_TOKEN' "$workflow" || fail "release workflow does not use CANDY_RELEASE_TOKEN"
grep -Fq 'reTsubasa/candy-release' "$workflow" || fail "release workflow targets the wrong repository"
grep -Fq 'gh release upload' "$workflow" || fail "release workflow does not upload release assets"
grep -Fq 'armv7-unknown-linux-musleabihf' "$workflow" || fail "release workflow does not build ARMv7 Runtime"
grep -Fq 'ipq40xx-generic' "$workflow" || fail "release workflow does not package IPQ40xx Runtime"
grep -Fq 'merge_runtime_release.sh' "$workflow" || fail "release workflow does not aggregate target assets"
grep -Fq -- '--draft' "$workflow" || fail "release workflow does not stage assets in a draft release"
grep -Fq 'incoming-$tag' "$workflow" || fail "release workflow does not isolate incoming assets"
grep -Fq 'candy-artifact-ready' "$workflow" || fail "release workflow does not request central finalization"
grep -Fq '"$payload/client/usr/bin/candy-sdwan-agent"' "$sdk_gate" || fail "SDK gate does not verify the packaged SD-WAN agent"
grep -Fq '"$payload/client/usr/bin/candy-netd"' "$sdk_gate" || fail "SDK gate does not verify the packaged netd"
grep -Fq '"$payload/client/usr/libexec/candy-cloud-enroll"' "$sdk_gate" || fail "SDK gate does not verify the packaged enrollment client"
grep -Fq '"$payload/luci/usr/lib/lua/luci/view/candy/sdwan.htm"' "$sdk_gate" || fail "SDK gate does not verify the packaged LuCI SD-WAN view"
grep -Fq 'repos/$RELEASE_REPOSITORY/dispatches' "$workflow" || fail "release workflow dispatches to the wrong repository"
if grep -Fq -- '--draft=false' "$workflow"; then
  fail "Runtime source workflow must not publish the draft itself"
fi
if grep -Fq -- '--clobber' "$workflow"; then
  fail "release workflow must not overwrite immutable assets"
fi
if grep -Eiq 'catalog|stable[-_ ]+(release|index|metadata)' "$workflow"; then
  fail "Runtime release workflow must not modify the stable catalog"
fi

printf '%s\n' "Candy centralized Runtime release contract passed"
