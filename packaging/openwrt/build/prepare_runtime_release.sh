#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
dist_dir=${1:-}
expected_version=${CANDY_RELEASE_VERSION:-}
expected_revision=${CANDY_RELEASE_REVISION:-}
expected_openwrt=${OPENWRT_RELEASE:-25.12.4}
expected_profile=${OPENWRT_PROFILE:-x86_64}
source_repository=${CANDY_RELEASE_SOURCE_REPOSITORY:-reTsubasa/candy-runtime}
source_commit=${CANDY_RELEASE_SOURCE_COMMIT:-}

fail() {
  printf '%s\n' "prepare_runtime_release: $*" >&2
  exit 1
}

manifest_value() {
  sed -n "s/^$2:=//p" "$1"
}

build_value() {
  sed -n "s/^$1=//p" "$dist_dir/BUILD-INFO" | tail -n 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print tolower($1) }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print tolower($1) }'
  else
    fail "sha256sum or shasum is required"
  fi
}

validate_product_payload() {
  config=$repo_root/openwrt/client/packages/candy-client/candy.config
  init=$repo_root/openwrt/client/packages/candy-client/candy.init
  rulesets=$repo_root/openwrt/client/packages/candy-client/rulesets
  ruleset_verifier=$repo_root/packaging/openwrt/build/verify_bootstrap_rulesets.sh
  [ -x "$ruleset_verifier" ] || fail "ruleset verifier is missing or not executable"
  awk '
    /^config node / { in_node=1; next }
    /^config / { in_node=0 }
    in_node && /option enabled '\''1'\''/ { exit 1 }
  ' "$config" || fail "default configuration contains an enabled node"
  ! grep -Eq "option (server|server_name|server_pin|auth) '(127\\.0\\.0\\.1(:[0-9]+)?|localhost|[^']*(change-me|replace-me)[^']*)'" "$config" ||
    fail "default configuration contains a deployable placeholder credential or endpoint"
  "$ruleset_verifier" "$rulesets" >/dev/null || fail "bootstrap ruleset verification failed"
  grep -F 'fail_open_locked()' "$init" >/dev/null || fail "OpenWrt init has no fail-open implementation"
  grep -F 'CANDY_SERVICE_LOCK_DIR=${CANDY_SERVICE_LOCK_DIR:-/var/lib/candy/service.lock}' "$init" >/dev/null ||
    fail "service lifecycle lock is not root-owned"
}

[ -n "$dist_dir" ] || fail "usage: $0 DIST_DIR"
[ -d "$dist_dir" ] || fail "distribution directory is missing: $dist_dir"
command -v jq >/dev/null 2>&1 || fail "jq is required"
[ -f "$dist_dir/BUILD-INFO" ] || fail "BUILD-INFO is missing"
validate_product_payload

runtime_version=$(tr -d '\r\n' < "$repo_root/VERSION")
client_manifest=$repo_root/openwrt/client/packages/candy-client/Makefile
luci_manifest=$repo_root/openwrt/client/packages/luci-app-candy/Makefile
client_version=$(manifest_value "$client_manifest" PKG_VERSION)
luci_version=$(manifest_value "$luci_manifest" PKG_VERSION)
client_revision=$(manifest_value "$client_manifest" PKG_RELEASE)
luci_revision=$(manifest_value "$luci_manifest" PKG_RELEASE)

[ -n "$expected_version" ] || expected_version=$runtime_version
[ -n "$expected_revision" ] || expected_revision=$client_revision
printf '%s' "$expected_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
  fail "invalid expected Runtime version: $expected_version"
case "$expected_revision" in
  ''|*[!0-9]*|0) fail "invalid expected Runtime revision: $expected_revision" ;;
esac
[ "$source_repository" = reTsubasa/candy-runtime ] ||
  fail "source repository must be reTsubasa/candy-runtime"
printf '%s' "$source_commit" | grep -Eq '^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$' ||
  fail "CANDY_RELEASE_SOURCE_COMMIT must be a full hexadecimal commit id"

[ "$runtime_version" = "$expected_version" ] ||
  fail "VERSION is $runtime_version, expected $expected_version"
[ "$client_version" = "$expected_version" ] && [ "$luci_version" = "$expected_version" ] ||
  fail "package versions do not match Runtime $expected_version"
[ "$client_revision" = "$expected_revision" ] && [ "$luci_revision" = "$expected_revision" ] ||
  fail "package revisions do not match Runtime r$expected_revision"

openwrt_release=$(build_value openwrt_release)
gcc_version=$(build_value gcc_version)
profile=$(build_value profile)
package_format=$(build_value package_format)
sdk_url=$(build_value sdk_url)
[ "$openwrt_release" = "$expected_openwrt" ] ||
  fail "BUILD-INFO OpenWrt release is $openwrt_release, expected $expected_openwrt"
[ "$profile" = "$expected_profile" ] ||
  fail "BUILD-INFO profile is $profile, expected $expected_profile"
[ "$package_format" = apk ] || fail "BUILD-INFO package format must be apk"
[ -n "$gcc_version" ] && [ -n "$sdk_url" ] || fail "BUILD-INFO is incomplete"

client_apk=candy-client-$expected_version-r$expected_revision.apk
luci_apk=luci-app-candy-$expected_version-r$expected_revision.apk
[ -s "$dist_dir/$client_apk" ] || fail "missing release artifact: $client_apk"
[ -s "$dist_dir/$luci_apk" ] || fail "missing release artifact: $luci_apk"
apk_count=$(find "$dist_dir" -maxdepth 1 -type f -name '*.apk' | wc -l | tr -d ' ')
[ "$apk_count" = 2 ] || fail "release directory must contain exactly two APK files"

build_info_tmp=$dist_dir/.BUILD-INFO.$$
{
  printf 'runtime_version=%s\n' "$expected_version"
  printf 'runtime_revision=%s\n' "$expected_revision"
  printf 'openwrt_release=%s\n' "$openwrt_release"
  printf 'gcc_version=%s\n' "$gcc_version"
  printf 'profile=%s\n' "$profile"
  printf 'package_format=apk\n'
  printf 'sdk_url=%s\n' "$sdk_url"
  printf 'source_repository=%s\n' "$source_repository"
  printf 'source_commit=%s\n' "$(printf '%s' "$source_commit" | tr 'A-F' 'a-f')"
} > "$build_info_tmp"
mv "$build_info_tmp" "$dist_dir/BUILD-INFO"

client_sha=$(sha256_file "$dist_dir/$client_apk")
luci_sha=$(sha256_file "$dist_dir/$luci_apk")
client_size=$(wc -c < "$dist_dir/$client_apk" | tr -d ' ')
luci_size=$(wc -c < "$dist_dir/$luci_apk" | tr -d ' ')
release_tag=runtime-v$expected_version-r$expected_revision

jq -n \
  --arg version "$expected_version" \
  --argjson revision "$expected_revision" \
  --arg tag "$release_tag" \
  --arg repository "$source_repository" \
  --arg commit "$(printf '%s' "$source_commit" | tr 'A-F' 'a-f')" \
  --arg openwrt "$openwrt_release" \
  --arg profile "$profile" \
  --arg client_name "$client_apk" \
  --arg client_sha "$client_sha" \
  --argjson client_size "$client_size" \
  --arg luci_name "$luci_apk" \
  --arg luci_sha "$luci_sha" \
  --argjson luci_size "$luci_size" \
  '{
    schema_version: 1,
    release_kind: "candy-runtime-openwrt-client",
    release_tag: $tag,
    runtime: {version: $version, revision: $revision},
    source: {repository: $repository, commit: $commit},
    target: {
      platform: "openwrt",
      role: "client",
      openwrt_release: $openwrt,
      profile: $profile,
      architecture: "x86_64",
      package_format: "apk"
    },
    artifacts: [
      {name: $client_name, component: "runtime-client", sha256: $client_sha, size_bytes: $client_size},
      {name: $luci_name, component: "luci", sha256: $luci_sha, size_bytes: $luci_size}
    ]
  }' > "$dist_dir/runtime-release-metadata.json"

(
  cd "$dist_dir"
  : > SHA256SUMS
  for artifact in "$client_apk" "$luci_apk" BUILD-INFO runtime-release-metadata.json; do
    printf '%s  %s\n' "$(sha256_file "$artifact")" "$artifact" >> SHA256SUMS
  done
)

jq -e \
  --arg tag "$release_tag" \
  '.schema_version == 1 and .release_tag == $tag and (.artifacts | length) == 2' \
  "$dist_dir/runtime-release-metadata.json" >/dev/null
printf '%s\n' "Prepared $release_tag in $dist_dir"
