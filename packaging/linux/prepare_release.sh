#!/bin/sh
set -eu

linux_dist=${1:-}
release_dist=${2:-}
version=${3:-}
revision=${4:-}
source_repository=${5:-}
source_commit=${6:-}

fail() { printf '%s\n' "prepare_linux_runtime_release: $*" >&2; exit 1; }
sha256_file() { sha256sum "$1" | awk '{ print tolower($1) }'; }
file_size() { wc -c < "$1" | tr -d ' '; }

[ -d "$linux_dist" ] || fail "Linux distribution directory is missing"
[ -d "$release_dist" ] || fail "merged Runtime release directory is missing"
[ -n "$version" ] || fail "Runtime version is required"
case "$revision" in ''|*[!0-9]*|0) fail "Runtime revision must be a positive integer" ;; esac
[ "$source_repository" = reTsubasa/candy-runtime ] || fail "unexpected source repository"
printf '%s' "$source_commit" | grep -Eq '^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$' || fail "invalid source commit"

release_tag="runtime-v$version-r$revision"
display="$version-r$revision"
metadata="$release_dist/runtime-release-metadata.json"
[ -s "$metadata" ] || fail "merged Runtime metadata is missing"
jq -e --arg version "$version" --argjson revision "$revision" --arg commit "$(printf '%s' "$source_commit" | tr 'A-F' 'a-f')" '
  .schema_version == 2 and .runtime.version == $version and .runtime.revision == $revision and
  .source.repository == "reTsubasa/candy-runtime" and .source.commit == $commit
' "$metadata" >/dev/null || fail "merged Runtime metadata does not match this release"

targets_json=$(mktemp)
artifacts_json=$(mktemp)
trap 'rm -f "$targets_json" "$artifacts_json"' EXIT HUP INT TERM
: >"$targets_json"
: >"$artifacts_json"

for architecture in x86_64 aarch64; do
	bundle="candy-server-runtime-$architecture.tar.gz"
	source="$linux_dist/$bundle"
	manifest="linux-$architecture.json"
	[ -s "$source" ] || fail "missing Linux Runtime bundle: $source"
	cp "$source" "$release_dist/$bundle"
	sha=$(sha256_file "$release_dist/$bundle")
	size=$(file_size "$release_dist/$bundle")
	url="https://github.com/reTsubasa/candy-release/releases/download/$release_tag/$bundle"
	case "$architecture" in
		x86_64) rust_target=x86_64-unknown-linux-musl; libc=musl ;;
		aarch64) rust_target=aarch64-unknown-linux-gnu; libc=glibc ;;
	esac
	jq -n \
		--arg platform linux --arg architecture "$architecture" \
		--arg runtime_version "$display" --arg runtime_url "$url" \
		--arg runtime_sha256 "$sha" --argjson runtime_size "$size" \
		'{schema_version:1,platform:$platform,architecture:$architecture,runtime_version:$runtime_version,runtime_url:$runtime_url,runtime_sha256:$runtime_sha256,runtime_size:$runtime_size}' \
		>"$release_dist/$manifest"
	manifest_sha=$(sha256_file "$release_dist/$manifest")
	manifest_size=$(file_size "$release_dist/$manifest")
	jq -nc --arg id "linux-$architecture" --arg arch "$architecture" --arg target "$rust_target" --arg libc "$libc" \
		'{target_id:$id,platform:"linux",role:"server",architecture:$arch,rust_target:$target,libc:$libc,package_format:"tar.gz"}' >>"$targets_json"
	jq -nc --arg name "$bundle" --arg arch "$architecture" --arg sha "$sha" --argjson size "$size" \
		'{name:$name,component:"runtime-server-bundle",architecture:$arch,sha256:$sha,size_bytes:$size}' >>"$artifacts_json"
	jq -nc --arg name "$manifest" --arg arch "$architecture" --arg sha "$manifest_sha" --argjson size "$manifest_size" \
		'{name:$name,component:"runtime-install-manifest",architecture:$arch,sha256:$sha,size_bytes:$size}' >>"$artifacts_json"
done

jq -s . "$targets_json" >"$targets_json.array"
jq -s . "$artifacts_json" >"$artifacts_json.array"
jq --slurpfile targets "$targets_json.array" --slurpfile artifacts "$artifacts_json.array" '
  .release_kind = "candy-runtime" |
  .targets += $targets[0] |
  .artifacts += $artifacts[0]
' "$metadata" >"$metadata.next"
mv "$metadata.next" "$metadata"
rm -f "$targets_json.array" "$artifacts_json.array"

(
	cd "$release_dist"
	: >SHA256SUMS
	for artifact in $(find . -maxdepth 1 -type f ! -name SHA256SUMS -print | sed 's#^./##' | sort); do
		printf '%s  %s\n' "$(sha256_file "$artifact")" "$artifact" >>SHA256SUMS
	done
)

jq -e '
  .release_kind == "candy-runtime" and
  ([.targets[].target_id] | sort) == ["ipq40xx-generic-arm_cortex-a7_neon-vfpv4","linux-aarch64","linux-x86_64","x86_64"] and
  ([.artifacts[].component] | sort) == ["luci","luci","runtime-client","runtime-client","runtime-install-manifest","runtime-install-manifest","runtime-server-bundle","runtime-server-bundle"]
' "$metadata" >/dev/null || fail "combined Runtime metadata is invalid"
printf '%s\n' "$release_dist"
