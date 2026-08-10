#!/bin/sh
set -eu

x86_dir=${1:-}
arm_dir=${2:-}
out_dir=${3:-}
[ -d "$x86_dir" ] && [ -d "$arm_dir" ] && [ -n "$out_dir" ] || {
  echo "usage: $0 X86_DIR ARM_DIR OUT_DIR" >&2
  exit 2
}
command -v jq >/dev/null 2>&1 || exit 2
mkdir -p "$out_dir"
rm -f "$out_dir"/*

for dir in "$x86_dir" "$arm_dir"; do
  metadata=$dir/runtime-release-metadata.json
  [ -f "$metadata" ] || { echo "missing target metadata: $metadata" >&2; exit 1; }
  jq -e '.schema_version == 2 and .release_kind == "candy-runtime-openwrt-client" and (.target.target_id | type == "string") and (.artifacts | length) == 2' "$metadata" >/dev/null || exit 1
  for artifact in $(jq -r '.artifacts[].name' "$metadata"); do
    [ -f "$dir/$artifact" ] || { echo "missing target artifact: $dir/$artifact" >&2; exit 1; }
    cp "$dir/$artifact" "$out_dir/$artifact"
  done
  target_id=$(jq -er '.target.target_id' "$metadata")
  case "$target_id" in
    x86_64|ipq40xx-generic-arm_cortex-a7_neon-vfpv4) ;;
    *) echo "unsupported Runtime target id: $target_id" >&2; exit 1 ;;
  esac
  cp "$dir/BUILD-INFO" "$out_dir/BUILD-INFO-$target_id"
  cp "$dir/SHA256SUMS" "$out_dir/SHA256SUMS-$target_id"
  cp "$metadata" "$out_dir/runtime-release-metadata-$target_id.json"
done

[ "$(jq -r '.target.target_id' "$x86_dir/runtime-release-metadata.json")" = x86_64 ] || exit 1
[ "$(jq -r '.target.target_id' "$arm_dir/runtime-release-metadata.json")" = ipq40xx-generic-arm_cortex-a7_neon-vfpv4 ] || exit 1

first=$x86_dir/runtime-release-metadata.json
version=$(jq -er '.runtime.version' "$first")
revision=$(jq -er '.runtime.revision' "$first")
tag=$(jq -er '.release_tag' "$first")
commit=$(jq -er '.source.commit' "$first")
for metadata in "$arm_dir/runtime-release-metadata.json"; do
  jq -e --arg version "$version" --argjson revision "$revision" --arg commit "$commit" --arg tag "$tag" \
    '.runtime.version == $version and .runtime.revision == $revision and .source.commit == $commit and .release_tag == $tag' "$metadata" >/dev/null || {
      echo "target release metadata does not share version/commit" >&2
      exit 1
    }
done

jq -s '{
  schema_version: 2,
  release_kind: "candy-runtime-openwrt-client",
  release_tag: .[0].release_tag,
  runtime: .[0].runtime,
  source: .[0].source,
  targets: [.[].target],
  artifacts: [.[].artifacts[]]
}' "$x86_dir/runtime-release-metadata.json" "$arm_dir/runtime-release-metadata.json" > "$out_dir/runtime-release-metadata.json"

(
  cd "$out_dir"
  : > SHA256SUMS
  for artifact in *.apk BUILD-INFO-* SHA256SUMS-* runtime-release-metadata-*.json runtime-release-metadata.json; do
    [ -f "$artifact" ] || continue
    printf '%s  %s\n' "$(sha256sum "$artifact" | awk '{print $1}')" "$artifact" >> SHA256SUMS
  done
)
printf '%s\n' "$out_dir"
