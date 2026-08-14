#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-linux-release-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
fail() { printf '%s\n' "prepare_release_test: $*" >&2; exit 1; }

mkdir -p "$tmp/linux" "$tmp/release"
printf 'x86 bundle\n' >"$tmp/linux/candy-server-runtime-x86_64.tar.gz"
printf 'arm bundle\n' >"$tmp/linux/candy-server-runtime-aarch64.tar.gz"
cat >"$tmp/release/runtime-release-metadata.json" <<'EOF'
{"schema_version":2,"release_kind":"candy-runtime-openwrt-client","release_tag":"runtime-v0.4.0-r26","runtime":{"version":"0.4.0","revision":26},"source":{"repository":"reTsubasa/candy-runtime","commit":"1111111111111111111111111111111111111111"},"targets":[{"target_id":"x86_64"},{"target_id":"ipq40xx-generic-arm_cortex-a7_neon-vfpv4"}],"artifacts":[{"component":"runtime-client"},{"component":"runtime-client"},{"component":"luci"},{"component":"luci"}]}
EOF

"$root/packaging/linux/prepare_release.sh" "$tmp/linux" "$tmp/release" 0.4.0 26 reTsubasa/candy-runtime 1111111111111111111111111111111111111111 >/dev/null
(cd "$tmp/release" && sha256sum -c SHA256SUMS >/dev/null)
jq -e '.runtime_version == "0.4.0-r26" and .architecture == "aarch64" and (.runtime_url | endswith("/runtime-v0.4.0-r26/candy-server-runtime-aarch64.tar.gz"))' "$tmp/release/linux-aarch64.json" >/dev/null || fail "ARM64 manifest is invalid"
jq -e '.release_kind == "candy-runtime" and (.targets | length) == 4 and (.artifacts | length) == 8' "$tmp/release/runtime-release-metadata.json" >/dev/null || fail "combined metadata is invalid"

printf '%s\n' "Linux Runtime release preparation test passed"
