#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-openwrt-sdk-profile-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

mkdir -p "$tmp/bin" "$tmp/runtime-bin"
printf '#!/bin/sh\nexit 0\n' > "$tmp/runtime-bin/candy-netd"
chmod 0755 "$tmp/runtime-bin/candy-netd"
printf '#!/bin/sh\nexit 0\n' > "$tmp/runtime-bin/candy-sdwan-agent"
chmod 0755 "$tmp/runtime-bin/candy-sdwan-agent"
printf '#!/bin/sh\nexit 0\n' > "$tmp/runtime-bin/candy-cloud-enroll"
chmod 0755 "$tmp/runtime-bin/candy-cloud-enroll"
cat > "$tmp/bin/docker" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod 0755 "$tmp/bin/docker"

trace="$tmp/trace"
if PATH="$tmp/bin:$PATH" \
  CANDY_RUNTIME_BIN_DIR="$tmp/runtime-bin" \
  OPENWRT_RELEASE=25.12.4 \
  OPENWRT_GCC_VERSION=14.3.0 \
  sh -x "$root/packaging/openwrt/build/sdk_container_gate.sh" apk x86_64 \
  >"$tmp/stdout" 2>"$trace"; then
  printf '%s\n' "SDK profile test unexpectedly reached Docker" >&2
  exit 1
fi

grep -F 'openwrt_release=25.12.4' "$trace" >/dev/null
grep -F 'gcc_version=14.3.0' "$trace" >/dev/null
grep -F 'openwrt-sdk-25.12.4-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst' "$trace" >/dev/null

default_trace="$tmp/default-trace"
PATH="$tmp/bin:$PATH" \
  CANDY_RUNTIME_BIN_DIR="$tmp/runtime-bin" \
  sh -x "$root/packaging/openwrt/build/sdk_container_gate.sh" apk x86_64 \
  >"$tmp/default-stdout" 2>"$default_trace" || true
grep -F 'openwrt_release=25.12.4' "$default_trace" >/dev/null
grep -F 'gcc_version=14.3.0' "$default_trace" >/dev/null

if PATH="$tmp/bin:$PATH" \
  CANDY_RUNTIME_BIN_DIR="$tmp/runtime-bin" \
  OPENWRT_RELEASE='25.12.4/../../bad' \
  "$root/packaging/openwrt/build/sdk_container_gate.sh" apk x86_64 \
  >/dev/null 2>&1; then
  printf '%s\n' "invalid OpenWrt release override was accepted" >&2
  exit 1
fi

printf '%s\n' "OpenWrt SDK profile override passed"
