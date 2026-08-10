#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-openwrt-package-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fake_bin="$tmp/bin"
sdk="$tmp/openwrt-sdk"
log="$tmp/make.log"
mkdir -p "$fake_bin" "$sdk/package" "$sdk/include"
runtime_bin_dir="$tmp/runtime-bin"
mkdir -p "$runtime_bin_dir"
printf '#!/bin/sh\nexit 0\n' > "$runtime_bin_dir/candy-netd"
chmod 0755 "$runtime_bin_dir/candy-netd"
printf '#!/bin/sh\nexit 0\n' > "$runtime_bin_dir/candy-sdwan-agent"
chmod 0755 "$runtime_bin_dir/candy-sdwan-agent"
touch "$sdk/rules.mk"

cat >"$fake_bin/make" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "make $*" >>"$FAKE_MAKE_LOG"
sdk=
previous=
for argument in "$@"; do
  if [ "$previous" = "-C" ]; then
    sdk=$argument
    break
  fi
  previous=$argument
done
case " $* " in
  *" package/candy-client/compile "*)
    mkdir -p "$sdk/bin/packages/candy"
	    printf '%s\n' client >"$sdk/bin/packages/candy/candy-client_0.4.0-1_fake.ipk"
    ;;
  *" package/luci-app-candy/compile "*)
    mkdir -p "$sdk/bin/packages/candy"
	    printf '%s\n' luci >"$sdk/bin/packages/candy/luci-app-candy_0.4.0-1_all.ipk"
    ;;
esac
EOF
chmod +x "$fake_bin/make"

cat >"$fake_bin/file" <<'EOF'
#!/bin/sh
printf '%s\n' "$1: ELF 64-bit LSB executable, x86-64"
EOF
chmod +x "$fake_bin/file"

PATH="$fake_bin:$PATH" \
FAKE_MAKE_LOG="$log" \
OPENWRT_SDK="$sdk" \
OPENWRT_PACKAGE_EXT=ipk \
OPENWRT_TARGET_ARCH=x86_64 \
OPENWRT_HOSTCC=/usr/bin/cc \
CANDY_RUNTIME_BIN_DIR="$runtime_bin_dir" \
packaging/openwrt/build/package_gate.sh >/dev/null

test -f "$sdk/package/candy-client/candy.init"
test -f "$sdk/package/candy-client/candy.config"
test -f "$sdk/package/candy-client/candy-core-manager"
test -f "$sdk/package/candy-client/candy-update-manager"
test -f "$sdk/package/candy-client/candy-runtime-health-check"
test -f "$sdk/package/candy-client/candy-sdwan-agent"
test -f "$sdk/package/candy-client/catalog-release.pub"
test -f "$sdk/package/candy-client/core-release.pub"
grep -Fx 'untrusted comment: Candy Core release 2026' "$sdk/package/candy-client/core-release.pub" >/dev/null
grep -Fx 'RWTXjeIqv8pbV2/hEu479ar7zVRElSjW94sxU28rJfQ5c5SIH2CnnVB5' "$sdk/package/candy-client/core-release.pub" >/dev/null
test -f "$sdk/package/candy-client/candy-client"
test -f "$sdk/package/candy-client/candy-sdwan"
test -f "$sdk/package/luci-app-candy/Makefile"
grep -F -- "HOSTCC=/usr/bin/cc" "$log" >/dev/null
grep -F 'target_arch=${OPENWRT_TARGET_ARCH:-}' "$root/packaging/openwrt/build/package_gate.sh" >/dev/null
! grep -F 'cargo' "$root/packaging/openwrt/build/package_gate.sh" >/dev/null
! grep -Eq 'CANDY_CORE_SRC|git (clone|checkout)|libcandy_core' "$root/packaging/openwrt/build/package_gate.sh"

printf '%s\n' "Candy OpenWrt package gate contract passed"
