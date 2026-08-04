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
for component in candy-client candy-netd candy-sdwan; do
  printf '#!/bin/sh\nexit 0\n' > "$runtime_bin_dir/$component"
  chmod 0755 "$runtime_bin_dir/$component"
done
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

PATH="$fake_bin:$PATH" \
FAKE_MAKE_LOG="$log" \
OPENWRT_SDK="$sdk" \
OPENWRT_PACKAGE_EXT=ipk \
OPENWRT_HOSTCC=/usr/bin/cc \
CANDY_RUNTIME_BIN_DIR="$runtime_bin_dir" \
packaging/openwrt/build/package_gate.sh >/dev/null

test -f "$sdk/package/candy-client/candy.init"
test -f "$sdk/package/candy-client/candy.config"
test -f "$sdk/package/candy-client/candy-core-manager"
test -f "$sdk/package/luci-app-candy/Makefile"
grep -F -- "HOSTCC=/usr/bin/cc" "$log" >/dev/null
! grep -F 'cargo' "$root/packaging/openwrt/build/package_gate.sh" >/dev/null

printf '%s\n' "Candy OpenWrt package gate contract passed"
