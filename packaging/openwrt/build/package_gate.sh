#!/bin/sh
set -eu

sdk=${OPENWRT_SDK:-}
runtime_bin_dir=${CANDY_RUNTIME_BIN_DIR:-}
target_arch=${OPENWRT_TARGET_ARCH:-}

if [ -z "$sdk" ]; then
  for candidate in "$PWD/openwrt-sdk" "$PWD/../openwrt-sdk"; do
    if [ -d "$candidate/include" ] && [ -f "$candidate/rules.mk" ]; then
      sdk=$candidate
      break
    fi
  done
fi

if [ -z "$sdk" ] || [ ! -f "$sdk/rules.mk" ] || [ ! -d "$sdk/package" ]; then
  printf '%s\n' "OpenWrt SDK is not available; set OPENWRT_SDK to an SDK root and rerun: $0" >&2
  exit 2
fi

[ -n "$runtime_bin_dir" ] && [ -x "$runtime_bin_dir/candy-netd" ] && [ -x "$runtime_bin_dir/candy-sdwan-agent" ] && [ -x "$runtime_bin_dir/candy-cloud-enroll" ] && [ -x "$runtime_bin_dir/candy-cloud-sync" ] || {
  printf '%s\n' "CANDY_RUNTIME_BIN_DIR must contain runtime-owned candy-netd, candy-sdwan-agent, candy-cloud-enroll and candy-cloud-sync" >&2
  exit 2
}

if [ -n "$target_arch" ] && command -v file >/dev/null 2>&1; then
  netd_file=$(file "$runtime_bin_dir/candy-netd")
  agent_file=$(file "$runtime_bin_dir/candy-sdwan-agent")
  enroll_file=$(file "$runtime_bin_dir/candy-cloud-enroll")
  sync_file=$(file "$runtime_bin_dir/candy-cloud-sync")
  for runtime_file in "$netd_file" "$agent_file" "$enroll_file" "$sync_file"; do
    case "$target_arch:$runtime_file" in
      x86_64:*ELF*x86-64*|aarch64:*ELF*aarch64*|aarch64:*ELF*ARM\ aarch64*|arm:*ELF*ARM*) ;;
      *)
        printf '%s\n' "Runtime executable does not match OpenWrt target $target_arch: $runtime_file" >&2
        exit 2
        ;;
    esac
  done
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
openwrt_hostcc=${OPENWRT_HOSTCC:-}
make_force=
[ "${FORCE:-0}" = "1" ] && make_force="FORCE=1"
pkg_dir="$sdk/package/candy-client"
rm -rf "$pkg_dir"
mkdir -p "$pkg_dir"
client_package="$repo_root/openwrt/client/packages/candy-client"
cp "$client_package/Makefile" "$pkg_dir/Makefile"
cp "$client_package/candy-client" "$pkg_dir/candy-client"
cp "$client_package/candy-sdwan" "$pkg_dir/candy-sdwan"
cp "$client_package/candy-cloud-sync.init" "$pkg_dir/candy-cloud-sync.init"
cp "$client_package/candy-cloud-sync-loop" "$pkg_dir/candy-cloud-sync-loop"
cp "$client_package/candy.init" "$pkg_dir/candy.init"
cp "$client_package/candy.config" "$pkg_dir/candy.config"
cp "$client_package/candy-core-manager" "$pkg_dir/candy-core-manager"
cp "$client_package/candy-update-manager" "$pkg_dir/candy-update-manager"
cp "$client_package/candy-runtime-health-check" "$pkg_dir/candy-runtime-health-check"
cp "$repo_root/linux/common/apps/candy-sdwan-runtime/candy-sdwan-runtime" "$pkg_dir/candy-sdwan-runtime"
cp "$runtime_bin_dir/candy-sdwan-agent" "$pkg_dir/candy-sdwan-agent"
cp "$runtime_bin_dir/candy-cloud-enroll" "$pkg_dir/candy-cloud-enroll"
cp "$runtime_bin_dir/candy-cloud-sync" "$pkg_dir/candy-cloud-sync"
chmod 0755 "$pkg_dir/candy-sdwan-runtime"
cp "$client_package/catalog-release.pub" "$pkg_dir/catalog-release.pub"
cp "$client_package/core-release.pub" "$pkg_dir/core-release.pub"
cp -R "$client_package/rulesets" "$pkg_dir/rulesets"
cp -R "$client_package/nftables" "$pkg_dir/nftables"

luci_pkg_dir="$sdk/package/luci-app-candy"
rm -rf "$luci_pkg_dir"
mkdir -p "$luci_pkg_dir"
cp -R "$repo_root/openwrt/client/packages/luci-app-candy/." "$luci_pkg_dir/"

write_minimal_package_config() {
  config_tmp="$sdk/.config.candy.$$"
  if [ -f "$sdk/.config" ]; then
    sed '/^CONFIG_PACKAGE_/d;/^# CONFIG_PACKAGE_.* is not set$/d' "$sdk/.config" >"$config_tmp"
  else
    : >"$config_tmp"
  fi
  {
    printf 'CONFIG_PACKAGE_%s=m\n' candy-client
    printf 'CONFIG_PACKAGE_%s=m\n' luci-app-candy
  } >>"$config_tmp"
  mv "$config_tmp" "$sdk/.config"
}

write_minimal_package_config
make -C "$sdk" defconfig $make_force
write_minimal_package_config
make -C "$sdk" package/candy-client/compile V=s NO_DEPS=1 \
  CANDY_RUNTIME_BIN_DIR="$runtime_bin_dir" $make_force
if [ -n "$openwrt_hostcc" ]; then
  make -C "$sdk" package/luci-app-candy/compile V=s NO_DEPS=1 \
    HOSTCC="$openwrt_hostcc" $make_force
else
  make -C "$sdk" package/luci-app-candy/compile V=s NO_DEPS=1 $make_force
fi

package_ext=${OPENWRT_PACKAGE_EXT:-}
if [ -z "$package_ext" ]; then
  if find "$sdk/bin/packages" -name 'candy-client_*.apk' -type f -size +0c | grep -q .; then
    package_ext=apk
  else
    package_ext=ipk
  fi
fi

case "$package_ext" in
  ipk|apk) ;;
  *)
    printf '%s\n' "OPENWRT_PACKAGE_EXT must be 'ipk' or 'apk', got: $package_ext" >&2
    exit 1
    ;;
esac

case "$package_ext" in
  ipk) artifact_pattern='candy-client_*.ipk' ;;
  apk) artifact_pattern='candy-client-*.apk' ;;
esac

artifact=$(find "$sdk/bin/packages" -name "$artifact_pattern" -type f -size +0c | head -n 1)
if [ -z "$artifact" ]; then
  printf '%s\n' "candy-client .$package_ext artifact was not produced under $sdk/bin/packages" >&2
  exit 1
fi
luci_artifact_pattern="luci-app-candy*.$package_ext"
luci_artifact=$(find "$sdk/bin/packages" -name "$luci_artifact_pattern" -type f -size +0c | head -n 1)
if [ -z "$luci_artifact" ]; then
  printf '%s\n' "luci-app-candy .$package_ext artifact was not produced under $sdk/bin/packages" >&2
  exit 1
fi

printf '%s\n' "$artifact"
printf '%s\n' "$luci_artifact"
printf '%s\n' "OpenWrt package gate passed ($package_ext)"
