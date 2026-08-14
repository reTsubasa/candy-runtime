#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
runtime_bin_dir=${CANDY_RUNTIME_BIN_DIR:-}
cache_dir=${OPENWRT_SDK_CACHE:-"$repo_root/.openwrt-sdk-cache"}
image=${OPENWRT_SDK_CONTAINER_IMAGE:-candy-openwrt-sdk-gate:bookworm-v6}
base_image=${OPENWRT_SDK_CONTAINER_BASE_IMAGE:-debian:bookworm}
no_build=${OPENWRT_SDK_CONTAINER_NO_BUILD:-0}
download_base=${OPENWRT_DOWNLOAD_BASE:-https://downloads.openwrt.org}
official_download_base=https://downloads.openwrt.org

[ -n "$runtime_bin_dir" ] && [ -x "$runtime_bin_dir/candy-netd" ] && [ -x "$runtime_bin_dir/candy-sdwan-agent" ] || {
  printf '%s\n' "CANDY_RUNTIME_BIN_DIR must contain runtime-owned candy-netd and candy-sdwan-agent" >&2
  exit 2
}

usage() {
  printf '%s\n' "usage: $0 ipk|apk [x86_64|ipq40xx-generic|mediatek-filogic|bcm27xx-bcm2711|sdk-url]" >&2
}

package_ext=${1:-}
profile_or_url=${2:-x86_64}
case "$package_ext" in
  ipk)
    default_openwrt_release=24.10.7
    default_gcc_version=13.3.0
    ;;
  apk)
    default_openwrt_release=25.12.4
    default_gcc_version=14.3.0
    ;;
  *)
    usage
    exit 1
    ;;
esac

openwrt_release=${OPENWRT_RELEASE:-$default_openwrt_release}
gcc_version=${OPENWRT_GCC_VERSION:-$default_gcc_version}
case "$openwrt_release" in
  ''|*[!0-9.]*)
    printf '%s\n' "OPENWRT_RELEASE must contain only digits and dots, got: $openwrt_release" >&2
    exit 2
    ;;
esac
case "$gcc_version" in
  ''|*[!0-9.]*)
    printf '%s\n' "OPENWRT_GCC_VERSION must contain only digits and dots, got: $gcc_version" >&2
    exit 2
    ;;
esac

profile=$profile_or_url
sdk_path=
case "$profile_or_url" in
  x86_64|x86-64|x86/64)
    profile=x86_64
    target_arch=x86_64
    sdk_path="releases/$openwrt_release/targets/x86/64/openwrt-sdk-$openwrt_release-x86-64_gcc-$gcc_version"_musl.Linux-x86_64.tar.zst
    ;;
  mediatek-filogic|mediatek/filogic)
    profile=mediatek-filogic
    target_arch=aarch64
    sdk_path="releases/$openwrt_release/targets/mediatek/filogic/openwrt-sdk-$openwrt_release-mediatek-filogic_gcc-$gcc_version"_musl.Linux-x86_64.tar.zst
    ;;
  ipq40xx-generic|ipq40xx/generic)
    profile=ipq40xx-generic
    target_arch=arm
    sdk_path="releases/$openwrt_release/targets/ipq40xx/generic/openwrt-sdk-$openwrt_release-ipq40xx-generic_gcc-$gcc_version"_musl_eabi.Linux-x86_64.tar.zst
    ;;
  bcm27xx-bcm2711|bcm27xx/bcm2711)
    profile=bcm27xx-bcm2711
    target_arch=aarch64
    sdk_path="releases/$openwrt_release/targets/bcm27xx/bcm2711/openwrt-sdk-$openwrt_release-bcm27xx-bcm2711_gcc-$gcc_version"_musl.Linux-x86_64.tar.zst
    ;;
  http://*|https://*)
    profile=custom
    target_arch=${OPENWRT_TARGET_ARCH:-}
    sdk_url=$profile_or_url
    ;;
  *)
    printf '%s\n' "unknown OpenWrt profile: $profile_or_url" >&2
    usage
    exit 1
    ;;
esac

if [ -n "$sdk_path" ]; then
  sdk_url="$download_base/$sdk_path"
  fallback_sdk_url="$official_download_base/$sdk_path"
else
  fallback_sdk_url=
fi

dist_dir=${OPENWRT_DIST_DIR:-"$repo_root/dist/openwrt/$profile/$package_ext"}

docker info >/dev/null 2>&1 || {
  printf '%s\n' "Docker daemon is not available; start Docker and rerun: $0 $package_ext" >&2
  exit 2
}

mkdir -p "$cache_dir" "$dist_dir"
archive="$cache_dir/$(basename "$sdk_url")"
sdk_root="$cache_dir/${archive##*/}"
sdk_root=${sdk_root%.tar.zst}
sdk_root=${sdk_root%.tar.xz}
sdk_root=${sdk_root%.tgz}
sdk_root=${sdk_root%.tar.gz}

if [ ! -s "$archive" ]; then
  if ! curl -L --fail --output "$archive" "$sdk_url"; then
    rm -f "$archive"
    if [ -n "$fallback_sdk_url" ] && [ "$fallback_sdk_url" != "$sdk_url" ]; then
      sdk_url=$fallback_sdk_url
      archive="$cache_dir/$(basename "$sdk_url")"
      sdk_root="$cache_dir/${archive##*/}"
      sdk_root=${sdk_root%.tar.zst}
      sdk_root=${sdk_root%.tar.xz}
      sdk_root=${sdk_root%.tgz}
      sdk_root=${sdk_root%.tar.gz}
      curl -L --fail --output "$archive" "$sdk_url"
    else
      exit 1
    fi
  fi
fi

if [ ! -f "$sdk_root/rules.mk" ]; then
  rm -rf "$sdk_root"
  tmp_extract="$cache_dir/extract-$$"
  rm -rf "$tmp_extract"
  mkdir -p "$tmp_extract"
  case "$archive" in
    *.tar.zst) tar --zstd -xf "$archive" -C "$tmp_extract" ;;
    *.tar.xz) tar -xJf "$archive" -C "$tmp_extract" ;;
    *.tar.gz|*.tgz) tar -xzf "$archive" -C "$tmp_extract" ;;
    *)
      printf '%s\n' "unsupported SDK archive format: $archive" >&2
      rm -rf "$tmp_extract"
      exit 1
      ;;
  esac
  extracted=$(find "$tmp_extract" -mindepth 1 -maxdepth 1 -type d | head -n 1)
  if [ -z "$extracted" ]; then
    printf '%s\n' "SDK archive did not contain a directory: $archive" >&2
    rm -rf "$tmp_extract"
    exit 1
  fi
  mv "$extracted" "$sdk_root"
  rm -rf "$tmp_extract"
fi

if [ ! -f "$sdk_root/rules.mk" ]; then
  printf '%s\n' "OpenWrt SDK extraction missing rules.mk: $sdk_root" >&2
  exit 1
fi

run_image=$image
if ! docker image inspect "$run_image" >/dev/null 2>&1; then
  image_id=$(docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | awk -v image="$image" '$1 == image { print $2; exit }')
  if [ -n "$image_id" ] && docker image inspect "$image_id" >/dev/null 2>&1; then
    run_image=$image_id
  fi
fi

if ! docker image inspect "$run_image" >/dev/null 2>&1; then
  if [ "$no_build" = "1" ]; then
    printf '%s\n' "OpenWrt SDK container image is missing and auto-build is disabled: $image" >&2
    exit 1
  fi
  docker build --platform linux/amd64 \
    --build-arg BASE_IMAGE="$base_image" \
    -t "$image" \
    -f - "$repo_root" <<'EOF'
ARG BASE_IMAGE=debian:bookworm
FROM ${BASE_IMAGE}

SHELL ["/bin/sh", "-eu", "-c"]

RUN install_deps() { \
      apt-get -o Acquire::Retries=5 update && \
      DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 install -y --fix-missing --no-install-recommends \
        ca-certificates build-essential curl file gawk git libncurses-dev \
        python3 python3-distutils rsync unzip wget zstd; \
    }; \
    set_sources() { \
      mirror="$1"; \
      security_mirror="$2"; \
      sed -i "s|http://deb.debian.org/debian|$mirror|g; s|http://deb.debian.org/debian-security|$security_mirror|g" /etc/apt/sources.list.d/debian.sources; \
    }; \
    install_with_retries() { \
      attempts=0; \
      while [ "$attempts" -lt 4 ]; do \
        if install_deps; then \
          return 0; \
        fi; \
        attempts=$((attempts + 1)); \
        apt-get clean; \
        sleep "$attempts"; \
      done; \
      return 1; \
    }; \
    install_with_retries || { \
      set_sources http://ftp.us.debian.org/debian http://security.debian.org/debian-security; \
      apt-get clean; \
      install_with_retries; \
    } || { \
      set_sources http://mirrors.kernel.org/debian http://mirrors.kernel.org/debian-security; \
      apt-get clean; \
      install_with_retries; \
    }; \
    rm -rf /var/lib/apt/lists/*
EOF
fi

docker run --rm --platform linux/amd64 \
  -e OPENWRT_SDK=/openwrt-sdk \
  -e OPENWRT_PACKAGE_EXT="$package_ext" \
  -e OPENWRT_TARGET_ARCH="$target_arch" \
  -e OPENWRT_RELEASE="$openwrt_release" \
  -e OPENWRT_GCC_VERSION="$gcc_version" \
  -e OPENWRT_SDK_URL="$sdk_url" \
  -e OPENWRT_PROFILE="$profile" \
  -e FORCE="${FORCE:-0}" \
  -v "$repo_root:/workspace" \
  -v "$runtime_bin_dir:/runtime-bin:ro" \
  -v "$sdk_root:/openwrt-sdk" \
  -v "$dist_dir:/dist" \
  -w /workspace \
  "$run_image" \
  sh -eu -c '
    rm -f /dist/candy-client-*.apk /dist/candy-client_*.ipk \
      /dist/luci-app-candy*.apk /dist/luci-app-candy*.ipk \
      /dist/BUILD-INFO /dist/SHA256SUMS
    rm -rf /tmp/workspace /tmp/openwrt-sdk
    mkdir -p /tmp/workspace /tmp/openwrt-sdk
    rsync -a --delete \
      --exclude .git \
      --exclude .openwrt-sdk-cache \
      --exclude target \
      --exclude dist \
      /workspace/ /tmp/workspace/
    rsync -a --delete /openwrt-sdk/ /tmp/openwrt-sdk/
    if [ "${FORCE:-0}" = "1" ]; then
      mkdir -p /tmp/openwrt-sdk/staging_dir/host
      touch /tmp/openwrt-sdk/staging_dir/host/.prereq-build
    fi
    cd /tmp/workspace
    OPENWRT_SDK=/tmp/openwrt-sdk OPENWRT_PACKAGE_EXT="$OPENWRT_PACKAGE_EXT" \
      OPENWRT_TARGET_ARCH="$OPENWRT_TARGET_ARCH" \
      CANDY_RUNTIME_BIN_DIR=/runtime-bin OPENWRT_HOSTCC=/usr/bin/gcc \
      packaging/openwrt/build/package_gate.sh
    case "$OPENWRT_PACKAGE_EXT" in
      ipk) artifact_pattern="candy-client_*.ipk" ;;
      apk) artifact_pattern="candy-client-*.apk" ;;
      *) exit 1 ;;
    esac
    find /tmp/openwrt-sdk/bin/packages -name "$artifact_pattern" -type f -size +0c -exec cp {} /dist/ \;
    find /tmp/openwrt-sdk/bin/packages -name "luci-app-candy*.$OPENWRT_PACKAGE_EXT" -type f -size +0c -exec cp {} /dist/ \;
    find /dist -name "$artifact_pattern" -type f -size +0c | grep -q .
    find /dist -name "luci-app-candy*.$OPENWRT_PACKAGE_EXT" -type f -size +0c | grep -q .
    if [ "$OPENWRT_PACKAGE_EXT" = apk ]; then
      set -- /dist/candy-client-*.apk
      [ "$#" -eq 1 ] && [ -f "$1" ] || { echo "expected exactly one candy-client APK" >&2; exit 1; }
      client_apk=$1
      set -- /dist/luci-app-candy*.apk
      [ "$#" -eq 1 ] && [ -f "$1" ] || { echo "expected exactly one luci-app-candy APK" >&2; exit 1; }
      luci_apk=$1
      apk_tool=/tmp/openwrt-sdk/staging_dir/host/bin/apk
      [ -x "$apk_tool" ] || { echo "OpenWrt SDK host apk tool is missing" >&2; exit 1; }
      payload=$(mktemp -d)
      mkdir -p "$payload/client" "$payload/luci"
      "$apk_tool" extract --allow-untrusted --no-chown --destination "$payload/client" "$client_apk" >/dev/null
      "$apk_tool" extract --allow-untrusted --no-chown --destination "$payload/luci" "$luci_apk" >/dev/null
      for executable in \
        "$payload/client/etc/init.d/candy" \
        "$payload/client/usr/bin/candy-netd" \
        "$payload/client/usr/bin/candy-sdwan-agent" \
        "$payload/client/usr/libexec/candy-cloud-enroll"; do
        [ -x "$executable" ] || { echo "OpenWrt package is missing executable ${executable#$payload/}" >&2; exit 1; }
      done
      for asset in \
        "$payload/luci/usr/lib/lua/luci/controller/candy.lua" \
        "$payload/luci/usr/lib/lua/luci/view/candy/status.htm" \
        "$payload/luci/usr/lib/lua/luci/view/candy/sdwan.htm"; do
        [ -s "$asset" ] || { echo "OpenWrt package is missing LuCI asset ${asset#$payload/}" >&2; exit 1; }
      done
    fi
    {
      printf "openwrt_release=%s\n" "$OPENWRT_RELEASE"
      printf "gcc_version=%s\n" "$OPENWRT_GCC_VERSION"
      printf "profile=%s\n" "$OPENWRT_PROFILE"
      printf "package_format=%s\n" "$OPENWRT_PACKAGE_EXT"
      printf "sdk_url=%s\n" "$OPENWRT_SDK_URL"
    } > /dist/BUILD-INFO
    (cd /dist && sha256sum candy-client*.$OPENWRT_PACKAGE_EXT \
      luci-app-candy*.$OPENWRT_PACKAGE_EXT > SHA256SUMS)
  '

printf '%s\n' "OpenWrt $openwrt_release $package_ext package exported: $dist_dir"
