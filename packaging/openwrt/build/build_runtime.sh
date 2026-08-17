#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
target=${1:-x86_64-unknown-linux-musl}
dist_root=${CANDY_OPENWRT_RUNTIME_DIST_DIR:-"$repo_root/dist/runtime/openwrt-client"}

case "$target" in
	x86_64-unknown-linux-musl)
		artifact_arch=x86_64
		if [ -z "${CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:-}" ]; then
			if command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then
				CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
			elif command -v musl-gcc >/dev/null 2>&1; then
				CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
			else
				printf '%s\n' "missing x86_64 musl C compiler" >&2
				exit 2
			fi
			export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER
		fi
		;;
	armv7-unknown-linux-musleabihf)
		artifact_arch=arm_cortex-a7_neon-vfpv4
		: "${CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER:=armv7l-linux-musleabihf-gcc}"
		export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER
		;;
	*)
		printf '%s\n' "unsupported OpenWrt Runtime target: $target" >&2
		exit 2
		;;
esac

cargo build --manifest-path "$repo_root/Cargo.toml" --release --locked \
	--package candy-netd --package candy-sdwan-agent --package candy-cloud-enroll --package candy-cloud-sync --target "$target"

command -v jq >/dev/null 2>&1 || {
	printf '%s\n' "jq is required to locate the Cargo target directory" >&2
	exit 2
}
target_root=$(cargo metadata --format-version 1 --no-deps --manifest-path "$repo_root/Cargo.toml" |
	jq -er '.target_directory')
[ -n "$target_root" ] || {
	printf '%s\n' "unable to determine Cargo target directory" >&2
	exit 2
}
binary="$target_root/$target/release/candy-netd"
[ -x "$binary" ] || {
	printf '%s\n' "candy-netd was not produced: $binary" >&2
	exit 1
}

stage="$dist_root/$artifact_arch"
mkdir -p "$stage"
install -m 0755 "$binary" "$stage/candy-netd"
agent_binary="$target_root/$target/release/candy-sdwan-agent"
[ -x "$agent_binary" ] || {
	printf '%s\n' "candy-sdwan-agent was not produced: $agent_binary" >&2
	exit 1
}
install -m 0755 "$agent_binary" "$stage/candy-sdwan-agent"
enroll_binary="$target_root/$target/release/candy-cloud-enroll"
[ -x "$enroll_binary" ] || {
	printf '%s\n' "candy-cloud-enroll was not produced: $enroll_binary" >&2
	exit 1
}
install -m 0755 "$enroll_binary" "$stage/candy-cloud-enroll"
sync_binary="$target_root/$target/release/candy-cloud-sync"
[ -x "$sync_binary" ] || { printf '%s\n' "candy-cloud-sync was not produced: $sync_binary" >&2; exit 1; }
install -m 0755 "$sync_binary" "$stage/candy-cloud-sync"

if command -v file >/dev/null 2>&1; then
	case "$target" in
		x86_64-unknown-linux-musl) file "$stage/candy-netd" | grep -Eq 'ELF.*x86-64' ;;
		armv7-unknown-linux-musleabihf) file "$stage/candy-netd" | grep -Eq 'ELF.*ARM' ;;
	*) false ;;
	esac || { printf '%s\n' "candy-netd has the wrong ELF architecture for $target" >&2; exit 1; }
	case "$target" in
		x86_64-unknown-linux-musl) file "$stage/candy-sdwan-agent" | grep -Eq 'ELF.*x86-64' ;;
		armv7-unknown-linux-musleabihf) file "$stage/candy-sdwan-agent" | grep -Eq 'ELF.*ARM' ;;
	esac || { printf '%s\n' "candy-sdwan-agent has the wrong ELF architecture for $target" >&2; exit 1; }
	case "$target" in
		x86_64-unknown-linux-musl) file "$stage/candy-cloud-enroll" | grep -Eq 'ELF.*x86-64' ;;
		armv7-unknown-linux-musleabihf) file "$stage/candy-cloud-enroll" | grep -Eq 'ELF.*ARM' ;;
	esac || { printf '%s\n' "candy-cloud-enroll has the wrong ELF architecture for $target" >&2; exit 1; }
	case "$target" in
		x86_64-unknown-linux-musl) file "$stage/candy-cloud-sync" | grep -Eq 'ELF.*x86-64' ;;
		armv7-unknown-linux-musleabihf) file "$stage/candy-cloud-sync" | grep -Eq 'ELF.*ARM' ;;
	esac || { printf '%s\n' "candy-cloud-sync has the wrong ELF architecture for $target" >&2; exit 1; }
fi

printf '%s\n' "$stage"
