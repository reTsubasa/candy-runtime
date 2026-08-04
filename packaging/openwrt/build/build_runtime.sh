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
	*)
		printf '%s\n' "unsupported initial OpenWrt Runtime target: $target" >&2
		exit 2
		;;
esac

cargo build --manifest-path "$repo_root/Cargo.toml" --release --locked \
	--package candy-netd --target "$target"

binary="$repo_root/target/$target/release/candy-netd"
[ -x "$binary" ] || {
	printf '%s\n' "candy-netd was not produced: $binary" >&2
	exit 1
}

stage="$dist_root/$artifact_arch"
mkdir -p "$stage"
install -m 0755 "$binary" "$stage/candy-netd"

if command -v file >/dev/null 2>&1; then
	file "$stage/candy-netd" | grep -Eq 'ELF.*x86-64' || {
		printf '%s\n' "candy-netd is not an x86_64 Linux ELF" >&2
		exit 1
	}
fi

printf '%s\n' "$stage"
