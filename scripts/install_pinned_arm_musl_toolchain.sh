#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=armv7l-linux-musleabihf-cross
archive="$root/.toolchains/$version.tgz"
directory="$root/.toolchains/$version"
repository=reTsubasa/candy-core
release_tag=build-toolchain-musl-gcc-11.2.1
expected_sha256=f49f1a15ec62364ef5e4edb4e3990c0e1d2d1a54c90153b8f3869dad63328a10
mkdir -p "$root/.toolchains"
if [ ! -s "$archive" ]; then
	command -v gh >/dev/null 2>&1 || { echo "gh is required to download the pinned ARM toolchain" >&2; exit 1; }
	[ -n "${GH_TOKEN:-}" ] || { echo "GH_TOKEN is required to download the pinned ARM toolchain" >&2; exit 1; }
	gh release download "$release_tag" --repo "$repository" --pattern "$version.tgz" --dir "$root/.toolchains"
fi
actual_sha256=$(sha256sum "$archive" | awk '{print tolower($1)}')
[ "$actual_sha256" = "$expected_sha256" ] || { echo "ARM musl toolchain checksum mismatch" >&2; exit 1; }
if [ ! -x "$directory/bin/armv7l-linux-musleabihf-gcc" ]; then
	rm -rf "$directory" "$root/.toolchains/.arm-extract"
	mkdir -p "$root/.toolchains/.arm-extract"
	tar -xzf "$archive" -C "$root/.toolchains/.arm-extract"
	extracted=$(find "$root/.toolchains/.arm-extract" -mindepth 1 -maxdepth 1 -type d | head -1)
	[ -n "$extracted" ] || exit 1
	mv "$extracted" "$directory"
	rm -rf "$root/.toolchains/.arm-extract"
fi
for tool in gcc g++ ar ranlib strip; do
	[ -x "$directory/bin/armv7l-linux-musleabihf-$tool" ] || { echo "missing ARM tool: $tool" >&2; exit 1; }
done
printf '%s\n' "$directory/bin"
