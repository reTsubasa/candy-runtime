#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-linux-server-package-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() {
	printf '%s\n' "server_package_test: $*" >&2
	exit 1
}

fake_bin=$tmp/bin
mkdir -p "$fake_bin"
cat >"$fake_bin/cargo" <<'EOF'
#!/bin/sh
printf '%s\n' "Runtime server package must not build or fetch Core source" >&2
exit 99
EOF
chmod 0755 "$fake_bin/cargo"

dist=$tmp/dist
PATH="$fake_bin:$PATH" CANDY_LINUX_DIST_DIR="$dist" \
	"$root/packaging/linux/build.sh" x86_64-unknown-linux-gnu >/dev/null

stage=$dist/server/x86_64
[ -x "$stage/usr/local/bin/serverd-linux" ] || fail "server launcher was not staged"
[ -f "$stage/etc/candy/server.toml.example" ] || fail "server example config was not staged"
[ -f "$stage/systemd/candy-server.service" ] || fail "systemd unit was not staged"
[ -x "$stage/install/install-candy-server.sh" ] || fail "installer was not staged"
[ -x "$dist/serverd-linux-x86_64" ] || fail "release launcher artifact was not staged"
cmp "$root/linux/server/apps/candy-server/serverd-linux" \
	"$stage/usr/local/bin/serverd-linux" >/dev/null || fail "staged launcher differs from source"

if find "$dist" -type f \( -name 'candy-core' -o -name 'libcandy_core.so' \) | grep -q .; then
	fail "private Core artifact leaked into Runtime package"
fi
if rg -n 'cargo (build|install)|git (clone|fetch)|crates/candy-core' \
	"$root/packaging/linux/build.sh" "$stage/usr/local/bin/serverd-linux" >/dev/null; then
	fail "server package still builds or fetches Core source"
fi

if CANDY_LINUX_DIST_DIR="$tmp/invalid" \
	"$root/packaging/linux/build.sh" riscv64-unknown-linux-gnu >"$tmp/invalid.out" 2>&1; then
	fail "unsupported release target unexpectedly succeeded"
fi
grep -F "unsupported Linux server release target" "$tmp/invalid.out" >/dev/null ||
	fail "unsupported target error is not actionable"

printf '%s\n' "Candy Linux server Runtime package test passed"
