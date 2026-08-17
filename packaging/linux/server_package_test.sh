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
real_tar=$(command -v tar)
cat >"$fake_bin/cargo" <<'EOF'
#!/bin/sh
printf '%s\n' "Runtime server package must not build or fetch Core source" >&2
exit 99
EOF
chmod 0755 "$fake_bin/cargo"
cat >"$fake_bin/tar" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>'$tmp/tar.args'
exec '$real_tar' "\$@"
EOF
chmod 0755 "$fake_bin/tar"

dist=$tmp/dist
agent=$tmp/candy-sdwan-agent
printf '#!/bin/sh\nexit 0\n' >"$agent"
chmod 0755 "$agent"
netd=$tmp/candy-netd
printf '#!/bin/sh\nexit 0\n' >"$netd"
chmod 0755 "$netd"
enroll=$tmp/candy-cloud-enroll
printf '#!/bin/sh\nexit 0\n' >"$enroll"
chmod 0755 "$enroll"
sync=$tmp/candy-cloud-sync
printf '#!/bin/sh\nexit 0\n' >"$sync"
chmod 0755 "$sync"
PATH="$fake_bin:$PATH" CANDY_LINUX_DIST_DIR="$dist" CANDY_SDWAN_AGENT_BINARY="$agent" \
	CANDY_NETD_BINARY="$netd" \
	CANDY_CLOUD_ENROLL_BINARY="$enroll" \
	CANDY_CLOUD_SYNC_BINARY="$sync" \
	"$root/packaging/linux/build.sh" x86_64-unknown-linux-gnu >/dev/null

stage=$dist/server/x86_64
edge_stage=$dist/client/x86_64
[ -x "$stage/usr/local/bin/candy-server" ] || fail "public candy-server command was not staged"
[ -x "$stage/usr/local/libexec/serverd-linux" ] || fail "internal compatibility launcher was not staged"
[ -x "$stage/usr/local/libexec/candy-sdwan-runtime" ] || fail "SD-WAN Runtime helper was not staged"
[ -x "$stage/usr/local/libexec/candy-sdwan-agent" ] || fail "server SD-WAN agent was not staged"
[ -x "$stage/usr/local/libexec/candy-netd" ] || fail "server netd was not staged"
[ -x "$stage/usr/local/libexec/candy-cloud-enroll" ] || fail "server Cloud enrollment client was not staged"
[ -x "$stage/usr/local/libexec/candy-cloud-sync" ] || fail "server Cloud Runtime synchronizer was not staged"
[ -x "$stage/usr/local/bin/candy-core-manager" ] || fail "Core bundle manager was not staged"
[ -x "$stage/usr/local/libexec/candy-server-health-check" ] || fail "server health check was not staged"
[ -f "$stage/etc/candy/server.toml.example" ] || fail "server example config was not staged"
[ -f "$stage/systemd/candy-server.service" ] || fail "systemd unit was not staged"
[ -x "$stage/install/install-candy-server.sh" ] || fail "installer was not staged"
[ -x "$dist/candy-server-x86_64" ] || fail "product release launcher artifact was not staged"
[ -s "$dist/candy-server-runtime-x86_64.tar.gz" ] || fail "complete server Runtime bundle was not staged"
grep -F -- '--no-xattrs' "$tmp/tar.args" >/dev/null || fail "server Runtime bundle does not suppress host extended attributes"
tar -tzf "$dist/candy-server-runtime-x86_64.tar.gz" | grep -F './usr/local/libexec/candy-cloud-enroll' >/dev/null ||
	fail "server Runtime bundle does not contain Cloud enrollment"
tar -tzf "$dist/candy-server-runtime-x86_64.tar.gz" | grep -F './usr/local/libexec/candy-cloud-sync' >/dev/null ||
	fail "server Runtime bundle does not contain Cloud synchronization"
if tar -tvzf "$dist/candy-server-runtime-x86_64.tar.gz" 2>&1 | grep -F 'LIBARCHIVE.xattr' >/dev/null; then
	fail "server Runtime bundle contains macOS extended attributes"
fi
cmp "$root/linux/server/apps/candy-server/candy-server" \
	"$stage/usr/local/bin/candy-server" >/dev/null || fail "staged product launcher differs from source"
[ -x "$edge_stage/usr/local/bin/candy" ] || fail "public Linux Edge candy command was not staged"
[ -x "$edge_stage/usr/local/libexec/candy-client" ] || fail "private Linux Edge process launcher was not staged"
[ -x "$edge_stage/usr/local/libexec/candy-sdwan-runtime" ] || fail "Linux Edge SD-WAN Runtime helper was not staged"
[ -x "$edge_stage/usr/local/libexec/candy-sdwan-agent" ] || fail "Linux Edge SD-WAN agent was not staged"
[ -x "$edge_stage/usr/local/libexec/candy-netd" ] || fail "Linux Edge netd was not staged"
[ -x "$edge_stage/usr/local/libexec/candy-cloud-enroll" ] || fail "Linux Edge Cloud enrollment client was not staged"
[ -x "$edge_stage/usr/local/libexec/candy-cloud-sync" ] || fail "Linux Edge Cloud Runtime synchronizer was not staged"
[ -f "$edge_stage/systemd/candy-client.service" ] || fail "Linux Edge systemd unit was not staged"
[ -f "$edge_stage/systemd/candy-netd.service" ] || fail "netd systemd unit was not staged"
[ -f "$edge_stage/systemd/candy-sdwan.service" ] || fail "SD-WAN systemd unit was not staged"
[ -f "$edge_stage/systemd/candy-cloud-sync.service" ] || fail "Cloud synchronization systemd unit was not staged"
[ -f "$edge_stage/systemd/candy-cloud-sync.timer" ] || fail "Cloud synchronization timer was not staged"
grep -F 'ConditionPathExists=/var/lib/candy/sdwan/identity/device-identity-v1.json' "$edge_stage/systemd/candy-cloud-sync.service" >/dev/null ||
	fail "Cloud synchronization does not wait for an enrolled identity"
grep -F 'OnUnitActiveSec=30s' "$edge_stage/systemd/candy-cloud-sync.timer" >/dev/null ||
	fail "Cloud synchronization timer has the wrong cadence"
grep -F 'Requires=candy-netd.service' "$edge_stage/systemd/candy-sdwan.service" >/dev/null || fail "SD-WAN unit does not require netd"
grep -F 'BindsTo=candy-netd.service' "$edge_stage/systemd/candy-sdwan.service" >/dev/null || fail "SD-WAN unit is not bound to netd"
grep -F -- '--recover --journal' "$edge_stage/systemd/candy-netd.service" >/dev/null || fail "netd unit has no real orphan recovery hook"
grep -F 'ExecStart=/usr/local/libexec/candy-client' "$edge_stage/systemd/candy-client.service" >/dev/null ||
	fail "Linux Edge service exposes a private data-plane command"
grep -F 'ExecStopPost=+/usr/local/libexec/candy-sdwan-runtime fail-open' "$edge_stage/systemd/candy-sdwan.service" >/dev/null ||
	fail "Linux Edge SD-WAN service has no fail-open lifecycle hook"
grep -F 'CONGESTION_TEST_BYTES=52428800' "$stage/install/install-candy-server.sh" >/dev/null ||
	fail "server installer does not provision the 50 MiB congestion test object"
grep -F 'dd if=/dev/zero' "$stage/install/install-candy-server.sh" >/dev/null ||
	fail "server installer does not generate congestion test data locally"

if find "$dist" -type f \( -name 'candy-core' -o -name 'libcandy_core.so' \) | grep -q .; then
	fail "private Core artifact leaked into Runtime package"
fi
if rg -n 'cargo (build|install)|git (clone|fetch)|crates/candy-core' \
	"$root/packaging/linux/build.sh" "$stage/usr/local/bin/candy-server" \
	"$stage/usr/local/bin/candy-core-manager" "$stage/usr/local/libexec/candy-server-health-check" >/dev/null; then
	fail "server package still builds or fetches Core source"
fi

if CANDY_LINUX_DIST_DIR="$tmp/invalid" \
	"$root/packaging/linux/build.sh" riscv64-unknown-linux-gnu >"$tmp/invalid.out" 2>&1; then
	fail "unsupported release target unexpectedly succeeded"
fi
grep -F "unsupported Linux server release target" "$tmp/invalid.out" >/dev/null ||
	fail "unsupported target error is not actionable"

printf '%s\n' "Candy Linux server Runtime package test passed"
