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
	CANDY_RELEASE_VERSION=0.4.0 CANDY_RELEASE_REVISION=57 \
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
grep -F 'LAUNCHER=${CANDY_SERVER_LAUNCHER:-/opt/candy/current/candy-server}' \
	"$stage/usr/local/bin/candy-core-manager" >/dev/null ||
	fail "Core manager does not use the stable current release launcher"
grep -F 'ExecStart=/opt/candy/current/candy-server --config /etc/candy/server.toml' \
	"$stage/systemd/candy-server.service" >/dev/null ||
	fail "server unit does not use the stable current release launcher"
[ -x "$stage/usr/local/libexec/candy-server-health-check" ] || fail "server health check was not staged"
[ -f "$stage/etc/candy/server.toml.example" ] || fail "server example config was not staged"
[ -f "$stage/etc/candy/cloud-sync.env.example" ] || fail "server Cloud sync endpoint example was not staged"
[ -f "$stage/systemd/candy-server.service" ] || fail "systemd unit was not staged"
[ -f "$stage/systemd/candy-netd.service" ] || fail "server netd unit was not staged"
[ -f "$stage/systemd/candy-cloud-sync.service" ] || fail "server Cloud sync unit was not staged"
[ ! -e "$stage/systemd/candy-sdwan.service" ] || fail "server package must not stage a second SD-WAN service"
[ -x "$stage/install/install-candy-server.sh" ] || fail "installer was not staged"
[ -x "$stage/install/upgrade-candy-server.sh" ] || fail "full Runtime upgrader was not staged"
[ "$(cat "$stage/RUNTIME-RELEASE")" = 0.4.0-r57 ] || fail "server bundle release identity is missing or invalid"
[ "$(cat "$stage/RUNTIME-ARCH")" = x86_64 ] || fail "server bundle architecture identity is missing or invalid"
[ "$(cat "$edge_stage/RUNTIME-RELEASE")" = 0.4.0-r57 ] || fail "edge bundle release identity is missing or invalid"
[ "$(cat "$edge_stage/RUNTIME-ARCH")" = x86_64 ] || fail "edge bundle architecture identity is missing or invalid"
[ -x "$dist/candy-server-x86_64" ] || fail "product release launcher artifact was not staged"
[ -s "$dist/candy-server-runtime-x86_64.tar.gz" ] || fail "complete server Runtime bundle was not staged"
grep -F -- '--no-xattrs' "$tmp/tar.args" >/dev/null || fail "server Runtime bundle does not suppress host extended attributes"
tar -tzf "$dist/candy-server-runtime-x86_64.tar.gz" | grep -F './usr/local/libexec/candy-cloud-enroll' >/dev/null ||
	fail "server Runtime bundle does not contain Cloud enrollment"
tar -tzf "$dist/candy-server-runtime-x86_64.tar.gz" | grep -F './usr/local/libexec/candy-cloud-sync' >/dev/null ||
	fail "server Runtime bundle does not contain Cloud synchronization"
tar -tzf "$dist/candy-server-runtime-x86_64.tar.gz" | grep -F './RUNTIME-RELEASE' >/dev/null ||
	fail "server Runtime bundle does not contain immutable release identity"
tar -tzf "$dist/candy-server-runtime-x86_64.tar.gz" | grep -F './RUNTIME-ARCH' >/dev/null ||
	fail "server Runtime bundle does not contain architecture identity"
if tar -tzf "$dist/candy-server-runtime-x86_64.tar.gz" | grep -F './systemd/candy-sdwan.service' >/dev/null; then
	fail "server Runtime bundle contains a duplicate SD-WAN service"
fi
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
grep -F 'OnActiveSec=15s' "$edge_stage/systemd/candy-cloud-sync.timer" >/dev/null ||
	fail "Cloud synchronization timer has no post-upgrade first trigger"
grep -F 'OnUnitInactiveSec=30s' "$edge_stage/systemd/candy-cloud-sync.timer" >/dev/null ||
	fail "Cloud synchronization timer has the wrong cadence"
if grep -F 'OnUnitActiveSec=' "$edge_stage/systemd/candy-cloud-sync.timer" >/dev/null; then
	fail "Cloud synchronization timer still depends on a pre-upgrade service activation"
fi
grep -F 'Requires=candy-netd.service' "$edge_stage/systemd/candy-sdwan.service" >/dev/null || fail "SD-WAN unit does not require netd"
grep -F 'BindsTo=candy-netd.service' "$edge_stage/systemd/candy-sdwan.service" >/dev/null || fail "SD-WAN unit is not bound to netd"
grep -F -- '--recover --journal' "$edge_stage/systemd/candy-netd.service" >/dev/null || fail "netd unit has no real orphan recovery hook"
grep -F 'ExecStart=/usr/local/libexec/candy-client' "$edge_stage/systemd/candy-client.service" >/dev/null ||
	fail "Linux Edge service exposes a private data-plane command"
grep -F 'ExecStopPost=+/usr/local/libexec/candy-sdwan-runtime fail-open' "$edge_stage/systemd/candy-sdwan.service" >/dev/null ||
	fail "Linux Edge SD-WAN service has no fail-open lifecycle hook"
grep -F 'ConditionPathIsSymbolicLink=/var/lib/candy/sdwan/candidate' "$edge_stage/systemd/candy-sdwan.service" >/dev/null ||
	fail "Linux Edge SD-WAN service starts without a Cloud candidate"
if grep -F 'ConditionPathExists=/etc/candy/sdwan-agent.env' "$edge_stage/systemd/candy-sdwan.service" >/dev/null; then
	fail "Linux Edge SD-WAN activation requires an example-only environment file"
fi
grep -F 'EnvironmentFile=-/etc/candy/sdwan-agent.env' "$edge_stage/systemd/candy-sdwan.service" >/dev/null ||
	fail "Linux Edge SD-WAN service does not support optional deployment overrides"
grep -F 'Environment=CANDY_CORE_BIN=/opt/candy/cores/current/candy-core' "$edge_stage/systemd/candy-sdwan.service" >/dev/null ||
	fail "Linux Edge SD-WAN service has no product Core default"
grep -F 'Restart=no' "$edge_stage/systemd/candy-sdwan.service" >/dev/null ||
	fail "Linux Edge SD-WAN service can loop on a rejected candidate"
grep -F 'ExecStartPost=+/usr/local/libexec/candy-sdwan-runtime reconcile candy-sdwan.service' "$edge_stage/systemd/candy-cloud-sync.service" >/dev/null ||
	fail "Linux Edge Cloud sync does not reconcile candidate lifecycle changes"
grep -F 'project-local-runtime-status' "$edge_stage/usr/local/libexec/candy-sdwan-runtime" >/dev/null ||
	fail "Linux Edge reconciliation does not publish verified product status"
grep -F 'candy-sdwan-agent --socket ${CANDY_NETD_SOCKET}' "$edge_stage/systemd/candy-sdwan.service" >/dev/null ||
	fail "Linux Edge SD-WAN service does not place agent options before the run subcommand"
if grep -F 'candy-sdwan-agent run --socket' "$edge_stage/systemd/candy-sdwan.service" >/dev/null; then
	fail "Linux Edge SD-WAN service does not use the canonical agent argument order"
fi
grep -F -- '--allowed-user candy --allowed-group candy' "$stage/systemd/candy-netd.service" >/dev/null ||
	fail "server netd socket is not bound to the Candy server identity"
grep -F -- '--server-config /etc/candy/server.toml' "$stage/systemd/candy-cloud-sync.service" >/dev/null ||
	fail "server Cloud sync does not request a server activation"
grep -F 'EnvironmentFile=-/etc/candy/cloud-sync.env' "$stage/systemd/candy-cloud-sync.service" >/dev/null ||
	fail "server Cloud sync does not load the persisted public endpoint"
grep -F 'CANDY_PUBLIC_ENDPOINT=203.0.113.10:8443' "$stage/etc/candy/cloud-sync.env.example" >/dev/null ||
	fail "server package has no valid public endpoint example"
grep -F 'ExecStartPost=+/usr/local/libexec/candy-sdwan-runtime reconcile candy-server.service' "$stage/systemd/candy-cloud-sync.service" >/dev/null ||
	fail "server Cloud sync does not reconcile candidate lifecycle changes"
grep -F 'Environment=CANDY_SDWAN_SERVICE_USER=candy' "$stage/systemd/candy-cloud-sync.service" >/dev/null ||
	fail "server Cloud reconciliation does not retain the candy service identity"
grep -F 'Wants=network-online.target candy-netd.service' "$stage/systemd/candy-server.service" >/dev/null ||
	fail "ordinary server does not order optional netd startup"
if grep -Eq 'Requires=candy-netd|BindsTo=candy-netd|candy-sdwan\.service' "$stage/systemd/candy-server.service"; then
	fail "ordinary server is incorrectly coupled to optional SD-WAN infrastructure"
fi
grep -F 'CONGESTION_TEST_BYTES=52428800' "$stage/install/install-candy-server.sh" >/dev/null ||
	fail "server installer does not provision the 50 MiB congestion test object"
grep -F -- '--public-endpoint' "$stage/install/install-candy-server.sh" >/dev/null ||
	fail "server installer does not accept an explicit public endpoint"
grep -F "CANDY_PUBLIC_ENDPOINT=%s" "$stage/install/install-candy-server.sh" >/dev/null ||
	fail "server installer does not persist the public endpoint"
grep -F 'Z /var/lib/candy/sdwan - candy candy -' "$stage/systemd/candy.tmpfiles" >/dev/null ||
	fail "server package does not migrate existing SD-WAN state to the candy service identity"
grep -F 'd /var/lib/candy 0711 root root -' "$stage/systemd/candy.tmpfiles" >/dev/null ||
	fail "server package exposes the root netd journal through a candy-owned state root"
grep -F 'chown root:root "$STATE_DIR"' "$stage/install/install-candy-server.sh" >/dev/null ||
	fail "server installer does not protect the shared state root"
if grep -F 'chown "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"' "$stage/install/install-candy-server.sh" >/dev/null; then
	fail "server installer delegates the root netd journal directory to candy"
fi
grep -F 'find "$sdwan_state" -xdev -type f -exec chmod 0600' "$stage/install/install-candy-server.sh" >/dev/null ||
	fail "server installer does not protect migrated SD-WAN state files"
grep -F 'Z /var/lib/candy/sdwan - candy-sdwan candy-sdwan -' "$edge_stage/systemd/candy.tmpfiles" >/dev/null ||
	fail "Linux Edge package does not migrate existing SD-WAN state to its service identity"
grep -F 'd /var/lib/candy 0711 root root -' "$edge_stage/systemd/candy.tmpfiles" >/dev/null ||
	fail "Linux Edge package has an unsafe shared state root"
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
