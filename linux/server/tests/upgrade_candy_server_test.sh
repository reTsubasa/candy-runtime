#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
upgrader=$repo_root/linux/server/packaging/upgrade-candy-server.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-runtime-upgrade-test.XXXXXX")
cleanup() { find "$tmp" -type d -exec chmod u+rwx {} \; 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT HUP INT TERM
fail() { printf '%s\n' "upgrade_candy_server_test: $*" >&2; exit 1; }

fake_bin=$tmp/bin
fake_state=$tmp/systemd-state
fake_kernel=$tmp/kernel-state
host=$tmp/host
mkdir -p "$fake_bin" "$fake_state" "$fake_kernel" "$host/etc/candy/sdwan/identity" "$host/var/lib/candy" "$host/opt/candy/cores/current"
printf '%s\n' 212992 >"$fake_kernel/net.core.rmem_max"
printf '%s\n' 212992 >"$fake_kernel/net.core.wmem_max"

cat >"$fake_bin/id" <<'EOF'
#!/bin/sh
[ "${1:-}" = -u ] && { printf '%s\n' 0; exit 0; }
exit 1
EOF
cat >"$fake_bin/uname" <<'EOF'
#!/bin/sh
printf '%s\n' x86_64
EOF
cat >"$fake_bin/chown" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$fake_bin/systemd-tmpfiles" <<'EOF'
#!/bin/sh
printf 'tmpfiles %s\n' "$*" >>"$FAKE_SYSTEMD_LOG"
exit 0
EOF
cat >"$fake_bin/sysctl" <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
	-n)
		[ "$#" -eq 2 ]
		cat "$FAKE_KERNEL_STATE/$2"
		;;
	-w)
		[ "$#" -eq 2 ]
		key=${2%%=*}
		value=${2#*=}
		case "$value" in ''|*[!0-9]*) exit 2 ;; esac
		printf '%s=%s\n' "$key" "$value" >>"$FAKE_SYSCTL_LOG"
		if [ "${FAKE_SYSCTL_FAIL_KEY:-}" = "$key" ] && [ "${FAKE_SYSCTL_FAIL_VALUE:-}" = "$value" ]; then
			exit 1
		fi
		printf '%s\n' "$value" >"$FAKE_KERNEL_STATE/$key"
		printf '%s = %s\n' "$key" "$value"
		;;
	*) exit 2 ;;
esac
EOF
cat >"$fake_bin/systemctl" <<'EOF'
#!/bin/sh
set -eu
command=$1
shift || true
service=
for argument in "$@"; do service=$argument; done
printf '%s %s\n' "$command" "$*" >>"$FAKE_SYSTEMD_LOG"
case "$command" in
	is-enabled) [ "$(cat "$FAKE_SYSTEMD_STATE/$service.enabled" 2>/dev/null || printf 0)" = 1 ] ;;
	is-active) [ "$(cat "$FAKE_SYSTEMD_STATE/$service.active" 2>/dev/null || printf 0)" = 1 ] ;;
	enable) printf 1 >"$FAKE_SYSTEMD_STATE/$service.enabled" ;;
	disable) printf 0 >"$FAKE_SYSTEMD_STATE/$service.enabled" ;;
	start)
		if [ "$service" = candy-cloud-sync.service ]; then
			# Model the oneshot returning to inactive after a successful dispatch.
			printf 0 >"$FAKE_SYSTEMD_STATE/$service.active"
		else
			printf 1 >"$FAKE_SYSTEMD_STATE/$service.active"
		fi
		;;
	stop) printf 0 >"$FAKE_SYSTEMD_STATE/$service.active" ;;
	daemon-reload) : ;;
	*) printf '%s\n' "unexpected systemctl command: $command" >&2; exit 2 ;;
esac
EOF
chmod 0755 "$fake_bin"/*
: >"$tmp/sysctl.log"

services='candy-netd.service candy-server.service candy-cloud-sync.service candy-cloud-sync.timer'
reset_service_state() {
	: >"$tmp/systemd.log"
	for service in $services; do printf 0 >"$fake_state/$service.enabled"; printf 0 >"$fake_state/$service.active"; done
	for service in candy-netd.service candy-server.service candy-cloud-sync.timer; do printf 1 >"$fake_state/$service.enabled"; printf 1 >"$fake_state/$service.active"; done
}

managed_files='usr/local/bin/candy-core-manager
usr/local/libexec/serverd-linux
usr/local/libexec/candy-sdwan-runtime
usr/local/libexec/candy-sdwan-agent
usr/local/libexec/candy-netd
usr/local/libexec/candy-cloud-enroll
usr/local/libexec/candy-cloud-sync
usr/local/libexec/candy-server-health-check'
units='candy-server.service candy-netd.service candy-cloud-sync.service candy-cloud-sync.timer'

write_host_generation() {
	value=$1
	for relative in $managed_files; do
		mkdir -p "$host/$(dirname "$relative")"
		printf '#!/bin/sh\nprintf "%%s\\n" %s\n' "$value" >"$host/$relative"
		chmod 0755 "$host/$relative"
	done
	for unit in $units; do mkdir -p "$host/etc/systemd/system"; printf '%s\n' "$value-$unit" >"$host/etc/systemd/system/$unit"; done
	mkdir -p "$host/usr/lib/tmpfiles.d"
	printf '%s\n' "$value-tmpfiles" >"$host/usr/lib/tmpfiles.d/candy.conf"
}

make_bundle() {
	directory=$1 architecture=$2 release=$3 generation=${4:-new}
	rm -rf "$directory"
	for relative in usr/local/bin/candy-server $managed_files; do
		mkdir -p "$directory/$(dirname "$relative")"
		if [ "$relative" = usr/local/libexec/candy-server-health-check ]; then
			printf '#!/bin/sh\nexit "${FAKE_HEALTH_FAIL:-0}"\n' >"$directory/$relative"
		else
			printf '#!/bin/sh\nprintf "%%s\\n" %s\n' "$generation" >"$directory/$relative"
		fi
		chmod 0755 "$directory/$relative"
	done
	mkdir -p "$directory/systemd" "$directory/install" "$directory/etc/candy"
	for unit in $units; do
		if [ "$unit" = candy-server.service ]; then
			printf '%s\n' '[Unit]' "Description=$generation-candy-server.service" '[Service]' \
				'ExecStart=/opt/candy/current/candy-server --config /etc/candy/server.toml' >"$directory/systemd/$unit"
		else
			printf '%s\n' "$generation-$unit" >"$directory/systemd/$unit"
		fi
	done
	printf '%s\n' "$generation-tmpfiles" >"$directory/systemd/candy.tmpfiles"
	printf '%s\n' "$release" >"$directory/RUNTIME-RELEASE"
	printf '%s\n' "$architecture" >"$directory/RUNTIME-ARCH"
	printf '%s\n' 0.4.0 >"$directory/VERSION"
	printf '%s\n' test >"$directory/README.md"
	cp "$upgrader" "$directory/install/upgrade-candy-server.sh"
	chmod 0755 "$directory/install/upgrade-candy-server.sh"
	tar -C "$directory" -czf "$directory.tar.gz" .
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
run_upgrade() {
	PATH="$fake_bin:$PATH" FAKE_SYSTEMD_STATE="$fake_state" FAKE_SYSTEMD_LOG="$tmp/systemd.log" \
		FAKE_KERNEL_STATE="$fake_kernel" FAKE_SYSCTL_LOG="$tmp/sysctl.log" \
		FAKE_SYSCTL_FAIL_KEY="${FAKE_SYSCTL_FAIL_KEY:-}" FAKE_SYSCTL_FAIL_VALUE="${FAKE_SYSCTL_FAIL_VALUE:-}" \
		CANDY_UPGRADE_ROOT="$host" CANDY_SYSTEMCTL="$fake_bin/systemctl" CANDY_SYSTEMD_TMPFILES="$fake_bin/systemd-tmpfiles" \
		CANDY_SYSCTL="$fake_bin/sysctl" \
		sh "${CANDY_TEST_UPGRADER:-$upgrader}" "$@"
}

grep -F 'LAUNCHER=${CANDY_SERVER_LAUNCHER:-/opt/candy/current/candy-server}' \
	"$repo_root/linux/server/apps/candy-server/candy-core-manager" >/dev/null || fail "fresh install Core manager launcher contract changed"
grep -F 'ExecStart=/opt/candy/current/candy-server --config /etc/candy/server.toml' \
	"$repo_root/linux/server/packaging/candy-server.service" >/dev/null || fail "fresh install service launcher contract changed"
grep -F 'LimitMEMLOCK=64M' "$repo_root/linux/server/packaging/candy-server.service" >/dev/null ||
	fail "server transaction agent cannot set its 64 MiB memlock limit"
grep -Fx 'CapabilityBoundingSet=' "$repo_root/linux/server/packaging/candy-server.service" >/dev/null ||
	fail "server service gained a capability bounding set"
if grep -Eq '^AmbientCapabilities=|^CapabilityBoundingSet=CAP_' "$repo_root/linux/server/packaging/candy-server.service"; then
	fail "server kernel tuning grants broad capabilities"
fi
for unit in candy-server.service candy-cloud-sync.service; do
	grep -F 'Environment=CANDY_SDWAN_STATE_DIR=/var/lib/candy/sdwan' \
		"$repo_root/linux/server/packaging/$unit" >/dev/null || fail "$unit does not pin the canonical state directory"
	grep -F 'Environment=CANDY_SDWAN_STATE_ROOT=/var/lib/candy/sdwan' \
		"$repo_root/linux/server/packaging/$unit" >/dev/null || fail "$unit does not pin the canonical state root"
done
grep -F -- '--state-dir /var/lib/candy/sdwan' \
	"$repo_root/linux/server/packaging/candy-cloud-sync.service" >/dev/null ||
	fail "Cloud sync does not receive an explicit canonical state directory"
if grep -R '/etc/candy/sdwan' "$repo_root/linux/server/apps" "$repo_root/linux/server/packaging"/*.service >/dev/null; then
	fail "a Linux server launcher or service still uses the legacy SD-WAN state root"
fi

write_host_generation old
mkdir -p "$host/usr/local/sbin"
printf '#!/bin/sh\nprintf "%%s\\n" legacy-core-manager\n' >"$host/usr/local/sbin/candy-core-manager"
chmod 0755 "$host/usr/local/sbin/candy-core-manager"
mkdir -p "$host/opt/candy/releases/old-runtime"
printf '#!/bin/sh\nprintf "%%s\\n" old\n' >"$host/opt/candy/releases/old-runtime/candy-server"
chmod 0755 "$host/opt/candy/releases/old-runtime/candy-server"
ln -s "$host/opt/candy/releases/old-runtime" "$host/opt/candy/current"
original_current=$(readlink "$host/opt/candy/current")
# This is host configuration embedded in the installer-generated unit, not a
# Runtime version detail. The upgrader must retain it while replacing the unit.
sed -i.bak '/old-candy-server.service/c\
[Service]\
Environment=CANDY_CORE_BINARY=/opt/operator/core/candy-core\
ExecStart=/opt/candy/current/candy-server --config /etc/candy/server.toml' "$host/etc/systemd/system/candy-server.service"
rm -f "$host/etc/systemd/system/candy-server.service.bak"
printf '%s\n' config-preserved >"$host/etc/candy/server.toml"
printf '%s\n' identity-preserved >"$host/etc/candy/sdwan/identity/device-identity-v1.json"
generation_id=$(printf '%064d' 7)
mkdir -p "$host/etc/candy/sdwan/generations/$generation_id/compatibility-generations/generation-1"
printf '%s\n' compatibility-preserved >"$host/etc/candy/sdwan/generations/$generation_id/compatibility-generations/generation-1/segment.snapshot"
chmod 0400 "$host/etc/candy/sdwan/generations/$generation_id/compatibility-generations/generation-1/segment.snapshot"
chmod 0500 "$host/etc/candy/sdwan/generations/$generation_id/compatibility-generations/generation-1" \
	"$host/etc/candy/sdwan/generations/$generation_id/compatibility-generations"
ln -s "generations/$generation_id" "$host/etc/candy/sdwan/configuration"
printf '%s\n' state-preserved >"$host/etc/candy/sdwan/state.json"
ln -s "$host/etc/candy/sdwan" "$host/var/lib/candy/sdwan"
printf '%s\n' core-preserved >"$host/opt/candy/cores/current/candy-core"
make_bundle "$tmp/good" x86_64 0.4.0-r62
good_sha=$(sha256 "$tmp/good.tar.gz")
reset_service_state
installed_upgrader=$tmp/installed-upgrade-candy-server.sh
cp "$upgrader" "$installed_upgrader"
printf '%s\n' '# simulate the previous installed Runtime revision' >>"$installed_upgrader"
chmod 0755 "$installed_upgrader"
CANDY_TEST_UPGRADER="$installed_upgrader" \
	run_upgrade --bundle-file "$tmp/good.tar.gz" --sha256 "$good_sha" --version 0.4.0-r62 >"$tmp/good.out"
grep -F 'handing off transaction to the validated candidate upgrader' "$tmp/good.out" >/dev/null ||
	fail "installed upgrader did not hand the transaction to the candidate"

active_release=$(readlink "$host/opt/candy/current")
[ "$active_release" != "$original_current" ] || fail "current Runtime release was not switched"
grep -F new "$active_release/candy-server" >/dev/null || fail "versioned Runtime launcher was not installed"
[ -f "$host/opt/candy/releases/old-runtime/candy-server" ] || fail "previous Runtime release was removed"
[ ! -e "$host/usr/local/sbin/candy-core-manager" ] || fail "legacy Core manager still shadows the managed command"
grep -F new-candy-server.service "$host/etc/systemd/system/candy-server.service" >/dev/null || fail "systemd unit was not installed"
grep -F 'Environment=CANDY_CORE_BINARY=/opt/operator/core/candy-core' "$host/etc/systemd/system/candy-server.service" >/dev/null || fail "operator-selected Core path was not preserved"
grep -Fx config-preserved "$host/etc/candy/server.toml" >/dev/null || fail "server configuration changed"
grep -Fx identity-preserved "$host/var/lib/candy/sdwan/identity/device-identity-v1.json" >/dev/null || fail "Cloud enrollment changed"
grep -Fx state-preserved "$host/var/lib/candy/sdwan/state.json" >/dev/null || fail "SD-WAN state changed"
[ ! -L "$host/var/lib/candy/sdwan" ] || fail "canonical SD-WAN state root became a symbolic link"
[ -L "$host/etc/candy/sdwan" ] || fail "legacy SD-WAN compatibility link was not installed"
[ "$(readlink "$host/etc/candy/sdwan")" = /var/lib/candy/sdwan ] || fail "legacy SD-WAN compatibility link targets the wrong directory"
[ "$(readlink "$host/var/lib/candy/sdwan/configuration")" = "generations/$generation_id" ] || fail "active configuration pointer changed during migration"
compatibility_file="$host/var/lib/candy/sdwan/generations/$generation_id/compatibility-generations/generation-1/segment.snapshot"
[ "$(stat -c '%a' "$compatibility_file" 2>/dev/null || stat -f '%Lp' "$compatibility_file")" = 400 ] ||
	fail "immutable compatibility generation permissions changed during migration"
grep -Fx core-preserved "$host/opt/candy/cores/current/candy-core" >/dev/null || fail "Candy Core changed"
[ "$(cat "$fake_kernel/net.core.rmem_max")" = 16777216 ] || fail "UDP receive maximum was not raised"
[ "$(cat "$fake_kernel/net.core.wmem_max")" = 16777216 ] || fail "UDP send maximum was not raised"
sysctl_policy="$host/usr/lib/sysctl.d/60-candy-server.conf"
grep -Fx 'net.core.rmem_max = 16777216' "$sysctl_policy" >/dev/null || fail "persistent UDP receive policy was not installed"
grep -Fx 'net.core.wmem_max = 16777216' "$sysctl_policy" >/dev/null || fail "persistent UDP send policy was not installed"
for service in candy-netd.service candy-server.service candy-cloud-sync.timer; do
	[ "$(cat "$fake_state/$service.enabled")" = 1 ] && [ "$(cat "$fake_state/$service.active")" = 1 ] || fail "$service state was not restored"
done
[ "$(cat "$fake_state/candy-cloud-sync.service.enabled")" = 0 ] && [ "$(cat "$fake_state/candy-cloud-sync.service.active")" = 0 ] || fail "inactive Cloud sync service was enabled"
grep -F 'start --no-block candy-cloud-sync.service' "$tmp/systemd.log" >/dev/null ||
	fail "restored Cloud sync timer was not armed by a oneshot dispatch"

# Integrity and architecture failures happen before services or files are touched.
: >"$tmp/systemd.log"
if run_upgrade --bundle-file "$tmp/good.tar.gz" --sha256 "$(printf '%064d' 0)" --version 0.4.0-r62 >"$tmp/bad-sha.out" 2>&1; then fail "wrong checksum was accepted"; fi
[ ! -s "$tmp/systemd.log" ] || fail "checksum rejection changed systemd state"
[ "$(readlink "$host/opt/candy/current")" = "$active_release" ] || fail "checksum rejection changed the active Runtime"
make_bundle "$tmp/wrong-arch" aarch64 0.4.0-r62
: >"$tmp/systemd.log"
if run_upgrade --bundle-file "$tmp/wrong-arch.tar.gz" --sha256 "$(sha256 "$tmp/wrong-arch.tar.gz")" --version 0.4.0-r62 >"$tmp/bad-arch.out" 2>&1; then fail "wrong architecture was accepted"; fi
[ ! -s "$tmp/systemd.log" ] || fail "architecture rejection changed systemd state"
make_bundle "$tmp/wrong-version" x86_64 0.4.0-r45
: >"$tmp/systemd.log"
if run_upgrade --bundle-file "$tmp/wrong-version.tar.gz" --sha256 "$(sha256 "$tmp/wrong-version.tar.gz")" --version 0.4.0-r62 >"$tmp/bad-version.out" 2>&1; then fail "wrong release identity was accepted"; fi
[ ! -s "$tmp/systemd.log" ] || fail "release identity rejection changed systemd state"

# A post-switch health failure must restore every file and exact prior service state.
cp "$active_release/candy-server" "$tmp/before-server"
cp "$host/etc/systemd/system/candy-server.service" "$tmp/before-unit"
before_current=$(readlink "$host/opt/candy/current")
# Model a file newly introduced by the candidate so rollback must remove it.
rm "$host/usr/local/libexec/serverd-linux"
# A later legacy install can recreate the old sbin manager. A failed Runtime
# transaction must restore it exactly instead of losing operator state.
mkdir -p "$host/usr/local/sbin"
printf '#!/bin/sh\nprintf "%%s\\n" rollback-legacy-core-manager\n' >"$host/usr/local/sbin/candy-core-manager"
chmod 0755 "$host/usr/local/sbin/candy-core-manager"
cp "$host/usr/local/sbin/candy-core-manager" "$tmp/before-legacy-core-manager"
# Start the failed transaction with an operator-owned policy and low live
# values. The candidate must raise them, then restore both forms of state.
cat >"$sysctl_policy" <<'EOF'
# operator policy retained across failed Runtime upgrades
net.core.rmem_max = 425984
net.core.wmem_max = 212992
EOF
printf '%s\n' 425984 >"$fake_kernel/net.core.rmem_max"
printf '%s\n' 212992 >"$fake_kernel/net.core.wmem_max"
cp "$sysctl_policy" "$tmp/before-sysctl-policy"
make_bundle "$tmp/rollback-candidate" x86_64 0.4.0-r62 broken
rollback_sha=$(sha256 "$tmp/rollback-candidate.tar.gz")
reset_service_state
if FAKE_HEALTH_FAIL=1 run_upgrade --bundle-file "$tmp/rollback-candidate.tar.gz" --sha256 "$rollback_sha" --version 0.4.0-r62 >"$tmp/rollback.out" 2>&1; then fail "failed health verification was accepted"; fi
cmp "$tmp/before-server" "$before_current/candy-server" >/dev/null || fail "Runtime executable rollback failed"
[ "$(readlink "$host/opt/candy/current")" = "$before_current" ] || fail "current Runtime link rollback failed"
failed_release="$host/opt/candy/releases/0.4.0-r62-$(printf '%s' "$rollback_sha" | cut -c 1-12)"
[ ! -e "$failed_release" ] || fail "failed Runtime release directory survived rollback"
cmp "$tmp/before-unit" "$host/etc/systemd/system/candy-server.service" >/dev/null || fail "systemd unit rollback failed"
[ ! -e "$host/usr/local/libexec/serverd-linux" ] || fail "newly introduced Runtime file was not removed during rollback"
cmp "$tmp/before-legacy-core-manager" "$host/usr/local/sbin/candy-core-manager" >/dev/null ||
	fail "legacy Core manager was not restored during rollback"
cmp "$tmp/before-sysctl-policy" "$sysctl_policy" >/dev/null || fail "kernel policy rollback failed"
[ "$(cat "$fake_kernel/net.core.rmem_max")" = 425984 ] || fail "receive sysctl rollback failed"
[ "$(cat "$fake_kernel/net.core.wmem_max")" = 212992 ] || fail "send sysctl rollback failed"
if grep -R broken "$host/usr/local/bin" "$host/usr/local/libexec" "$host/etc/systemd/system" "$host/usr/lib/tmpfiles.d" >/dev/null; then
	fail "rollback left candidate Runtime content installed"
fi
for service in candy-netd.service candy-server.service candy-cloud-sync.timer; do
	[ "$(cat "$fake_state/$service.enabled")" = 1 ] && [ "$(cat "$fake_state/$service.active")" = 1 ] || fail "$service rollback state is incorrect"
done

# Existing operator values above Candy's minimum must never be lowered.
unset FAKE_HEALTH_FAIL
printf '%s\n' 33554432 >"$fake_kernel/net.core.rmem_max"
printf '%s\n' 67108864 >"$fake_kernel/net.core.wmem_max"
# Exercise the older dual-real-directory layout as well as the production
# reverse-link layout used by the first upgrade above.
rm "$host/etc/candy/sdwan"
mkdir -p "$host/etc/candy/sdwan/identity"
printf '%s\n' merged-legacy-state >"$host/etc/candy/sdwan/legacy-state.json"
make_bundle "$tmp/high-kernel-values" x86_64 0.4.0-r62 high-kernel-values
high_kernel_sha=$(sha256 "$tmp/high-kernel-values.tar.gz")
reset_service_state
run_upgrade --bundle-file "$tmp/high-kernel-values.tar.gz" --sha256 "$high_kernel_sha" --version 0.4.0-r62 >/dev/null
[ "$(cat "$fake_kernel/net.core.rmem_max")" = 33554432 ] || fail "higher receive sysctl was lowered"
[ "$(cat "$fake_kernel/net.core.wmem_max")" = 67108864 ] || fail "higher send sysctl was lowered"
grep -Fx 'net.core.rmem_max = 33554432' "$sysctl_policy" >/dev/null || fail "higher receive sysctl was not persisted"
grep -Fx 'net.core.wmem_max = 67108864' "$sysctl_policy" >/dev/null || fail "higher send sysctl was not persisted"
grep -Fx merged-legacy-state "$host/var/lib/candy/sdwan/legacy-state.json" >/dev/null || fail "legacy SD-WAN state was not merged"
[ -L "$host/etc/candy/sdwan" ] && [ "$(readlink "$host/etc/candy/sdwan")" = /var/lib/candy/sdwan ] ||
	fail "dual-directory migration did not establish the compatibility link"

# Rollback must attempt receive and send restoration independently. Keep both
# live values above the candidate minimum so only rollback invokes sysctl -w.
printf '%s\n' 50331648 >"$fake_kernel/net.core.rmem_max"
printf '%s\n' 83886080 >"$fake_kernel/net.core.wmem_max"
make_bundle "$tmp/partial-sysctl-rollback" x86_64 0.4.0-r62 partial-sysctl-rollback
partial_rollback_sha=$(sha256 "$tmp/partial-sysctl-rollback.tar.gz")
reset_service_state
: >"$tmp/sysctl.log"
if FAKE_HEALTH_FAIL=1 FAKE_SYSCTL_FAIL_KEY=net.core.rmem_max FAKE_SYSCTL_FAIL_VALUE=50331648 \
	run_upgrade --bundle-file "$tmp/partial-sysctl-rollback.tar.gz" --sha256 "$partial_rollback_sha" --version 0.4.0-r62 >"$tmp/partial-sysctl-rollback.out" 2>&1; then
	fail "failed health verification with partial sysctl rollback was accepted"
fi
grep -Fx 'net.core.rmem_max=50331648' "$tmp/sysctl.log" >/dev/null || fail "receive sysctl rollback was not attempted"
grep -Fx 'net.core.wmem_max=83886080' "$tmp/sysctl.log" >/dev/null || fail "send sysctl rollback was skipped after receive rollback failed"

# A failed upgrade from the production reverse-link layout must restore that
# exact old layout and leave its only state tree intact.
rm "$host/etc/candy/sdwan"
mv "$host/var/lib/candy/sdwan" "$host/etc/candy/sdwan"
ln -s "$host/etc/candy/sdwan" "$host/var/lib/candy/sdwan"
printf '%s\n' reverse-rollback-preserved >"$host/etc/candy/sdwan/reverse-rollback.json"
make_bundle "$tmp/reverse-link-rollback" x86_64 0.4.0-r62 reverse-link-rollback
reverse_rollback_sha=$(sha256 "$tmp/reverse-link-rollback.tar.gz")
reset_service_state
if FAKE_HEALTH_FAIL=1 run_upgrade --bundle-file "$tmp/reverse-link-rollback.tar.gz" --sha256 "$reverse_rollback_sha" --version 0.4.0-r62 >"$tmp/reverse-link-rollback.out" 2>&1; then
	fail "failed reverse-link migration health verification was accepted"
fi
[ -L "$host/var/lib/candy/sdwan" ] || fail "reverse-link rollback did not restore the canonical link"
[ "$(readlink "$host/var/lib/candy/sdwan")" = "$host/etc/candy/sdwan" ] || fail "reverse-link rollback restored the wrong target"
[ -d "$host/etc/candy/sdwan" ] && [ ! -L "$host/etc/candy/sdwan" ] || fail "reverse-link rollback lost the legacy state directory"
grep -Fx reverse-rollback-preserved "$host/etc/candy/sdwan/reverse-rollback.json" >/dev/null || fail "reverse-link rollback lost SD-WAN state"

# Links and other non-regular archive members are rejected before mutation.
make_bundle "$tmp/link-bundle" x86_64 0.4.0-r62
rm "$tmp/link-bundle/usr/local/libexec/candy-cloud-sync"
ln -s /etc/passwd "$tmp/link-bundle/usr/local/libexec/candy-cloud-sync"
tar -C "$tmp/link-bundle" -czf "$tmp/link-bundle.tar.gz" .
: >"$tmp/systemd.log"
if run_upgrade --bundle-file "$tmp/link-bundle.tar.gz" --sha256 "$(sha256 "$tmp/link-bundle.tar.gz")" --version 0.4.0-r62 >"$tmp/link.out" 2>&1; then fail "symlink member was accepted"; fi
[ ! -s "$tmp/systemd.log" ] || fail "link rejection changed systemd state"

printf '%s\n' "Candy Linux server Runtime upgrade test passed"
