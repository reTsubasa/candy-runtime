#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
upgrader=$repo_root/linux/server/packaging/upgrade-candy-server.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-runtime-upgrade-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
fail() { printf '%s\n' "upgrade_candy_server_test: $*" >&2; exit 1; }

fake_bin=$tmp/bin
fake_state=$tmp/systemd-state
host=$tmp/host
mkdir -p "$fake_bin" "$fake_state" "$host/etc/candy" "$host/var/lib/candy/sdwan/identity" "$host/opt/candy/cores/current"

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
	start) printf 1 >"$FAKE_SYSTEMD_STATE/$service.active" ;;
	stop) printf 0 >"$FAKE_SYSTEMD_STATE/$service.active" ;;
	daemon-reload) : ;;
	*) printf '%s\n' "unexpected systemctl command: $command" >&2; exit 2 ;;
esac
EOF
chmod 0755 "$fake_bin"/*

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
	tar -C "$directory" -czf "$directory.tar.gz" .
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
run_upgrade() {
	PATH="$fake_bin:$PATH" FAKE_SYSTEMD_STATE="$fake_state" FAKE_SYSTEMD_LOG="$tmp/systemd.log" \
		CANDY_UPGRADE_ROOT="$host" CANDY_SYSTEMCTL="$fake_bin/systemctl" CANDY_SYSTEMD_TMPFILES="$fake_bin/systemd-tmpfiles" \
		sh "$upgrader" "$@"
}

grep -F 'LAUNCHER=${CANDY_SERVER_LAUNCHER:-/opt/candy/current/candy-server}' \
	"$repo_root/linux/server/apps/candy-server/candy-core-manager" >/dev/null || fail "fresh install Core manager launcher contract changed"
grep -F 'ExecStart=/opt/candy/current/candy-server --config /etc/candy/server.toml' \
	"$repo_root/linux/server/packaging/candy-server.service" >/dev/null || fail "fresh install service launcher contract changed"

write_host_generation old
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
printf '%s\n' identity-preserved >"$host/var/lib/candy/sdwan/identity/device-identity-v1.json"
printf '%s\n' state-preserved >"$host/var/lib/candy/sdwan/state.json"
printf '%s\n' core-preserved >"$host/opt/candy/cores/current/candy-core"
make_bundle "$tmp/good" x86_64 0.4.0-r50
good_sha=$(sha256 "$tmp/good.tar.gz")
reset_service_state
run_upgrade --bundle-file "$tmp/good.tar.gz" --sha256 "$good_sha" --version 0.4.0-r50 >/dev/null

active_release=$(readlink "$host/opt/candy/current")
[ "$active_release" != "$original_current" ] || fail "current Runtime release was not switched"
grep -F new "$active_release/candy-server" >/dev/null || fail "versioned Runtime launcher was not installed"
[ -f "$host/opt/candy/releases/old-runtime/candy-server" ] || fail "previous Runtime release was removed"
grep -F new-candy-server.service "$host/etc/systemd/system/candy-server.service" >/dev/null || fail "systemd unit was not installed"
grep -F 'Environment=CANDY_CORE_BINARY=/opt/operator/core/candy-core' "$host/etc/systemd/system/candy-server.service" >/dev/null || fail "operator-selected Core path was not preserved"
grep -Fx config-preserved "$host/etc/candy/server.toml" >/dev/null || fail "server configuration changed"
grep -Fx identity-preserved "$host/var/lib/candy/sdwan/identity/device-identity-v1.json" >/dev/null || fail "Cloud enrollment changed"
grep -Fx state-preserved "$host/var/lib/candy/sdwan/state.json" >/dev/null || fail "SD-WAN state changed"
grep -Fx core-preserved "$host/opt/candy/cores/current/candy-core" >/dev/null || fail "Candy Core changed"
for service in candy-netd.service candy-server.service candy-cloud-sync.timer; do
	[ "$(cat "$fake_state/$service.enabled")" = 1 ] && [ "$(cat "$fake_state/$service.active")" = 1 ] || fail "$service state was not restored"
done
[ "$(cat "$fake_state/candy-cloud-sync.service.enabled")" = 0 ] && [ "$(cat "$fake_state/candy-cloud-sync.service.active")" = 0 ] || fail "inactive Cloud sync service was enabled"

# Integrity and architecture failures happen before services or files are touched.
: >"$tmp/systemd.log"
if run_upgrade --bundle-file "$tmp/good.tar.gz" --sha256 "$(printf '%064d' 0)" --version 0.4.0-r50 >"$tmp/bad-sha.out" 2>&1; then fail "wrong checksum was accepted"; fi
[ ! -s "$tmp/systemd.log" ] || fail "checksum rejection changed systemd state"
[ "$(readlink "$host/opt/candy/current")" = "$active_release" ] || fail "checksum rejection changed the active Runtime"
make_bundle "$tmp/wrong-arch" aarch64 0.4.0-r50
: >"$tmp/systemd.log"
if run_upgrade --bundle-file "$tmp/wrong-arch.tar.gz" --sha256 "$(sha256 "$tmp/wrong-arch.tar.gz")" --version 0.4.0-r50 >"$tmp/bad-arch.out" 2>&1; then fail "wrong architecture was accepted"; fi
[ ! -s "$tmp/systemd.log" ] || fail "architecture rejection changed systemd state"
make_bundle "$tmp/wrong-version" x86_64 0.4.0-r45
: >"$tmp/systemd.log"
if run_upgrade --bundle-file "$tmp/wrong-version.tar.gz" --sha256 "$(sha256 "$tmp/wrong-version.tar.gz")" --version 0.4.0-r50 >"$tmp/bad-version.out" 2>&1; then fail "wrong release identity was accepted"; fi
[ ! -s "$tmp/systemd.log" ] || fail "release identity rejection changed systemd state"

# A post-switch health failure must restore every file and exact prior service state.
cp "$active_release/candy-server" "$tmp/before-server"
cp "$host/etc/systemd/system/candy-server.service" "$tmp/before-unit"
before_current=$(readlink "$host/opt/candy/current")
# Model a file newly introduced by the candidate so rollback must remove it.
rm "$host/usr/local/libexec/serverd-linux"
make_bundle "$tmp/rollback-candidate" x86_64 0.4.0-r50 broken
rollback_sha=$(sha256 "$tmp/rollback-candidate.tar.gz")
reset_service_state
if FAKE_HEALTH_FAIL=1 run_upgrade --bundle-file "$tmp/rollback-candidate.tar.gz" --sha256 "$rollback_sha" --version 0.4.0-r50 >"$tmp/rollback.out" 2>&1; then fail "failed health verification was accepted"; fi
cmp "$tmp/before-server" "$before_current/candy-server" >/dev/null || fail "Runtime executable rollback failed"
[ "$(readlink "$host/opt/candy/current")" = "$before_current" ] || fail "current Runtime link rollback failed"
failed_release="$host/opt/candy/releases/0.4.0-r50-$(printf '%s' "$rollback_sha" | cut -c 1-12)"
[ ! -e "$failed_release" ] || fail "failed Runtime release directory survived rollback"
cmp "$tmp/before-unit" "$host/etc/systemd/system/candy-server.service" >/dev/null || fail "systemd unit rollback failed"
[ ! -e "$host/usr/local/libexec/serverd-linux" ] || fail "newly introduced Runtime file was not removed during rollback"
if grep -R broken "$host/usr/local/bin" "$host/usr/local/libexec" "$host/etc/systemd/system" "$host/usr/lib/tmpfiles.d" >/dev/null; then
	fail "rollback left candidate Runtime content installed"
fi
for service in candy-netd.service candy-server.service candy-cloud-sync.timer; do
	[ "$(cat "$fake_state/$service.enabled")" = 1 ] && [ "$(cat "$fake_state/$service.active")" = 1 ] || fail "$service rollback state is incorrect"
done

# Links and other non-regular archive members are rejected before mutation.
make_bundle "$tmp/link-bundle" x86_64 0.4.0-r50
rm "$tmp/link-bundle/usr/local/libexec/candy-cloud-sync"
ln -s /etc/passwd "$tmp/link-bundle/usr/local/libexec/candy-cloud-sync"
tar -C "$tmp/link-bundle" -czf "$tmp/link-bundle.tar.gz" .
: >"$tmp/systemd.log"
if run_upgrade --bundle-file "$tmp/link-bundle.tar.gz" --sha256 "$(sha256 "$tmp/link-bundle.tar.gz")" --version 0.4.0-r50 >"$tmp/link.out" 2>&1; then fail "symlink member was accepted"; fi
[ ! -s "$tmp/systemd.log" ] || fail "link rejection changed systemd state"

printf '%s\n' "Candy Linux server Runtime upgrade test passed"
