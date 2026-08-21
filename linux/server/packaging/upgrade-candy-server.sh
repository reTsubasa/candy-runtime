#!/bin/sh
set -eu

# The upgrader deliberately owns only immutable Runtime program and unit files.
# Configuration, enrollment, mutable SD-WAN state, and Core are outside this list.
ROOT=${CANDY_UPGRADE_ROOT:-}
SYSTEMCTL=${CANDY_SYSTEMCTL:-systemctl}
TMPFILES=${CANDY_SYSTEMD_TMPFILES:-systemd-tmpfiles}
HEALTH_CHECK=${CANDY_HEALTH_CHECK:-/usr/local/libexec/candy-server-health-check}
MAX_BUNDLE_BYTES=${CANDY_MAX_BUNDLE_BYTES:-268435456}
BUNDLE_FILE=
BUNDLE_URL=
EXPECTED_SHA256=
EXPECTED_VERSION=
transaction_started=0
transaction_finished=0
work_dir=
release_dir=
release_stage=
release_created=0
previous_current=
had_current=0

usage() {
	cat <<'EOF'
usage: upgrade-candy-server.sh (--bundle-file PATH | --bundle-url HTTPS_URL) --sha256 SHA256 --version VERSION

Atomically upgrades the complete Candy Linux server Runtime bundle. Runtime
configuration, Cloud enrollment, SD-WAN state, and installed Candy Core files
are preserved. On failure, all managed files and systemd states are restored.
EOF
}

log() { printf '%s\n' "upgrade-candy-server: $*"; }
die() { printf '%s\n' "upgrade-candy-server: $*" >&2; exit 1; }
need_command() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
host_path() { printf '%s%s\n' "$ROOT" "$1"; }
replace_symlink() {
	target=$1
	link=$2
	temporary=$3
	rm -f "$temporary"
	ln -s "$target" "$temporary"
	if mv -Tf "$temporary" "$link" 2>/dev/null; then
		return 0
	fi
	# BSD mv lacks -T. This branch exists for repository tests; supported Linux
	# hosts use the atomic rename above.
	rm -f "$link"
	mv -f "$temporary" "$link"
}

case "${1:-}" in -h|--help) usage; exit 0 ;; esac
if [ "$(id -u)" != 0 ]; then
	if [ -z "$ROOT" ] && command -v sudo >/dev/null 2>&1; then exec sudo sh "$0" "$@"; fi
	die "run as root"
fi

while [ "$#" -gt 0 ]; do
	case "$1" in
		--bundle-file|--artifact-file) option=$1; shift; [ "$#" -gt 0 ] || die "$option requires a path"; BUNDLE_FILE=$1 ;;
		--bundle-url|--artifact-url) option=$1; shift; [ "$#" -gt 0 ] || die "$option requires a URL"; BUNDLE_URL=$1 ;;
		--sha256) shift; [ "$#" -gt 0 ] || die "--sha256 requires a value"; EXPECTED_SHA256=$1 ;;
		--version) shift; [ "$#" -gt 0 ] || die "--version requires a value"; EXPECTED_VERSION=$1 ;;
		*) die "unknown option: $1" ;;
	esac
	shift
done

[ -n "$BUNDLE_FILE" ] || [ -n "$BUNDLE_URL" ] || die "provide --bundle-file or --bundle-url"
[ -z "$BUNDLE_FILE" ] || [ -z "$BUNDLE_URL" ] || die "use only one bundle source"
case "$BUNDLE_URL" in '') ;; https://*) ;; *) die "--bundle-url must use HTTPS" ;; esac
case "$EXPECTED_SHA256" in
	????????????????????????????????????????????????????????????????) ;;
	*) die "--sha256 must contain exactly 64 hexadecimal characters" ;;
esac
case "$EXPECTED_SHA256" in *[!0-9A-Fa-f]*) die "--sha256 contains non-hexadecimal characters" ;; esac
case "$EXPECTED_VERSION" in ''|*[!A-Za-z0-9._+-]*) die "--version is invalid" ;; esac
case "$MAX_BUNDLE_BYTES" in ''|*[!0-9]*) die "CANDY_MAX_BUNDLE_BYTES must be an integer" ;; esac
[ "$MAX_BUNDLE_BYTES" -gt 0 ] || die "CANDY_MAX_BUNDLE_BYTES must be positive"

need_command tar
need_command awk
need_command find
need_command mktemp
need_command mv
need_command cp
need_command "$SYSTEMCTL"
need_command "$TMPFILES"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/candy-runtime-upgrade.XXXXXX")
bundle=$work_dir/runtime.tar.gz
extract_dir=$work_dir/extract
backup_dir=$work_dir/backup
state_dir=$work_dir/service-state
mkdir -p "$extract_dir" "$backup_dir" "$state_dir"

cleanup() {
	[ -z "$release_stage" ] || rm -rf "$release_stage"
	[ -z "$work_dir" ] || rm -rf "$work_dir"
}

managed_files='usr/local/bin/candy-core-manager
usr/local/libexec/serverd-linux
usr/local/libexec/candy-sdwan-runtime
usr/local/libexec/candy-sdwan-agent
usr/local/libexec/candy-netd
usr/local/libexec/candy-cloud-enroll
usr/local/libexec/candy-cloud-sync
usr/local/libexec/candy-server-health-check'
unit_files='candy-server.service
candy-netd.service
candy-cloud-sync.service
candy-cloud-sync.timer'
services='candy-netd.service
candy-server.service
candy-cloud-sync.service
candy-cloud-sync.timer'

record_service_state() {
	for service in $services; do
		if "$SYSTEMCTL" is-enabled --quiet "$service" >/dev/null 2>&1; then echo 1 >"$state_dir/$service.enabled"; else echo 0 >"$state_dir/$service.enabled"; fi
		if "$SYSTEMCTL" is-active --quiet "$service" >/dev/null 2>&1; then echo 1 >"$state_dir/$service.active"; else echo 0 >"$state_dir/$service.active"; fi
	done
}

stop_services() {
	stop_failed=0
	for service in candy-cloud-sync.timer candy-cloud-sync.service candy-server.service candy-netd.service; do
		"$SYSTEMCTL" stop "$service" >/dev/null 2>&1 || true
		if "$SYSTEMCTL" is-active --quiet "$service" >/dev/null 2>&1; then
			log "could not stop $service"
			stop_failed=1
		fi
	done
	[ "$stop_failed" = 0 ]
}

restore_service_state() {
	stop_services || return 1
	for service in $services; do "$SYSTEMCTL" disable "$service" >/dev/null 2>&1 || true; done
	for service in $services; do
		if [ "$(cat "$state_dir/$service.enabled")" = 1 ]; then "$SYSTEMCTL" enable "$service" >/dev/null; fi
	done
	# Dependency order is significant; the timer is restored last.
	for service in $services; do
		if [ "$(cat "$state_dir/$service.active")" = 1 ]; then "$SYSTEMCTL" start "$service" >/dev/null; fi
	done
}

restore_files() {
	for relative in $managed_files; do restore_one "/$relative"; done
	for unit in $unit_files; do restore_one "/etc/systemd/system/$unit"; done
	restore_one /usr/lib/tmpfiles.d/candy.conf
}

restore_current() {
	current_link=$(host_path /opt/candy/current)
	rm -f "$current_link"
	if [ "$had_current" = 1 ]; then
		temporary=$(host_path "/opt/candy/.current.restore.$$")
		replace_symlink "$previous_current" "$current_link" "$temporary"
	fi
	if [ "$release_created" = 1 ] && [ -n "$release_dir" ]; then
		rm -rf "$release_dir"
	fi
}

restore_one() {
	destination=$(host_path "$1")
	key=$(printf '%s' "$1" | sed 's#^/##; s#/#__#g')
	if [ -f "$backup_dir/$key.present" ]; then
		mkdir -p "$(dirname "$destination")"
		cp -p "$backup_dir/$key" "$destination.restore.$$"
		mv -f "$destination.restore.$$" "$destination"
	else
		rm -f "$destination"
	fi
}

rollback() {
	[ "$transaction_started" = 1 ] || return 0
	[ "$transaction_finished" = 0 ] || return 0
	set +e
	log "upgrade failed; restoring the previous Runtime and service states"
	stop_services || true
	restore_files
	restore_current
	"$SYSTEMCTL" daemon-reload >/dev/null 2>&1
	restore_service_state
	status=$?
	transaction_finished=1
	set -e
	[ "$status" -eq 0 ] || log "warning: Runtime files were restored but a previous service state could not be restored"
}
trap 'rollback; cleanup' EXIT HUP INT TERM

if [ -n "$BUNDLE_FILE" ]; then
	[ -f "$BUNDLE_FILE" ] && [ ! -L "$BUNDLE_FILE" ] || die "bundle is not a regular file: $BUNDLE_FILE"
	cp "$BUNDLE_FILE" "$bundle"
else
	if command -v curl >/dev/null 2>&1; then
		curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 "$BUNDLE_URL" -o "$bundle"
	elif command -v wget >/dev/null 2>&1; then
		wget --https-only -qO "$bundle" "$BUNDLE_URL"
	else
		die "curl or wget is required to download a bundle"
	fi
fi

bundle_size=$(wc -c <"$bundle" | tr -d ' ')
[ "$bundle_size" -gt 0 ] && [ "$bundle_size" -le "$MAX_BUNDLE_BYTES" ] || die "bundle size is outside the accepted range"
if command -v sha256sum >/dev/null 2>&1; then
	actual_sha256=$(sha256sum "$bundle" | awk '{print tolower($1)}')
elif command -v shasum >/dev/null 2>&1; then
	actual_sha256=$(shasum -a 256 "$bundle" | awk '{print tolower($1)}')
else
	die "sha256sum or shasum is required"
fi
expected_sha256=$(printf '%s' "$EXPECTED_SHA256" | tr 'A-F' 'a-f')
[ "$actual_sha256" = "$expected_sha256" ] || die "bundle SHA-256 does not match"

# Validate member names before extraction so tar cannot write outside the private directory.
tar -tzf "$bundle" >"$work_dir/members"
tar -tvzf "$bundle" >"$work_dir/member-details"
member_count=$(wc -l <"$work_dir/members" | tr -d ' ')
[ "$member_count" -gt 0 ] && [ "$member_count" -le 64 ] || die "bundle contains an invalid number of archive members"
awk '
	{
		name = $0
		sub(/^\.\//, "", name)
		if (name != "" && name != "." && seen[name]++) exit 1
	}
' "$work_dir/members" || die "bundle contains duplicate archive members"
while IFS= read -r detail; do
	type=$(printf '%s' "$detail" | cut -c 1)
	case "$type" in -|d) ;; *) die "bundle contains a link or special archive member" ;; esac
done <"$work_dir/member-details"
while IFS= read -r member; do
	case "$member" in ./*) member=${member#./} ;; esac
	case "$member" in ''|.) continue ;; /*|../*|*/../*|*/..|..|*\\*) die "unsafe archive member: $member" ;; esac
	case "$member" in
		usr/|usr/local/|usr/local/bin/|usr/local/libexec/|systemd/|install/|etc/|etc/candy/) ;;
		usr/local/bin/candy-server|usr/local/bin/candy-core-manager|usr/local/libexec/serverd-linux|usr/local/libexec/candy-sdwan-runtime|usr/local/libexec/candy-sdwan-agent|usr/local/libexec/candy-netd|usr/local/libexec/candy-cloud-enroll|usr/local/libexec/candy-cloud-sync|usr/local/libexec/candy-server-health-check) ;;
		systemd/candy-server.service|systemd/candy-netd.service|systemd/candy-cloud-sync.service|systemd/candy-cloud-sync.timer|systemd/candy.tmpfiles) ;;
		install/install-candy-server.sh|install/upgrade-candy-server.sh|etc/candy/server.toml.example|etc/candy/cloud-sync.env.example|README.md|VERSION|RUNTIME-RELEASE|RUNTIME-ARCH) ;;
		*) die "unexpected archive member: $member" ;;
	esac
done <"$work_dir/members"

tar -xzf "$bundle" -C "$extract_dir"
if find "$extract_dir" -type l -o -type b -o -type c -o -type p -o -type s | grep -q .; then
	die "bundle contains a link or special file"
fi
[ -f "$extract_dir/usr/local/bin/candy-server" ] && [ -x "$extract_dir/usr/local/bin/candy-server" ] ||
	die "bundle executable is missing: usr/local/bin/candy-server"
for relative in $managed_files; do [ -f "$extract_dir/$relative" ] && [ -x "$extract_dir/$relative" ] || die "bundle executable is missing: $relative"; done
for unit in $unit_files; do [ -f "$extract_dir/systemd/$unit" ] || die "bundle unit is missing: $unit"; done
[ -f "$extract_dir/systemd/candy.tmpfiles" ] || die "bundle tmpfiles policy is missing"
[ -f "$extract_dir/RUNTIME-RELEASE" ] || die "bundle release identity is missing"
[ "$(tr -d '\r\n' <"$extract_dir/RUNTIME-RELEASE")" = "$EXPECTED_VERSION" ] || die "bundle version does not match --version"

case "$(uname -m)" in x86_64|amd64) host_arch=x86_64 ;; aarch64|arm64) host_arch=aarch64 ;; *) die "unsupported host architecture: $(uname -m)" ;; esac
[ -f "$extract_dir/RUNTIME-ARCH" ] || die "bundle architecture identity is missing"
[ "$(tr -d '\r\n' <"$extract_dir/RUNTIME-ARCH")" = "$host_arch" ] || die "bundle architecture does not match this host"

release_suffix=$(printf '%s' "$expected_sha256" | cut -c 1-12)
release_dir=$(host_path "/opt/candy/releases/$EXPECTED_VERSION-$release_suffix")
release_stage=$(host_path "/opt/candy/releases/.candy-runtime-$EXPECTED_VERSION-$release_suffix.$$")
current_link=$(host_path /opt/candy/current)
if [ -L "$current_link" ]; then
	previous_current=$(readlink "$current_link")
	had_current=1
elif [ -e "$current_link" ]; then
	die "refusing non-symbolic Candy current path: $current_link"
fi
if [ -e "$release_dir" ] || [ -L "$release_dir" ]; then
	die "Runtime release directory already exists: $release_dir"
fi

backup_one() {
	destination=$(host_path "$1")
	key=$(printf '%s' "$1" | sed 's#^/##; s#/#__#g')
	if [ -f "$destination" ] && [ ! -L "$destination" ]; then
		cp -p "$destination" "$backup_dir/$key"
		: >"$backup_dir/$key.present"
	elif [ -e "$destination" ] || [ -L "$destination" ]; then
		die "refusing non-regular managed destination: $destination"
	fi
}
install_one() {
	source=$1 destination=$(host_path "$2") mode=$3
	mkdir -p "$(dirname "$destination")"
	temporary="$(dirname "$destination")/.candy-upgrade.$$.$(basename "$destination")"
	cp "$source" "$temporary"
	chmod "$mode" "$temporary"
	chown root:root "$temporary"
	mv -f "$temporary" "$destination"
}

# install-candy-server.sh permits an operator-selected Core path. Carry that
# host-specific choice into the new Runtime-owned unit without preserving old
# executable paths or other stale unit behavior.
server_unit_source=$extract_dir/systemd/candy-server.service
installed_server_unit=$(host_path /etc/systemd/system/candy-server.service)
if [ -f "$installed_server_unit" ] && [ ! -L "$installed_server_unit" ]; then
	core_override=$(sed -n '/^Environment=CANDY_CORE_BINARY=/{p;q;}' "$installed_server_unit")
	case "$core_override" in
		'') ;;
		Environment=CANDY_CORE_BINARY=/*)
			case "$core_override" in *[!A-Za-z0-9_./+=-]*) die "installed Candy Core override is unsafe" ;; esac
			awk -v override="$core_override" '{ print; if ($0 == "[Service]") print override }' \
				"$server_unit_source" >"$work_dir/candy-server.service"
			server_unit_source=$work_dir/candy-server.service
			;;
		*) die "installed Candy Core override is invalid" ;;
	esac
fi

# Refuse mutation of protected trees even when a hostile host has replaced one with a link.
for protected in /etc/candy /var/lib/candy /opt/candy/cores; do
	protected_path=$(host_path "$protected")
	[ ! -L "$protected_path" ] || die "protected path is a symbolic link: $protected_path"
done

mkdir -p "$(host_path /opt/candy/releases)"
[ ! -e "$release_stage" ] && [ ! -L "$release_stage" ] || die "temporary Runtime release path already exists"
mkdir -m 0755 "$release_stage"
cp "$extract_dir/usr/local/bin/candy-server" "$release_stage/candy-server"
chmod 0755 "$release_stage/candy-server"
chown root:root "$release_stage" "$release_stage/candy-server"

record_service_state
for relative in $managed_files; do backup_one "/$relative"; done
for unit in $unit_files; do backup_one "/etc/systemd/system/$unit"; done
backup_one /usr/lib/tmpfiles.d/candy.conf
transaction_started=1
stop_services

mv "$release_stage" "$release_dir"
release_created=1
current_temporary=$(host_path "/opt/candy/.current.$$")
replace_symlink "$release_dir" "$current_link" "$current_temporary"

for relative in $managed_files; do install_one "$extract_dir/$relative" "/$relative" 0755; done
for unit in $unit_files; do
	unit_source=$extract_dir/systemd/$unit
	[ "$unit" != candy-server.service ] || unit_source=$server_unit_source
	install_one "$unit_source" "/etc/systemd/system/$unit" 0644
done
install_one "$extract_dir/systemd/candy.tmpfiles" /usr/lib/tmpfiles.d/candy.conf 0644
"$SYSTEMCTL" daemon-reload
"$TMPFILES" --create "$(host_path /usr/lib/tmpfiles.d/candy.conf)"
restore_service_state

if [ "$(cat "$state_dir/candy-netd.service.active")" = 1 ]; then "$SYSTEMCTL" is-active --quiet candy-netd.service; fi
if [ "$(cat "$state_dir/candy-server.service.active")" = 1 ]; then
	health=$(host_path "$HEALTH_CHECK")
	CANDY_SERVER_HEALTH_WAIT_SECONDS=${CANDY_SERVER_HEALTH_WAIT_SECONDS:-15} "$health"
fi
if [ "$(cat "$state_dir/candy-cloud-sync.timer.active")" = 1 ]; then "$SYSTEMCTL" is-active --quiet candy-cloud-sync.timer; fi

transaction_finished=1
log "Runtime $EXPECTED_VERSION installed; configuration, enrollment, SD-WAN state, and Core were preserved"
cleanup
trap - EXIT HUP INT TERM
