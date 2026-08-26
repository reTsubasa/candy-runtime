#!/bin/sh
set -eu

# The upgrader owns immutable Runtime program, unit, and kernel policy files.
# Configuration, enrollment, mutable SD-WAN state, and Core are outside this list.
ROOT=${CANDY_UPGRADE_ROOT:-}
SYSTEMCTL=${CANDY_SYSTEMCTL:-systemctl}
TMPFILES=${CANDY_SYSTEMD_TMPFILES:-systemd-tmpfiles}
SYSCTL=${CANDY_SYSCTL:-sysctl}
HEALTH_CHECK=${CANDY_HEALTH_CHECK:-/usr/local/libexec/candy-server-health-check}
MAX_BUNDLE_BYTES=${CANDY_MAX_BUNDLE_BYTES:-268435456}
SYSCTL_POLICY=/usr/lib/sysctl.d/60-candy-server.conf
UDP_BUFFER_MAX_BYTES=16777216
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
sdwan_migration_pending=
sdwan_reverse_link_target=
sdwan_reverse_migration=0
sysctl_state_recorded=0
previous_rmem_max=
previous_wmem_max=

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
need_command cmp
need_command "$SYSTEMCTL"
need_command "$TMPFILES"
need_command "$SYSCTL"

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
# Releases before the managed Runtime layout installed the Core manager in
# sbin. Root shells commonly search sbin before bin, so leaving that file in
# place silently selects the stale manager after an otherwise successful
# upgrade. Treat it as transaction-owned migration state: remove it only after
# backups exist, and restore it on rollback.
legacy_files='usr/local/sbin/candy-core-manager'
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

read_positive_sysctl() {
	key=$1
	value=$("$SYSCTL" -n "$key") || return 1
	case "$value" in ''|*[!0-9]*|0) return 1 ;; esac
	printf '%s\n' "$value"
}

record_kernel_tuning() {
	previous_rmem_max=$(read_positive_sysctl net.core.rmem_max) ||
		die "could not read net.core.rmem_max"
	previous_wmem_max=$(read_positive_sysctl net.core.wmem_max) ||
		die "could not read net.core.wmem_max"
	sysctl_state_recorded=1
}

raise_sysctl_minimum() {
	key=$1
	minimum=$2
	current=$(read_positive_sysctl "$key") || return 1
	if [ "$current" -lt "$minimum" ]; then
		"$SYSCTL" -w "$key=$minimum" >/dev/null || return 1
	fi
	current=$(read_positive_sysctl "$key") || return 1
	[ "$current" -ge "$minimum" ]
}

install_kernel_tuning() {
	policy=$(host_path "$SYSCTL_POLICY")
	target_rmem_max=$previous_rmem_max
	target_wmem_max=$previous_wmem_max
	[ "$target_rmem_max" -ge "$UDP_BUFFER_MAX_BYTES" ] || target_rmem_max=$UDP_BUFFER_MAX_BYTES
	[ "$target_wmem_max" -ge "$UDP_BUFFER_MAX_BYTES" ] || target_wmem_max=$UDP_BUFFER_MAX_BYTES
	mkdir -p "$(dirname "$policy")"
	temporary="$(dirname "$policy")/.60-candy-server.conf.$$"
	cat >"$temporary" <<EOF
# Candy Core requests 8 MiB QUIC socket queues. Keep kernel maxima above that
# request without granting the service CAP_NET_ADMIN for SO_*BUFFORCE.
net.core.rmem_max = $target_rmem_max
net.core.wmem_max = $target_wmem_max
EOF
	chmod 0644 "$temporary"
	chown root:root "$temporary"
	mv -f "$temporary" "$policy"
	raise_sysctl_minimum net.core.rmem_max "$target_rmem_max" ||
		die "could not raise net.core.rmem_max to $target_rmem_max"
	raise_sysctl_minimum net.core.wmem_max "$target_wmem_max" ||
		die "could not raise net.core.wmem_max to $target_wmem_max"
}

restore_kernel_tuning() {
	status=0
	[ "$sysctl_state_recorded" = 1 ] || return 0
	"$SYSCTL" -w "net.core.rmem_max=$previous_rmem_max" >/dev/null 2>&1 || status=1
	"$SYSCTL" -w "net.core.wmem_max=$previous_wmem_max" >/dev/null 2>&1 || status=1
	return "$status"
}

merge_legacy_sdwan_tree() {
	mode=$1
	canonical=$(host_path /var/lib/candy/sdwan)
	legacy=$(host_path /etc/candy/sdwan)
	find "$legacy" -xdev -print | while IFS= read -r source; do
		[ "$source" != "$legacy" ] || continue
		relative=${source#"$legacy"/}
		case "$relative" in ''|/*|*[!A-Za-z0-9._/-]*|../*|*/../*|*/..|..) die "unsafe legacy SD-WAN state path: $source" ;; esac
		destination=$canonical/$relative
		if [ -L "$source" ]; then
			target=$(readlink "$source") || die "could not read legacy SD-WAN state link: $source"
			case "$target" in /*|../*|*/../*|*/..|..) die "unsafe legacy SD-WAN state link: $source" ;; esac
			if [ -L "$destination" ]; then
				[ "$(readlink "$destination")" = "$target" ] || die "conflicting SD-WAN state link: $destination"
			elif [ -e "$destination" ]; then
				die "conflicting SD-WAN state object: $destination"
			elif [ "$mode" = copy ]; then
				ln -s "$target" "$destination"
			fi
		elif [ -d "$source" ]; then
			if [ -L "$destination" ] || { [ -e "$destination" ] && [ ! -d "$destination" ]; }; then
				die "conflicting SD-WAN state directory: $destination"
			elif [ "$mode" = copy ] && [ ! -d "$destination" ]; then
				mkdir -m 0700 "$destination"
			fi
		elif [ -f "$source" ]; then
			if [ -f "$destination" ] && [ ! -L "$destination" ]; then
				cmp "$source" "$destination" >/dev/null || die "conflicting SD-WAN state file: $destination"
			elif [ -e "$destination" ] || [ -L "$destination" ]; then
				die "conflicting SD-WAN state object: $destination"
			elif [ "$mode" = copy ]; then
				cp -p "$source" "$destination"
			fi
		else
			die "unsupported legacy SD-WAN state object: $source"
		fi
	done
}

migrate_legacy_sdwan_state() {
	canonical=$(host_path /var/lib/candy/sdwan)
	legacy=$(host_path /etc/candy/sdwan)
	if [ -L "$canonical" ]; then
		canonical_target=$(readlink "$canonical") || die "could not read canonical SD-WAN state link"
		case "$canonical_target" in
			/etc/candy/sdwan|"$legacy") ;;
			*) die "canonical SD-WAN state link does not target /etc/candy/sdwan" ;;
		esac
		[ -d "$legacy" ] && [ ! -L "$legacy" ] ||
			die "reverse-linked legacy SD-WAN state is not a real directory"
		log "migrating reverse-linked Linux server SD-WAN state to /var/lib/candy/sdwan"
		rm -f "$canonical" || die "could not remove reverse SD-WAN state link"
		mkdir -m 0700 "$canonical" || {
			ln -s "$canonical_target" "$canonical" 2>/dev/null || true
			die "could not create the canonical SD-WAN state directory"
		}
		sdwan_reverse_link_target=$canonical_target
		sdwan_reverse_migration=1
		merge_legacy_sdwan_tree check
		merge_legacy_sdwan_tree copy
		sdwan_migration_pending=reverse-directory
	fi
	mkdir -p "$canonical"
	if [ "$sdwan_migration_pending" = reverse-directory ]; then
		:
	elif [ -L "$legacy" ]; then
		legacy_target=$(readlink "$legacy") || die "could not read legacy SD-WAN state link"
		case "$legacy_target" in
			/var/lib/candy/sdwan|"$canonical") sdwan_migration_pending=link ;;
			*) die "legacy SD-WAN state link does not target /var/lib/candy/sdwan" ;;
		esac
	elif [ -e "$legacy" ]; then
		[ -d "$legacy" ] || die "legacy SD-WAN state path is not a real directory: $legacy"
		log "migrating Linux server SD-WAN state from /etc/candy/sdwan to /var/lib/candy/sdwan"
		merge_legacy_sdwan_tree check
		merge_legacy_sdwan_tree copy
		sdwan_migration_pending=directory
	else
		sdwan_migration_pending=absent
	fi
	find "$canonical" -xdev -type d -exec chmod 0700 {} \;
	find "$canonical" -xdev -type f -exec chmod 0600 {} \;
	for compatibility_root in \
		"$canonical"/generations/*/compatibility-generations \
		"$canonical"/activations/*/compatibility-generations; do
		[ -d "$compatibility_root" ] || continue
		[ ! -L "$compatibility_root" ] || die "compatibility catalog must not be a symbolic link: $compatibility_root"
		find "$compatibility_root" -xdev -type f -exec chmod 0400 {} \;
		find "$compatibility_root" -xdev -type d -exec chmod 0500 {} \;
	done
	find "$canonical" -xdev ! -type l -exec chown candy:candy {} \;
}

finalize_legacy_sdwan_state() {
	legacy=$(host_path /etc/candy/sdwan)
	case "$sdwan_migration_pending" in
		link)
			[ -L "$legacy" ] || return 1
			legacy_target=$(readlink "$legacy") || return 1
			case "$legacy_target" in /var/lib/candy/sdwan|"$(host_path /var/lib/candy/sdwan)") ;; *) return 1 ;; esac
			;;
		directory|reverse-directory)
			[ -d "$legacy" ] && [ ! -L "$legacy" ] || return 1
			legacy_backup="$legacy.runtime-upgrade-backup.$$"
			[ ! -e "$legacy_backup" ] && [ ! -L "$legacy_backup" ] || return 1
			mv "$legacy" "$legacy_backup" || return 1
			if ! ln -s /var/lib/candy/sdwan "$legacy"; then
				mv "$legacy_backup" "$legacy" 2>/dev/null || true
				return 1
			fi
			find "$legacy_backup" -xdev -type d -exec chmod u+w {} \; 2>/dev/null || true
			rm -rf "$legacy_backup" ||
				log "warning: retained migrated SD-WAN backup at $legacy_backup"
			;;
		absent)
			[ ! -e "$legacy" ] && [ ! -L "$legacy" ] || return 1
			ln -s /var/lib/candy/sdwan "$legacy" || return 1
			;;
		'') ;;
	esac
}

restore_sdwan_reverse_migration() {
	[ "$sdwan_reverse_migration" = 1 ] || return 0
	canonical=$(host_path /var/lib/candy/sdwan)
	legacy=$(host_path /etc/candy/sdwan)
	[ -d "$canonical" ] && [ ! -L "$canonical" ] || return 1
	[ -d "$legacy" ] && [ ! -L "$legacy" ] || return 1
	find "$canonical" -xdev -type d -exec chmod u+w {} \; 2>/dev/null || true
	rm -rf "$canonical" || return 1
	ln -s "$sdwan_reverse_link_target" "$canonical"
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
	for relative in $legacy_files; do restore_one "/$relative"; done
	for unit in $unit_files; do restore_one "/etc/systemd/system/$unit"; done
	restore_one /usr/lib/tmpfiles.d/candy.conf
	restore_one "$SYSCTL_POLICY"
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
	migration_status=0
	restore_sdwan_reverse_migration || migration_status=1
	restore_files
	restore_current
	kernel_tuning_status=0
	restore_kernel_tuning || kernel_tuning_status=1
	"$SYSTEMCTL" daemon-reload >/dev/null 2>&1
	restore_service_state
	status=$?
	[ "$kernel_tuning_status" = 0 ] || status=1
	[ "$migration_status" = 0 ] || status=1
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

# Transaction behavior belongs to the release being installed. Once the
# current upgrader has authenticated and structurally validated the candidate,
# hand control to the candidate copy when it differs. The candidate's second
# validation sees an identical script and proceeds without recursion.
candidate_upgrader=$extract_dir/install/upgrade-candy-server.sh
[ -f "$candidate_upgrader" ] && [ -x "$candidate_upgrader" ] && [ ! -L "$candidate_upgrader" ] ||
	die "bundle candidate upgrader is missing or invalid"
if ! cmp -s "$0" "$candidate_upgrader"; then
	log "handing off transaction to the validated candidate upgrader"
	"$candidate_upgrader" --bundle-file "$bundle" --sha256 "$expected_sha256" --version "$EXPECTED_VERSION"
	transaction_finished=1
	cleanup
	trap - EXIT HUP INT TERM
	exit 0
fi

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

# Refuse mutation of protected parent trees even when a hostile host has replaced
# one with a link. migrate_legacy_sdwan_state separately validates the one
# supported historical child link before replacing it.
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
for relative in $legacy_files; do backup_one "/$relative"; done
for unit in $unit_files; do backup_one "/etc/systemd/system/$unit"; done
backup_one /usr/lib/tmpfiles.d/candy.conf
backup_one "$SYSCTL_POLICY"
record_kernel_tuning
transaction_started=1
stop_services
migrate_legacy_sdwan_state
install_kernel_tuning

mv "$release_stage" "$release_dir"
release_created=1
current_temporary=$(host_path "/opt/candy/.current.$$")
replace_symlink "$release_dir" "$current_link" "$current_temporary"

for relative in $managed_files; do install_one "$extract_dir/$relative" "/$relative" 0755; done
for relative in $legacy_files; do rm -f "$(host_path "/$relative")"; done
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

finalize_legacy_sdwan_state || die "could not establish the legacy /etc/candy/sdwan compatibility link"
transaction_finished=1
log "Runtime $EXPECTED_VERSION installed; configuration, enrollment, SD-WAN state, and Core were preserved"
cleanup
trap - EXIT HUP INT TERM
