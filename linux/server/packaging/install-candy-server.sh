#!/bin/sh
set -eu

INSTALL_PREFIX=/opt/candy
CONFIG_DIR=/etc/candy
STATE_DIR=/var/lib/candy
BACKUP_DIR=/var/backups/candy
SERVICE_PATH=/etc/systemd/system/candy-server.service
SERVICE_NAME=candy-server
SERVICE_USER=candy
LISTEN_ADDR=0.0.0.0:8443
TLS_NAME=candy-server
PUBLIC_HOST=
ARTIFACT_FILE=
ARTIFACT_URL=
VERSION=latest
FORCE_CONFIG=0
DRY_RUN=0
LEGACY_ROOT=/root/candy
DEFAULT_ARTIFACT_BASE_URL=${CANDY_RELEASE_BASE_URL:-}
CORE_BINARY=${CANDY_CORE_BINARY:-/opt/candy/cores/current/candy-core}
EXPECTED_CORE_PROCESS_API=1

usage() {
	cat <<'EOF'
usage: install-candy-server.sh [options]

Options:
  --artifact-file PATH   Use an already uploaded Candy server artifact.
  --artifact-url URL     Download this exact Candy server artifact.
  --version VERSION      Resolve the artifact URL for a release version.
  --core-binary PATH     Active private candy-core executable.
  --listen ADDR          Server listen address, default 0.0.0.0:8443.
  --tls-name NAME        Self-signed certificate name, default candy-server.
  --public-host HOST     Override the auto-detected public server address.
  --force-config         Regenerate /etc/candy/server.toml.
  --dry-run              Print planned actions without changing the host.
  -h, --help             Show this help.
EOF
}

log() {
	printf '%s\n' "$*"
}

die() {
	printf '%s\n' "install-candy-server: $*" >&2
	exit 1
}

run() {
	if [ "$DRY_RUN" = 1 ]; then
		printf 'dry-run:'
		printf ' %s' "$@"
		printf '\n'
	else
		"$@"
	fi
}

need_command() {
	command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

case "${1:-}" in
	-h|--help)
		usage
		exit 0
		;;
esac

if [ "$(id -u)" != 0 ]; then
	if command -v sudo >/dev/null 2>&1; then
		exec sudo sh "$0" "$@"
	fi
	die "run as root or install sudo"
fi

while [ "$#" -gt 0 ]; do
	case "$1" in
		--artifact-file)
			shift
			[ "$#" -gt 0 ] || die "--artifact-file requires a path"
			ARTIFACT_FILE=$1
			;;
		--artifact-url)
			shift
			[ "$#" -gt 0 ] || die "--artifact-url requires a URL"
			ARTIFACT_URL=$1
			;;
		--version)
			shift
			[ "$#" -gt 0 ] || die "--version requires a value"
			VERSION=$1
			;;
		--core-binary)
			shift
			[ "$#" -gt 0 ] || die "--core-binary requires a path"
			CORE_BINARY=$1
			;;
		--listen)
			shift
			[ "$#" -gt 0 ] || die "--listen requires an address"
			LISTEN_ADDR=$1
			;;
		--tls-name)
			shift
			[ "$#" -gt 0 ] || die "--tls-name requires a name"
			TLS_NAME=$1
			;;
		--public-host)
			shift
			[ "$#" -gt 0 ] || die "--public-host requires a host or IP address"
			PUBLIC_HOST=$1
			;;
		--force-config)
			FORCE_CONFIG=1
			;;
		--dry-run)
			DRY_RUN=1
			;;
		*)
			die "unknown option: $1"
			;;
	esac
	shift
done

need_command systemctl
need_command openssl

if [ "$DRY_RUN" = 1 ]; then
	log "Candy server dry run"
	log "artifact-file: ${ARTIFACT_FILE:-<download>}"
	log "artifact-url: ${ARTIFACT_URL:-<resolved from version $VERSION>}"
	log "install-prefix: $INSTALL_PREFIX"
	log "core-binary: $CORE_BINARY"
	log "config: $CONFIG_DIR/server.toml"
	log "state: $STATE_DIR"
	log "backup: $BACKUP_DIR"
	log "listen: $LISTEN_ADDR"
	log "tls-name: $TLS_NAME"
	log "public-host: ${PUBLIC_HOST:-<auto-detect>}"
	exit 0
fi

case "$(uname -s)" in
	Linux) ;;
	*) die "Candy server installer supports Linux only" ;;
esac

case "$CORE_BINARY" in
	/*) ;;
	*) die "--core-binary must be an absolute path: $CORE_BINARY" ;;
esac
case "$CORE_BINARY" in
	*[!A-Za-z0-9_./+-]*) die "--core-binary contains characters unsafe for a systemd Environment value: $CORE_BINARY" ;;
esac
[ -f "$CORE_BINARY" ] && [ -x "$CORE_BINARY" ] ||
	die "active Candy Core is missing or not executable: $CORE_BINARY; install and activate Core before installing Runtime"
core_process_api=$("$CORE_BINARY" runtime-api-version) ||
	die "failed to inspect Candy Core process API: $CORE_BINARY runtime-api-version"
[ "$core_process_api" = "$EXPECTED_CORE_PROCESS_API" ] ||
	die "incompatible Candy Core process API '$core_process_api'; Runtime requires $EXPECTED_CORE_PROCESS_API"

arch=$(uname -m)
case "$arch" in
	x86_64|amd64)
		artifact_name=serverd-linux-x86_64
		;;
	aarch64|arm64)
		artifact_name=serverd-linux-aarch64
		;;
	*)
		die "unsupported architecture: $arch"
		;;
esac

if [ -n "$ARTIFACT_FILE" ] && [ -n "$ARTIFACT_URL" ]; then
	die "use only one of --artifact-file or --artifact-url"
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/candy-server-install.XXXXXX")
artifact_path=$work_dir/$artifact_name
release_id=$(date +%Y%m%d%H%M%S)
release_dir=$INSTALL_PREFIX/releases/$release_id
current_link=$INSTALL_PREFIX/current
config_file=$CONFIG_DIR/server.toml
tls_dir=$STATE_DIR/tls
cert_file=/var/lib/candy/tls/server.crt
key_file=/var/lib/candy/tls/server.key
previous_current=
previous_unit=$work_dir/previous-candy-server.service
had_previous_unit=0
previous_service_active=0
config_backup=
config_changed=0
cert_sha256=

cleanup() {
	rm -rf "$work_dir"
}
trap cleanup EXIT HUP INT TERM

rollback() {
	set +e
	rollback_failed=0
	log "rollback: restoring previous Candy server state"
	run systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
	if [ -n "$previous_current" ] && [ -e "$previous_current" ]; then
		run ln -sfn "$previous_current" "$current_link"
	else
		run rm -f "$current_link"
	fi
	if [ "$had_previous_unit" = 1 ]; then
		run cp "$previous_unit" "$SERVICE_PATH"
	else
		run systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
		run rm -f "$SERVICE_PATH"
	fi
	if [ "$config_changed" = 1 ]; then
		if [ -n "$config_backup" ]; then
			run cp "$config_backup" "$config_file"
		else
			run rm -f "$config_file"
		fi
	fi
	run systemctl daemon-reload
	if [ "$previous_service_active" = 1 ]; then
		run systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || rollback_failed=1
	fi
	set -e
	[ "$rollback_failed" = 0 ]
}

download_artifact() {
	if [ -n "$ARTIFACT_FILE" ]; then
		[ -f "$ARTIFACT_FILE" ] || die "artifact file not found: $ARTIFACT_FILE"
		run cp "$ARTIFACT_FILE" "$artifact_path"
		return
	fi

	if [ -z "$ARTIFACT_URL" ]; then
		[ -n "$DEFAULT_ARTIFACT_BASE_URL" ] || die "provide --artifact-file, --artifact-url, or CANDY_RELEASE_BASE_URL"
		if [ "$VERSION" = latest ]; then
			ARTIFACT_URL=$DEFAULT_ARTIFACT_BASE_URL/latest/$artifact_name
		else
			ARTIFACT_URL=$DEFAULT_ARTIFACT_BASE_URL/$VERSION/$artifact_name
		fi
	fi

	if command -v curl >/dev/null 2>&1; then
		run curl -fsSL "$ARTIFACT_URL" -o "$artifact_path"
	elif command -v wget >/dev/null 2>&1; then
		run wget -qO "$artifact_path" "$ARTIFACT_URL"
	else
		die "missing curl or wget for artifact download"
	fi
}

create_service_user() {
	if id "$SERVICE_USER" >/dev/null 2>&1; then
		return
	fi
	if command -v useradd >/dev/null 2>&1; then
		run useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
	elif command -v adduser >/dev/null 2>&1; then
		run adduser -S -D -H -h "$STATE_DIR" -s /sbin/nologin "$SERVICE_USER"
	else
		die "missing useradd/adduser"
	fi
}

random_secret() {
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -hex 32
	else
		od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
	fi
}

write_default_config() {
	secret=$(random_secret)
	cat >"$config_file" <<EOF
listen = "$LISTEN_ADDR"
cert_pem = "$cert_file"
key_pem = "$key_file"

[port_hopping]
ports = []

[[users]]
key_id = "router-1"
secret = "$secret"
features = ["recommended"]
EOF
	chmod 0640 "$config_file"
	run chown root:"$SERVICE_USER" "$config_file"
}

validate_config_policy() {
	if grep -Eq 'secret[[:space:]]*=[[:space:]]*"replace-with-at-least-16-random-bytes"|secret[[:space:]]*=[[:space:]]*"change-me-long-random-secret"' "$config_file"; then
		die "$config_file contains a placeholder authentication secret; use --force-config or edit it"
	fi
	if grep -Eq '^development_ephemeral_certificate[[:space:]]*=[[:space:]]*true' "$config_file"; then
		die "$config_file enables development_ephemeral_certificate; configure persistent cert_pem/key_pem instead"
	fi
}

extract_config_value() {
	key=$1
	awk -F= -v key="$key" '
		$1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
			gsub(/^[[:space:]"]+|[[:space:]"]+$/, "", $2)
			print $2
			exit
		}
	' "$config_file"
}

detect_public_host() {
	if [ -n "$PUBLIC_HOST" ]; then
		printf '%s\n' "$PUBLIC_HOST"
		return
	fi

	if command -v curl >/dev/null 2>&1; then
		candidate=$(curl -4 -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true)
		case "$candidate" in
			''|*[!0-9.]*) ;;
			*) printf '%s\n' "$candidate"; return ;;
		esac
	fi

	hostname -I 2>/dev/null | awk '{ print $1 }'
}

ensure_tls() {
	if [ -s "$cert_file" ] && [ -s "$key_file" ]; then
		return
	fi
	log "Generating persistent Candy self-signed TLS certificate"
	run openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
		-keyout "$key_file" \
		-out "$cert_file" \
		-subj "/CN=$TLS_NAME" \
		-addext "subjectAltName=DNS:$TLS_NAME" >/dev/null 2>&1
	run chmod 0600 "$key_file"
	run chmod 0644 "$cert_file"
	run chown "$SERVICE_USER:$SERVICE_USER" "$cert_file" "$key_file"
}

install_unit() {
	cat >"$SERVICE_PATH" <<EOF
[Unit]
Description=Candy server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$STATE_DIR
Environment=CANDY_CORE_BINARY=$CORE_BINARY
ExecStart=$current_link/serverd-linux --config $config_file
Restart=on-failure
RestartSec=2s
LimitNOFILE=1048576
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
}

verify_udp_listener() {
	port=$(printf '%s' "$effective_listen" | awk -F: '{print $NF}')
	port_hex=$(printf '%04X' "$port")
	attempt=0
	while [ "$attempt" -lt 10 ]; do
		if command -v ss >/dev/null 2>&1; then
			ss -lunp | grep -E "[:.]$port([[:space:]]|$)" >/dev/null && return 0
		elif grep -Eiq "[[:xdigit:]]{8}:$port_hex[[:space:]]" /proc/net/udp /proc/net/udp6 2>/dev/null; then
			return 0
		fi
		attempt=$((attempt + 1))
		sleep 1
	done
	return 1
}

legacy_migrate() {
	if [ -d "$LEGACY_ROOT" ] && [ ! -f "$config_file" ]; then
		log "Migrating legacy Candy server config from $LEGACY_ROOT"
		if [ -f "$LEGACY_ROOT/server.toml" ]; then
			sed \
				-e "s#$LEGACY_ROOT/candy-data/server\.crt#$cert_file#g" \
				-e "s#$LEGACY_ROOT/candy-data/server\.key#$key_file#g" \
				"$LEGACY_ROOT/server.toml" >"$work_dir/migrated-server.toml"
			run cp "$work_dir/migrated-server.toml" "$config_file"
		fi
		if [ -f "$LEGACY_ROOT/candy-data/server.crt" ] && [ -f "$LEGACY_ROOT/candy-data/server.key" ]; then
			run cp "$LEGACY_ROOT/candy-data/server.crt" "$cert_file"
			run cp "$LEGACY_ROOT/candy-data/server.key" "$key_file"
		fi
	fi
}

print_client_output() {
	key_id=$(extract_config_value key_id || true)
	secret=$(extract_config_value secret || true)
	host=$(detect_public_host)
	[ -n "$host" ] || host=$(hostname 2>/dev/null || printf '%s' "$TLS_NAME")
	server_port=${effective_listen##*:}
	case "$effective_listen" in
		0.0.0.0:*|\[::\]:*)
			case "$host" in
				*:*) server="[$host]:$server_port" ;;
				*) server="$host:$server_port" ;;
			esac
			;;
		*) server=$effective_listen ;;
	esac
	cat <<EOF
Candy server installed.

密钥 ID: ${key_id:-router-1}
服务器地址: $server
TLS 服务器名: $effective_tls_name
服务器证书指纹: $cert_sha256
认证密钥: ${secret:-preserved in $config_file}
EOF
}

download_artifact
[ -s "$artifact_path" ] || die "server Runtime launcher is empty: $artifact_path"
run chmod 0755 "$artifact_path"

create_service_user
run mkdir -p "$INSTALL_PREFIX/releases" "$CONFIG_DIR" "$tls_dir" "$STATE_DIR/candy-data" "$BACKUP_DIR"
run chown "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR" "$STATE_DIR/candy-data" "$tls_dir"

if [ -L "$current_link" ]; then
	previous_current=$(readlink "$current_link")
fi
if [ -f "$SERVICE_PATH" ]; then
	had_previous_unit=1
	cp "$SERVICE_PATH" "$previous_unit"
fi
if systemctl is-active --quiet "$SERVICE_NAME"; then
	previous_service_active=1
fi

legacy_migrate
ensure_tls

if [ "$FORCE_CONFIG" = 1 ] || [ ! -f "$config_file" ]; then
	config_changed=1
	if [ -f "$config_file" ]; then
		config_backup=$BACKUP_DIR/server.toml.$release_id
		run cp "$config_file" "$config_backup"
	fi
	write_default_config
fi
validate_config_policy
effective_listen=$(extract_config_value listen || true)
[ -n "$effective_listen" ] || die "$config_file does not define listen"
effective_tls_name=$TLS_NAME
effective_cert_file=$(extract_config_value cert_pem || true)
if [ -n "$effective_cert_file" ] && [ -s "$effective_cert_file" ]; then
	cert_name=$(openssl x509 -in "$effective_cert_file" -noout -ext subjectAltName 2>/dev/null \
		| sed -n 's/.*DNS:\([^, ]*\).*/\1/p' | head -n 1)
	if [ -z "$cert_name" ]; then
		cert_name=$(openssl x509 -in "$effective_cert_file" -noout -subject 2>/dev/null \
			| sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,\/]*\).*/\1/p' | head -n 1)
	fi
	[ -n "$cert_name" ] && effective_tls_name=$cert_name
fi

run mkdir -p "$release_dir"
run cp "$artifact_path" "$release_dir/serverd-linux"
run chmod 0755 "$release_dir/serverd-linux"
run chown -R root:root "$release_dir"
install_unit
run systemctl daemon-reload

if ! CANDY_CORE_BINARY="$CORE_BINARY" "$release_dir/serverd-linux" --config "$config_file" --check-config; then
	rollback
	die "config check failed"
fi
run systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
preflight_output=$(CANDY_CORE_BINARY="$CORE_BINARY" "$release_dir/serverd-linux" --config "$config_file" --preflight 2>&1) || {
	printf '%s\n' "$preflight_output" >&2
	rollback
	die "preflight failed"
}
cert_sha256=$(printf '%s\n' "$preflight_output" | awk -F\" '/"cert_sha256"/ { print $4; exit }')
run ln -sfn "$release_dir" "$current_link"
if ! run systemctl enable --now "$SERVICE_NAME"; then
	rollback
	die "failed to start $SERVICE_NAME"
fi
verification_error=
if ! run systemctl is-active "$SERVICE_NAME" >/dev/null; then
	verification_error="$SERVICE_NAME is not active after startup"
else
	restarts=$(systemctl show "$SERVICE_NAME" -p NRestarts --value 2>/dev/null) || verification_error="failed to read $SERVICE_NAME restart count"
	if [ -z "$verification_error" ] && [ "${restarts:-0}" -ne 0 ]; then
		verification_error="$SERVICE_NAME restarted during verification: NRestarts=$restarts"
	fi
	if [ -z "$verification_error" ] && ! verify_udp_listener; then
		verification_error="Candy server UDP listen socket not found"
	fi
fi
if [ -n "$verification_error" ]; then
	if ! rollback; then
		die "$verification_error; rollback also failed to restore the previous service"
	fi
	die "$verification_error; previous service state restored"
fi
journalctl -u "$SERVICE_NAME" -n 20 --no-pager >/dev/null || true
print_client_output
