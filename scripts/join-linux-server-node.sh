#!/bin/sh
set -eu

bootstrap_file=
node_host=
node_user=
node_port=22
runtime_bundle=
runtime_sha256=
public_endpoint=
log_file=

usage() {
	cat <<'EOF'
usage: join-linux-server-node.sh --bootstrap-file FILE --node HOST [options]

The SSH client performs authentication normally. Prefer an authorized SSH key;
this script never accepts or stores an SSH password.

Options:
  --bootstrap-file FILE   Short-lived, single-use JSON downloaded from Cloud.
  --node HOST             Linux server hostname or IP.
  --user USER             SSH user, default current user.
  --port PORT             SSH port, default 22.
  --runtime-bundle FILE   Optional complete candy-server-runtime bundle.
  --runtime-sha256 HEX    Required SHA-256 when a bundle is supplied.
  --public-endpoint ADDR  Required inbound SD-WAN endpoint (HOST:PORT).
  --log FILE              Append a credential-free execution record.
EOF
}

event() {
	timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	printf '%s stage=%s result=%s%s\n' "$timestamp" "$1" "$2" "${3:+ detail=$3}" >&2
	[ -z "$log_file" ] || printf '%s stage=%s result=%s%s\n' "$timestamp" "$1" "$2" "${3:+ detail=$3}" >>"$log_file"
}
fail() {
	event failure failed "$*"
	printf '%s\n' "join-linux-server-node: $*" >&2
	exit 1
}
cleanup() {
	[ -z "${remote_bundle:-}" ] || ssh -p "$node_port" "$ssh_target" "rm -f '$remote_bundle'" >/dev/null 2>&1 || true
	[ -z "${remote_bootstrap:-}" ] || ssh -p "$node_port" "$ssh_target" "rm -f '$remote_bootstrap'" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

while [ "$#" -gt 0 ]; do
	case "$1" in
		--bootstrap-file) shift; [ "$#" -gt 0 ] || fail "--bootstrap-file requires a file"; bootstrap_file=$1 ;;
		--node) shift; [ "$#" -gt 0 ] || fail "--node requires a host"; node_host=$1 ;;
		--user) shift; [ "$#" -gt 0 ] || fail "--user requires a value"; node_user=$1 ;;
		--port) shift; [ "$#" -gt 0 ] || fail "--port requires a value"; node_port=$1 ;;
		--runtime-bundle) shift; [ "$#" -gt 0 ] || fail "--runtime-bundle requires a file"; runtime_bundle=$1 ;;
		--runtime-sha256) shift; [ "$#" -gt 0 ] || fail "--runtime-sha256 requires a digest"; runtime_sha256=$1 ;;
		--public-endpoint) shift; [ "$#" -gt 0 ] || fail "--public-endpoint requires HOST:PORT"; public_endpoint=$1 ;;
		--log) shift; [ "$#" -gt 0 ] || fail "--log requires a file"; log_file=$1 ;;
		-h|--help) usage; exit 0 ;;
		*) fail "unknown option: $1" ;;
	esac
	shift
done

[ -n "$bootstrap_file" ] || fail "--bootstrap-file is required"
[ -f "$bootstrap_file" ] && [ ! -L "$bootstrap_file" ] || fail "Bootstrap input must be a regular file"
bootstrap_bytes=$(wc -c <"$bootstrap_file" | tr -d ' ')
[ "$bootstrap_bytes" -gt 0 ] && [ "$bootstrap_bytes" -le 16384 ] || fail "Bootstrap input must be at most 16 KiB"
[ -n "$node_host" ] || fail "--node is required"
[ -n "$public_endpoint" ] || fail "--public-endpoint is required; Candy never guesses a node's public address"
case "$public_endpoint" in
	''|*[!A-Za-z0-9._:\[\]-]*) fail "--public-endpoint must be a plain HOST:PORT value" ;;
esac
case "$public_endpoint" in
	\[*\]:*)
		public_host=${public_endpoint%:*}; public_host=${public_host#\[}; public_host=${public_host%\]}
		case "$public_host" in ''|*[!0-9A-Fa-f:.]*) fail "--public-endpoint must contain a numeric IP address" ;; esac
		;;
	*:*:*) fail "IPv6 public endpoints must use [ADDRESS]:PORT" ;;
	*:*)
		public_host=${public_endpoint%:*}
		case "$public_host" in ''|*[!0-9.]*) fail "--public-endpoint must contain a numeric IP address" ;; esac
		printf '%s\n' "$public_host" | awk -F. '
			NF != 4 { exit 1 }
			{ for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i > 255) exit 1 }
		' || fail "--public-endpoint contains an invalid IPv4 address"
		;;
	*) fail "--public-endpoint must include a port" ;;
esac
public_port=${public_endpoint##*:}
case "$public_port" in ''|*[!0-9]*) fail "--public-endpoint port must be numeric" ;; esac
[ "$public_port" -ge 1 ] && [ "$public_port" -le 65535 ] || fail "--public-endpoint port is outside 1..65535"
case "$public_host" in ''|'*'|0.0.0.0|::) fail "--public-endpoint must identify a concrete reachable IP address" ;; esac
[ -n "$node_user" ] || node_user=$(id -un)
case "$node_port" in ''|*[!0-9]*) fail "--port must be numeric" ;; esac
[ "$node_port" -ge 1 ] && [ "$node_port" -le 65535 ] || fail "--port is outside 1..65535"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v ssh >/dev/null 2>&1 || fail "ssh is required"
command -v scp >/dev/null 2>&1 || fail "scp is required"
cloud_url=$(jq -er 'select(.schema_version == 1) | .cloud_address | select(startswith("https://"))' "$bootstrap_file") ||
	fail "Bootstrap file is not a supported HTTPS Candy Cloud document"
jq -e '.bootstrap_code | type == "string" and length >= 32' "$bootstrap_file" >/dev/null ||
	fail "Bootstrap file lacks a valid single-use code"
jq -e '.expires_at | type == "string" and length > 0' "$bootstrap_file" >/dev/null ||
	fail "Bootstrap file lacks an expiration"
ssh_target=$node_user@$node_host
if [ -n "$log_file" ]; then
	umask 077
	case "$log_file" in */*) mkdir -p "${log_file%/*}" ;; esac
	touch "$log_file"
	chmod 0600 "$log_file"
fi

event preflight started "node=$node_host"
remote_arch=$(ssh -p "$node_port" "$ssh_target" 'test "$(uname -s)" = Linux; command -v sudo >/dev/null; sudo -n true; command -v systemctl >/dev/null; uname -m') ||
	fail "remote Linux preflight failed"
case "$remote_arch" in
	x86_64|amd64) artifact_arch=x86_64 ;;
	aarch64|arm64) artifact_arch=aarch64 ;;
	*) fail "remote Linux architecture is unsupported: $remote_arch" ;;
esac

configure_public_endpoint() {
	ssh -p "$node_port" "$ssh_target" "set -eu; sudo install -d -m 0755 /etc/candy; temporary=\$(sudo mktemp /etc/candy/.cloud-sync.env.XXXXXX); trap 'sudo rm -f \"\$temporary\"' EXIT; printf '%s\\n' 'CANDY_PUBLIC_ENDPOINT=$public_endpoint' | sudo tee \"\$temporary\" >/dev/null; sudo chown root:candy \"\$temporary\"; sudo chmod 0640 \"\$temporary\"; sudo mv -f \"\$temporary\" /etc/candy/cloud-sync.env; trap - EXIT" ||
		fail "could not persist the explicit public endpoint"
	event endpoint succeeded "address=$public_endpoint"
}

existing_status_raw=$(ssh -p "$node_port" "$ssh_target" '
	if test -x /usr/local/libexec/candy-cloud-sync &&
		test -f /etc/systemd/system/candy-cloud-sync.service &&
		test -f /etc/systemd/system/candy-cloud-sync.timer; then
		printf "%s\\n" __candy_runtime_ready__
	fi
	sudo /usr/local/bin/candy-server sdwan status 2>/dev/null
' || true)
# A legacy server can report a persisted registration while lacking the
# Runtime-owned Cloud sync units. Only use the idempotent fast path when the
# complete sync runtime is installed; otherwise install the supplied bundle
# before attempting to resume that registration.
if printf '%s\n' "$existing_status_raw" | grep -Fxq __candy_runtime_ready__; then
	existing_runtime_ready=true
else
	existing_runtime_ready=false
fi
existing_status=$(printf '%s\n' "$existing_status_raw" | grep -Fvx __candy_runtime_ready__ || true)
if [ "$existing_runtime_ready" = true ] && printf '%s' "$existing_status" | jq -e --arg cloud "$cloud_url" \
	'.schema_version == 1 and .registration.state == "registered" and .registration.cloud_address == $cloud' >/dev/null 2>&1; then
	configure_public_endpoint
	ssh -p "$node_port" "$ssh_target" 'sudo systemctl is-active --quiet candy-netd; sudo systemctl is-active --quiet candy-server' ||
		fail "registered node services are not healthy"
	ssh -p "$node_port" "$ssh_target" 'set -eu; sudo systemctl enable --now candy-cloud-sync.timer >/dev/null; sudo systemctl start candy-cloud-sync.service; sudo systemctl is-active --quiet candy-cloud-sync.timer' ||
		fail "registered node Cloud synchronization is not healthy"
	status=$(ssh -p "$node_port" "$ssh_target" 'sudo /usr/local/bin/candy-server sdwan status') || fail "node status query failed"
	printf '%s' "$status" | jq -e '.schema_version == 1 and .registration.state == "registered" and (.runtime.state == "stopped" or .runtime.state == "running")' >/dev/null ||
		fail "registered node did not return to a healthy SD-WAN state"
	event verification succeeded "already_registered=true ordinary_service=active sdwan=registered"
	printf '%s\n' "$status"
	exit 0
fi

if [ -n "$runtime_bundle" ]; then
	[ -f "$runtime_bundle" ] || fail "Runtime bundle does not exist"
	case "$runtime_sha256" in
		*[!0-9a-fA-F]*|'') fail "--runtime-sha256 must be exactly 64 hexadecimal characters" ;;
	esac
	[ "${#runtime_sha256}" -eq 64 ] || fail "--runtime-sha256 must be exactly 64 hexadecimal characters"
	runtime_sha256=$(printf '%s' "$runtime_sha256" | tr 'A-F' 'a-f')
	actual_sha256=$(shasum -a 256 "$runtime_bundle" | awk '{print $1}')
	[ "$actual_sha256" = "$runtime_sha256" ] || fail "Runtime bundle SHA-256 mismatch"
	remote_bundle=/tmp/candy-server-runtime-$artifact_arch.$$.tar.gz
	scp -P "$node_port" "$runtime_bundle" "$ssh_target:$remote_bundle"
	ssh -p "$node_port" "$ssh_target" "set -eu; test \"\$(sha256sum '$remote_bundle' | awk '{print \$1}')\" = '$runtime_sha256'; stage=\$(mktemp -d); trap 'rm -rf \"\$stage\"' EXIT; tar -xzf '$remote_bundle' -C \"\$stage\"; for path in usr/local/bin/candy-server usr/local/libexec/candy-sdwan-runtime usr/local/libexec/candy-cloud-enroll usr/local/libexec/candy-cloud-sync usr/local/libexec/candy-sdwan-agent usr/local/libexec/candy-netd systemd/candy-netd.service systemd/candy-cloud-sync.service systemd/candy-cloud-sync.timer systemd/candy.tmpfiles; do test -f \"\$stage/\$path\"; done; sudo install -d -m 0755 /usr/local/bin /usr/local/libexec; sudo install -m 0755 \"\$stage/usr/local/bin/candy-server\" /usr/local/bin/candy-server; for name in candy-sdwan-runtime candy-cloud-enroll candy-cloud-sync candy-sdwan-agent candy-netd; do sudo install -m 0755 \"\$stage/usr/local/libexec/\$name\" \"/usr/local/libexec/\$name\"; sudo test -x \"/usr/local/libexec/\$name\"; done; for unit in candy-netd.service candy-cloud-sync.service candy-cloud-sync.timer; do sudo install -m 0644 \"\$stage/systemd/\$unit\" \"/etc/systemd/system/\$unit\"; done; sudo install -d -m 0755 /usr/lib/tmpfiles.d; sudo install -m 0644 \"\$stage/systemd/candy.tmpfiles\" /usr/lib/tmpfiles.d/candy.conf; sudo test ! -L /var/lib/candy/sdwan; sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/candy.conf; sudo find /var/lib/candy/sdwan -xdev -type d -exec chmod 0700 {} \\;; sudo find /var/lib/candy/sdwan -xdev -type f -exec chmod 0600 {} \\;; sudo systemctl daemon-reload; sudo systemctl enable --now candy-netd.service; sudo systemctl is-active --quiet candy-netd.service; rm -f '$remote_bundle'"
	remote_bundle=
	event runtime_install succeeded
fi

ssh -p "$node_port" "$ssh_target" 'test -x /usr/local/bin/candy-server; test -x /usr/local/libexec/candy-sdwan-runtime; test -x /usr/local/libexec/candy-cloud-enroll; test -x /usr/local/libexec/candy-cloud-sync; test -x /usr/local/libexec/candy-sdwan-agent; test -x /usr/local/libexec/candy-netd; test -f /etc/systemd/system/candy-cloud-sync.service; test -f /etc/systemd/system/candy-cloud-sync.timer; sudo systemctl is-active --quiet candy-netd; sudo systemctl is-active --quiet candy-server' ||
	fail "node lacks a complete Runtime or ordinary Candy service is not active"
configure_public_endpoint

# Installing a newer Runtime can complete the local Cloud sync runtime for a
# node that was already enrolled by an older release. Reuse that identity
# after the upgrade instead of attempting a second bootstrap, which the Cloud
# identity store must (correctly) reject.
if printf '%s' "$existing_status" | jq -e --arg cloud "$cloud_url" \
	'.schema_version == 1 and .registration.state == "registered" and .registration.cloud_address == $cloud' >/dev/null 2>&1; then
	ssh -p "$node_port" "$ssh_target" 'set -eu; sudo systemctl enable --now candy-cloud-sync.timer >/dev/null; sudo systemctl start candy-cloud-sync.service; sudo systemctl is-active --quiet candy-cloud-sync.timer' ||
		fail "registered node Cloud synchronization is not healthy after Runtime installation"
	status=$(ssh -p "$node_port" "$ssh_target" 'sudo /usr/local/bin/candy-server sdwan status') || fail "node status query failed"
	printf '%s' "$status" | jq -e '.schema_version == 1 and .registration.state == "registered" and (.runtime.state == "stopped" or .runtime.state == "running")' >/dev/null ||
		fail "registered node did not return to a healthy SD-WAN state after Runtime installation"
	ssh -p "$node_port" "$ssh_target" 'sudo systemctl is-active --quiet candy-server' || fail "ordinary Candy service stopped during Runtime installation"
	event verification succeeded "already_registered=true runtime_upgraded=true ordinary_service=active sdwan=registered"
	printf '%s\n' "$status"
	exit 0
fi

remote_bootstrap=/tmp/candy-node-bootstrap.$$.json
scp -q -P "$node_port" "$bootstrap_file" "$ssh_target:$remote_bootstrap" || fail "Bootstrap upload failed"
ssh -p "$node_port" "$ssh_target" "set -eu; chmod 0600 '$remote_bootstrap'; test \"\$(stat -c '%a' '$remote_bootstrap')\" = 600; sudo /usr/local/bin/candy-server bootstrap '$remote_bootstrap'" ||
	fail "Cloud bootstrap exchange failed; the local Bootstrap file remains available for an idempotent retry"
remote_bootstrap=
event enrollment succeeded "cloud=$cloud_url"

ssh -p "$node_port" "$ssh_target" 'set -eu; sudo systemctl enable --now candy-cloud-sync.timer >/dev/null; sudo systemctl start candy-cloud-sync.service; sudo systemctl is-active --quiet candy-cloud-sync.timer' ||
	fail "Cloud synchronization did not start after enrollment"

status=$(ssh -p "$node_port" "$ssh_target" 'sudo /usr/local/bin/candy-server sdwan status') || fail "node status query failed"
printf '%s' "$status" | jq -e '.schema_version == 1 and .registration.state == "registered" and (.runtime.state == "stopped" or .runtime.state == "running")' >/dev/null ||
	fail "node did not reach a healthy registered state"
ssh -p "$node_port" "$ssh_target" 'sudo systemctl is-active --quiet candy-server' || fail "ordinary Candy service stopped during enrollment"
event verification succeeded "ordinary_service=active sdwan=registered"
printf '%s\n' "$status"
