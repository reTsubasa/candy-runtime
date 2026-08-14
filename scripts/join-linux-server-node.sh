#!/bin/sh
set -eu

bootstrap_file=
node_host=
node_user=
node_port=22
runtime_bundle=
runtime_sha256=
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
ssh -p "$node_port" "$ssh_target" 'test "$(uname -s)" = Linux; test "$(uname -m)" = aarch64; command -v sudo >/dev/null; sudo -n true; command -v systemctl >/dev/null' ||
	fail "remote Linux ARM64 preflight failed"

existing_status=$(ssh -p "$node_port" "$ssh_target" 'sudo /usr/local/bin/candy-server sdwan status 2>/dev/null' || true)
if printf '%s' "$existing_status" | jq -e --arg cloud "$cloud_url" \
	'.schema_version == 1 and .registration.state == "registered" and .registration.cloud_address == $cloud and .runtime.state == "stopped"' >/dev/null 2>&1; then
	ssh -p "$node_port" "$ssh_target" 'sudo systemctl is-active --quiet candy-netd; sudo systemctl is-active --quiet candy-server' ||
		fail "registered node services are not healthy"
	event verification succeeded "already_registered=true ordinary_service=active sdwan=registered/stopped"
	printf '%s\n' "$existing_status"
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
	remote_bundle=/tmp/candy-server-runtime-aarch64.$$.tar.gz
	scp -P "$node_port" "$runtime_bundle" "$ssh_target:$remote_bundle"
	ssh -p "$node_port" "$ssh_target" "set -eu; test \"\$(sha256sum '$remote_bundle' | awk '{print \$1}')\" = '$runtime_sha256'; stage=\$(mktemp -d); trap 'rm -rf \"\$stage\"' EXIT; tar -xzf '$remote_bundle' -C \"\$stage\"; for path in usr/local/bin/candy-server usr/local/libexec/candy-sdwan-runtime usr/local/libexec/candy-cloud-enroll usr/local/libexec/candy-sdwan-agent usr/local/libexec/candy-netd systemd/candy-netd.service systemd/candy-sdwan.service systemd/candy.sysusers systemd/candy.tmpfiles; do test -f \"\$stage/\$path\"; done; sudo install -d -m 0755 /usr/local/bin /usr/local/libexec; sudo install -m 0755 \"\$stage/usr/local/bin/candy-server\" /usr/local/bin/candy-server; for name in candy-sdwan-runtime candy-cloud-enroll candy-sdwan-agent candy-netd; do sudo install -m 0755 \"\$stage/usr/local/libexec/\$name\" \"/usr/local/libexec/\$name\"; sudo test -x \"/usr/local/libexec/\$name\"; done; sudo install -m 0644 \"\$stage/systemd/candy-netd.service\" /etc/systemd/system/candy-netd.service; sudo install -m 0644 \"\$stage/systemd/candy-sdwan.service\" /etc/systemd/system/candy-sdwan.service; sudo install -d -m 0755 /usr/lib/sysusers.d /usr/lib/tmpfiles.d; sudo install -m 0644 \"\$stage/systemd/candy.sysusers\" /usr/lib/sysusers.d/candy.conf; sudo install -m 0644 \"\$stage/systemd/candy.tmpfiles\" /usr/lib/tmpfiles.d/candy.conf; sudo systemd-sysusers /usr/lib/sysusers.d/candy.conf; sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/candy.conf; sudo systemctl daemon-reload; sudo systemctl enable --now candy-netd.service; sudo systemctl is-active --quiet candy-netd.service; rm -f '$remote_bundle'"
	remote_bundle=
	event runtime_install succeeded
fi

ssh -p "$node_port" "$ssh_target" 'test -x /usr/local/bin/candy-server; test -x /usr/local/libexec/candy-sdwan-runtime; test -x /usr/local/libexec/candy-cloud-enroll; test -x /usr/local/libexec/candy-sdwan-agent; test -x /usr/local/libexec/candy-netd; sudo systemctl is-active --quiet candy-netd; sudo systemctl is-active --quiet candy-server' ||
	fail "node lacks a complete Runtime or ordinary Candy service is not active"

remote_bootstrap=/tmp/candy-node-bootstrap.$$.json
scp -q -P "$node_port" "$bootstrap_file" "$ssh_target:$remote_bootstrap" || fail "Bootstrap upload failed"
ssh -p "$node_port" "$ssh_target" "set -eu; chmod 0600 '$remote_bootstrap'; test \"\$(stat -c '%a' '$remote_bootstrap')\" = 600; sudo /usr/local/bin/candy-server bootstrap '$remote_bootstrap'" ||
	fail "Cloud bootstrap exchange failed; the local Bootstrap file remains available for an idempotent retry"
remote_bootstrap=
event enrollment succeeded "cloud=$cloud_url"

status=$(ssh -p "$node_port" "$ssh_target" 'sudo /usr/local/bin/candy-server sdwan status') || fail "node status query failed"
printf '%s' "$status" | jq -e '.schema_version == 1 and .registration.state == "registered" and .runtime.state == "stopped"' >/dev/null ||
	fail "node did not reach registered/stopped state"
ssh -p "$node_port" "$ssh_target" 'sudo systemctl is-active --quiet candy-server' || fail "ordinary Candy service stopped during enrollment"
event verification succeeded "ordinary_service=active sdwan=registered/stopped"
printf '%s\n' "$status"
