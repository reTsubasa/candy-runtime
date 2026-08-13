#!/bin/sh
set -eu

cloud_url=
node_host=
node_user=
node_port=22
runtime_bundle=
runtime_sha256=
log_file=

usage() {
	cat <<'EOF'
usage: join-linux-server-node.sh --cloud URL --node HOST [options]

Required environment variables:
  CANDY_CLOUD_EMAIL       Cloud account email
  CANDY_CLOUD_PASSWORD    Cloud account password

The SSH client performs authentication normally. Prefer an authorized SSH key;
this script never accepts or stores an SSH password.

Options:
  --cloud URL             Public HTTPS Candy Cloud base URL.
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
	access_token=
	join_code=
	login_payload=
	login_response=
	join_response=
	[ -z "${curl_config:-}" ] || rm -f "$curl_config"
	[ -z "${remote_bundle:-}" ] || ssh -p "$node_port" "$ssh_target" "rm -f '$remote_bundle'" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

while [ "$#" -gt 0 ]; do
	case "$1" in
		--cloud) shift; [ "$#" -gt 0 ] || fail "--cloud requires a URL"; cloud_url=$1 ;;
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

case "$cloud_url" in https://*) ;; *) fail "--cloud must use public HTTPS" ;; esac
[ -n "$node_host" ] || fail "--node is required"
[ -n "$node_user" ] || node_user=$(id -un)
case "$node_port" in ''|*[!0-9]*) fail "--port must be numeric" ;; esac
[ "$node_port" -ge 1 ] && [ "$node_port" -le 65535 ] || fail "--port is outside 1..65535"
[ -n "${CANDY_CLOUD_EMAIL:-}" ] || fail "CANDY_CLOUD_EMAIL is required"
[ -n "${CANDY_CLOUD_PASSWORD:-}" ] || fail "CANDY_CLOUD_PASSWORD is required"
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v expect >/dev/null 2>&1 || fail "expect is required"
command -v ssh >/dev/null 2>&1 || fail "ssh is required"
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

login_payload=$(jq -cn --arg email "$CANDY_CLOUD_EMAIL" --arg password "$CANDY_CLOUD_PASSWORD" \
	'{email:$email,password:$password,device_label:"node-enrollment-script"}')
login_response=$(printf '%s' "$login_payload" | curl --fail-with-body --silent --show-error --max-time 30 \
	-H 'Accept: application/json' -H 'Content-Type: application/json' \
	--data-binary @- \
	"$cloud_url/identity/v1/auth/login") || fail "Cloud login failed"
login_payload=
access_token=$(printf '%s' "$login_response" | jq -er '.access_token') || fail "Cloud login response lacks an access token"
tenant_id=$(printf '%s' "$login_response" | jq -er '.membership.tenant_id') || fail "Cloud login response lacks a tenant"
login_response=
event cloud_login succeeded "tenant_id=$tenant_id"

curl_config=$(mktemp)
chmod 0600 "$curl_config"
printf '%s\n' \
	'header = "Accept: application/json"' \
	'header = "Content-Type: application/json"' \
	"header = \"Authorization: Bearer $access_token\"" >"$curl_config"
join_response=$(printf '%s' '{"expires_in_seconds":600}' | curl --fail-with-body --silent --show-error --max-time 30 \
	--config "$curl_config" --data-binary @- \
	"$cloud_url/api/v1/tenants/$tenant_id/enrollment/activations") || {
	rm -f "$curl_config"
	fail "node join code creation failed"
}
rm -f "$curl_config"
curl_config=
join_code=$(printf '%s' "$join_response" | jq -er '.credential') || fail "Cloud response lacks a node join code"
join_code_id=$(printf '%s' "$join_response" | jq -er '.id') || fail "Cloud response lacks a join-code record ID"
join_response=
access_token=
event join_code created "id=$join_code_id"

CANDY_JOIN_CODE=$join_code CANDY_JOIN_TARGET=$ssh_target CANDY_JOIN_PORT=$node_port CANDY_JOIN_CLOUD=$cloud_url expect <<'EOF'
log_user 1
set timeout 90
spawn ssh -tt -p $env(CANDY_JOIN_PORT) $env(CANDY_JOIN_TARGET) sudo /usr/local/bin/candy-server join --cloud $env(CANDY_JOIN_CLOUD)
expect {
  "Node join code: " { send -- "$env(CANDY_JOIN_CODE)\r" }
  timeout { exit 124 }
  eof { catch wait result; exit [lindex $result 3] }
}
expect {
  "This server has joined Candy Cloud." { exp_continue }
  eof { catch wait result; exit [lindex $result 3] }
  timeout { exit 124 }
}
EOF
join_code=
event enrollment succeeded "join_code_id=$join_code_id"

status=$(ssh -p "$node_port" "$ssh_target" 'sudo /usr/local/bin/candy-server sdwan status') || fail "node status query failed"
printf '%s' "$status" | jq -e '.schema_version == 1 and .registration.state == "registered" and .runtime.state == "stopped"' >/dev/null ||
	fail "node did not reach registered/stopped state"
ssh -p "$node_port" "$ssh_target" 'sudo systemctl is-active --quiet candy-server' || fail "ordinary Candy service stopped during enrollment"
event verification succeeded "ordinary_service=active sdwan=registered/stopped"
printf '%s\n' "$status"
