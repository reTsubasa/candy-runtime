#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
product=$root/scripts/join-linux-server-node.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-node-bootstrap-script-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
fail() { printf '%s\n' "join_linux_server_node_test: $*" >&2; exit 1; }

bin=$tmp/bin
mkdir -p "$bin"
calls=$tmp/calls
bootstrap=$tmp/candy-node-bootstrap.json
cat >"$bootstrap" <<'EOF'
{"schema_version":1,"cloud_address":"https://cloud.example.test","bootstrap_code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":"2030-01-01T00:00:00Z"}
EOF
chmod 0600 "$bootstrap"

cat >"$bin/ssh" <<'EOF'
#!/bin/sh
printf 'ssh' >>"$FAKE_CALLS"; printf ' <%s>' "$@" >>"$FAKE_CALLS"; printf '\n' >>"$FAKE_CALLS"
case "$*" in
	*'candy-cloud-sync'*|*'candy-cloud-sync.service'*|*'candy-cloud-sync.timer'*)
		if ! printf '%s' "$*" | grep -Fq 'sdwan status'; then
			:
		elif [ "${FAKE_ALREADY_REGISTERED:-0}" = 1 ]; then
			printf '%s\n' __candy_runtime_ready__
			printf '%s\n' '{"schema_version":1,"registration":{"state":"registered","cloud_address":"https://cloud.example.test"},"runtime":{"state":"stopped"}}'
		elif [ "${FAKE_LEGACY_REGISTERED:-0}" = 1 ]; then
			printf '%s\n' '{"schema_version":1,"registration":{"state":"registered","cloud_address":"https://cloud.example.test"},"runtime":{"state":"stopped"}}'
		elif printf '%s' "$*" | grep -Fq 'sdwan status'; then
			printf '%s\n' '{"schema_version":1,"registration":{"state":"unregistered"},"runtime":{"state":"unavailable"}}'
		fi
		;;
	*'uname -m'*)
		printf '%s\n' "${FAKE_REMOTE_ARCH:-aarch64}"
		;;
	*'sdwan status'*)
		status_calls=$(grep -c 'sdwan status' "$FAKE_CALLS")
		if [ "${FAKE_ALREADY_REGISTERED:-0}" = 1 ] || [ "${FAKE_LEGACY_REGISTERED:-0}" = 1 ] || [ "$status_calls" -gt 1 ]; then
			printf '%s\n' '{"schema_version":1,"registration":{"state":"registered","cloud_address":"https://cloud.example.test"},"runtime":{"state":"stopped"}}'
		else
			printf '%s\n' '{"schema_version":1,"registration":{"state":"unregistered"},"runtime":{"state":"unavailable"}}'
		fi
		;;
esac
EOF
cat >"$bin/scp" <<'EOF'
#!/bin/sh
printf 'scp' >>"$FAKE_CALLS"; printf ' <%s>' "$@" >>"$FAKE_CALLS"; printf '\n' >>"$FAKE_CALLS"
EOF
cat >"$bin/jq" <<'EOF'
#!/bin/sh
exec /usr/bin/jq "$@"
EOF
chmod 0755 "$bin"/* "$product"

log=$tmp/join.log
FAKE_CALLS="$calls" PATH="$bin:$PATH" \
	"$product" --bootstrap-file "$bootstrap" --node 192.0.2.10 --user operator \
		--public-endpoint 203.0.113.10:18443 --log "$log" >"$tmp/status.json"
jq -e '.registration.state == "registered" and .runtime.state == "stopped"' "$tmp/status.json" >/dev/null ||
	fail "script did not return verified node status"
grep -F 'stage=verification result=succeeded' "$log" >/dev/null || fail "verification was not recorded"
if grep -F 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$log" >/dev/null; then
	fail "Bootstrap credential leaked into execution record"
fi
grep -F '<operator@192.0.2.10:/tmp/candy-node-bootstrap.' "$calls" >/dev/null || fail "Bootstrap file was not securely transported"
grep -F 'candy-server bootstrap' "$calls" >/dev/null || fail "remote Bootstrap workflow was not invoked"
grep -F '<operator@192.0.2.10>' "$calls" >/dev/null || fail "requested SSH target was not used"
grep -F 'CANDY_PUBLIC_ENDPOINT=203.0.113.10:18443' "$calls" >/dev/null || fail "explicit endpoint was not persisted remotely"

before_calls=$(wc -l <"$calls")
FAKE_ALREADY_REGISTERED=1 FAKE_CALLS="$calls" PATH="$bin:$PATH" \
	"$product" --bootstrap-file "$bootstrap" --node 192.0.2.10 --user operator \
	--public-endpoint 203.0.113.10:18443 --log "$log" >"$tmp/already.json"
jq -e '.registration.state == "registered" and .runtime.state == "stopped"' "$tmp/already.json" >/dev/null ||
	fail "already registered node was not returned idempotently"
after_calls=$(wc -l <"$calls")
[ "$after_calls" -gt "$before_calls" ] || fail "idempotent verification performed no remote checks"
tail -n 6 "$calls" >"$tmp/idempotent.calls"
if grep -E '^scp|candy-server bootstrap' "$tmp/idempotent.calls" >/dev/null; then
	fail "idempotent bootstrap transported or exchanged the Bootstrap file"
fi
grep -F 'already_registered=true' "$log" >/dev/null || fail "idempotent verification was not recorded"

legacy_bundle=$tmp/legacy-runtime.tar.gz
printf '%s\n' legacy-runtime >"$legacy_bundle"
legacy_sha=$(shasum -a 256 "$legacy_bundle" | awk '{print $1}')
legacy_before=$(wc -l <"$calls")
FAKE_LEGACY_REGISTERED=1 FAKE_CALLS="$calls" PATH="$bin:$PATH" \
	"$product" --bootstrap-file "$bootstrap" --node 192.0.2.10 --user operator \
	--runtime-bundle "$legacy_bundle" --runtime-sha256 "$legacy_sha" \
	--public-endpoint 203.0.113.10:18443 --log "$log" >"$tmp/legacy.json"
jq -e '.registration.state == "registered" and .runtime.state == "stopped"' "$tmp/legacy.json" >/dev/null ||
	fail "legacy registered node was not resumed after Runtime installation"
legacy_after=$(wc -l <"$calls")
tail -n "$((legacy_after - legacy_before))" "$calls" >"$tmp/legacy.calls"
grep -F "$legacy_bundle" "$tmp/legacy.calls" >/dev/null || fail "legacy Runtime bundle was not transported"
if grep -E ':/tmp/candy-node-bootstrap\.|candy-server bootstrap' "$tmp/legacy.calls" >/dev/null; then
	fail "legacy registered node attempted to replace its Cloud identity"
fi
grep -F 'runtime_upgraded=true' "$log" >/dev/null || fail "legacy Runtime recovery was not recorded"

insecure=$tmp/insecure.json
sed 's#https://cloud.example.test#http://cloud.example.test#' "$bootstrap" >"$insecure"
chmod 0600 "$insecure"
if FAKE_CALLS="$calls" PATH="$bin:$PATH" "$product" --bootstrap-file "$insecure" --node 192.0.2.10 \
	--public-endpoint 203.0.113.10:18443 >/dev/null 2>&1; then
	fail "non-HTTPS Bootstrap Cloud was accepted"
fi

if FAKE_CALLS="$calls" PATH="$bin:$PATH" "$product" --bootstrap-file "$bootstrap" --node 192.0.2.10 \
	--public-endpoint 0.0.0.0:18443 >/dev/null 2>&1; then
	fail "wildcard public endpoint was accepted"
fi

if FAKE_CALLS="$calls" PATH="$bin:$PATH" "$product" --bootstrap-file "$bootstrap" --node 192.0.2.10 \
	--public-endpoint 203.0.113.10:0 >/dev/null 2>&1; then
	fail "zero public endpoint port was accepted"
fi

printf '%s\n' "Candy Linux server node Bootstrap script passed"
