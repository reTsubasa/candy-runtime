#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
product=$root/scripts/join-linux-server-node.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-node-join-script-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
fail() { printf '%s\n' "join_linux_server_node_test: $*" >&2; exit 1; }

bin=$tmp/bin
mkdir -p "$bin"
calls=$tmp/calls
cat >"$bin/ssh" <<'EOF'
#!/bin/sh
printf 'ssh' >>"$FAKE_CALLS"; printf ' <%s>' "$@" >>"$FAKE_CALLS"; printf '\n' >>"$FAKE_CALLS"
case "$*" in
	*'sdwan status'*) printf '%s\n' '{"schema_version":1,"registration":{"state":"registered"},"runtime":{"state":"stopped"}}' ;;
esac
EOF
cat >"$bin/curl" <<'EOF'
#!/bin/sh
printf 'curl' >>"$FAKE_CALLS"; printf ' <%s>' "$@" >>"$FAKE_CALLS"; printf '\n' >>"$FAKE_CALLS"
case "$*" in
	*/identity/v1/auth/login*) printf '%s\n' '{"access_token":"secret-access-token","membership":{"tenant_id":"tenant-1"}}' ;;
	*/enrollment/activations*) printf '%s\n' '{"id":"join-record-1","credential":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}' ;;
	*) exit 1 ;;
esac
EOF
cat >"$bin/expect" <<'EOF'
#!/bin/sh
input=$(cat)
printf 'expect\n' >>"$FAKE_CALLS"
printf '%s' "$input" | grep -F 'Node join code: ' >/dev/null
test "$CANDY_JOIN_CODE" = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
EOF
cat >"$bin/jq" <<'EOF'
#!/bin/sh
exec /usr/bin/jq "$@"
EOF
chmod 0755 "$bin"/* "$product"

log=$tmp/join.log
FAKE_CALLS="$calls" PATH="$bin:$PATH" CANDY_CLOUD_EMAIL=owner@example.test CANDY_CLOUD_PASSWORD=secret-password \
	"$product" --cloud https://cloud.example.test --node 192.0.2.10 --user operator --log "$log" >"$tmp/status.json"
jq -e '.registration.state == "registered" and .runtime.state == "stopped"' "$tmp/status.json" >/dev/null ||
	fail "script did not return verified node status"
grep -F 'stage=verification result=succeeded' "$log" >/dev/null || fail "verification was not recorded"
if grep -E 'secret-password|secret-access-token|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$log" >/dev/null; then
	fail "credential leaked into execution record"
fi
grep -F 'https://cloud.example.test/identity/v1/auth/login' "$calls" >/dev/null || fail "Cloud login endpoint was not used"
grep -F 'https://cloud.example.test/api/v1/tenants/tenant-1/enrollment/activations' "$calls" >/dev/null ||
	fail "scoped node join code endpoint was not used"
grep -F '<operator@192.0.2.10>' "$calls" >/dev/null || fail "requested SSH target was not used"

if FAKE_CALLS="$calls" PATH="$bin:$PATH" CANDY_CLOUD_EMAIL=owner@example.test CANDY_CLOUD_PASSWORD=secret-password \
	"$product" --cloud http://cloud.example.test --node 192.0.2.10 >/dev/null 2>&1; then
	fail "non-HTTPS Cloud was accepted"
fi

printf '%s\n' "Candy Linux server node join script passed"
