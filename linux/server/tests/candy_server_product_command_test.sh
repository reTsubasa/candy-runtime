#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
launcher=$root/linux/server/apps/candy-server/candy-server
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-server-product-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() { printf '%s\n' "candy_server_product_command_test: $*" >&2; exit 1; }

fake_core=$tmp/data-plane
args=$tmp/args
calls=$tmp/calls
cat >"$fake_core" <<'EOF'
#!/bin/sh
printf '<%s>' "$@" >>"${FAKE_CALLS:?}"
printf '\n' >>"$FAKE_CALLS"
case "${1:-}" in
	runtime-api-version) printf '%s\n' "${FAKE_CORE_API:-1}" ;;
	server) shift; : >"$FAKE_ARGS"; printf '<%s>\n' "$@" >>"$FAKE_ARGS"; exit "${FAKE_SERVER_EXIT:-0}" ;;
	*) exit 64 ;;
esac
EOF
chmod 0755 "$fake_core"

FAKE_CALLS="$calls" FAKE_ARGS="$args" CANDY_CORE_BINARY="$fake_core" "$launcher" --check-config --config /tmp/server.toml
grep -Fx '<--check-config>' "$args" >/dev/null || fail "--check-config was not preserved"
grep -Fx '<--config>' "$args" >/dev/null || fail "--config was not preserved"
grep -Fx '</tmp/server.toml>' "$args" >/dev/null || fail "config path was not preserved"

FAKE_CALLS="$calls" FAKE_ARGS="$args" CANDY_CORE_BINARY="$fake_core" "$launcher" --preflight --config /tmp/server.toml
grep -Fx '<--preflight>' "$args" >/dev/null || fail "--preflight was not preserved"

if FAKE_CALLS="$calls" FAKE_ARGS="$args" CANDY_CORE_BINARY="$fake_core" FAKE_CORE_API=2 "$launcher" >"$tmp/api.out" 2>&1; then
	fail "incompatible data plane unexpectedly launched"
fi

: >"$calls"
FAKE_CALLS="$calls" FAKE_ARGS="$args" CANDY_CORE_BINARY="$fake_core" \
	"$launcher" --config /tmp/server.toml
grep -F '<server><--config></tmp/server.toml>' "$calls" >/dev/null || fail "ordinary server was not started"
[ "$(grep -Fc '<server>' "$calls")" -eq 1 ] || fail "candy-server launched more than one server process"
if grep -F '<server><sdwan>' "$calls" >/dev/null; then
	fail "candy-server split SD-WAN into a second server process"
fi
grep -F 'requires process API 1' "$tmp/api.out" >/dev/null || fail "process API error is not actionable"
if grep -F 'candy-core' "$tmp/api.out" >/dev/null; then
	fail "public candy-server output exposed the internal executable"
fi

printf '%s\n' "Candy server product command passed"
