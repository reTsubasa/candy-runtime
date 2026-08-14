#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
launcher=$root/linux/server/apps/candy-server/candy-server
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-server-product-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() { printf '%s\n' "candy_server_product_command_test: $*" >&2; exit 1; }

fake_core=$tmp/data-plane
fake_runtime=$tmp/sdwan-runtime
args=$tmp/args
calls=$tmp/calls
fake_bin=$tmp/bin
mkdir -p "$fake_bin"
cat >"$fake_bin/id" <<'EOF'
#!/bin/sh
if [ "${1:-}" = -u ]; then printf '%s\n' 0; else exec /usr/bin/id "$@"; fi
EOF
chmod 0755 "$fake_bin/id"
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
cat >"$fake_runtime" <<'EOF'
#!/bin/sh
printf '<%s>' "$@" >>"${FAKE_SDWAN_CALLS:?}"
printf '\n' >>"$FAKE_SDWAN_CALLS"
case "${1:-}" in
	status) printf '%s\n' '{"schema_version":1,"registration":{"state":"unregistered"}}' ;;
	bootstrap) [ "$#" -eq 2 ] && [ -f "$2" ] ;;
	*) : ;;
esac
EOF
chmod 0755 "$fake_runtime"

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

FAKE_SDWAN_CALLS="$calls" CANDY_SDWAN_RUNTIME="$fake_runtime" "$launcher" sdwan status >"$tmp/status.out"
grep -F '<status>' "$calls" >/dev/null || fail "SD-WAN status did not use the Runtime boundary"
if FAKE_SDWAN_CALLS="$calls" CANDY_SDWAN_RUNTIME="$fake_runtime" "$launcher" join --cloud https://cloud.example.test >"$tmp/join.out" 2>&1; then
	fail "removed server join command unexpectedly succeeded"
fi
grep -F 'candy-server bootstrap FILE' "$tmp/join.out" >/dev/null || fail "removed join failure did not show the Bootstrap workflow"
bootstrap=$tmp/candy-node-bootstrap.json
printf '%s\n' '{"schema_version":1,"cloud_address":"https://cloud.example.test","bootstrap_code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":"2030-01-01T00:00:00Z"}' >"$bootstrap"
chmod 0644 "$bootstrap"
FAKE_SDWAN_CALLS="$calls" CANDY_SDWAN_RUNTIME="$fake_runtime" PATH="$fake_bin:$PATH" "$launcher" bootstrap "$bootstrap" >"$tmp/bootstrap.out"
grep -F "<bootstrap><$bootstrap>" "$calls" >/dev/null || fail "server bootstrap did not use the Runtime boundary"
[ "$(stat -c '%a' "$bootstrap" 2>/dev/null || stat -f '%Lp' "$bootstrap")" = 600 ] || fail "server bootstrap did not protect its input"
grep -F 'joined Candy Cloud' "$tmp/bootstrap.out" >/dev/null || fail "server bootstrap success is not actionable"

printf '%s\n' "Candy server product command passed"
