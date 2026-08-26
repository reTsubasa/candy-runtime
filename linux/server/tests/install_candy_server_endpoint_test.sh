#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
installer=$root/linux/server/packaging/install-candy-server.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-server-endpoint-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
fail() { printf '%s\n' "install_candy_server_endpoint_test: $*" >&2; exit 1; }

mkdir -p "$tmp/bin"
cat >"$tmp/bin/id" <<'EOF'
#!/bin/sh
case "${1:-}" in -u) printf '%s\n' 0 ;; *) exit 1 ;; esac
EOF
cat >"$tmp/bin/systemctl" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$tmp/bin/openssl" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "$tmp/bin"/*

PATH="$tmp/bin:$PATH" sh "$installer" --dry-run --public-endpoint 203.0.113.10:18443 >"$tmp/ipv4.out"
grep -F 'public-endpoint: 203.0.113.10:18443' "$tmp/ipv4.out" >/dev/null ||
	fail "valid IPv4 endpoint was not retained"
PATH="$tmp/bin:$PATH" sh "$installer" --dry-run --public-endpoint '[2001:db8::10]:18443' >"$tmp/ipv6.out"
grep -F 'public-endpoint: [2001:db8::10]:18443' "$tmp/ipv6.out" >/dev/null ||
	fail "valid IPv6 endpoint was not retained"

for endpoint in server.example.test:18443 0.0.0.0:18443 203.0.113.999:18443 203.0.113.10:0 2001:db8::10:18443; do
	if PATH="$tmp/bin:$PATH" sh "$installer" --dry-run --public-endpoint "$endpoint" >"$tmp/invalid.out" 2>&1; then
		fail "invalid public endpoint was accepted: $endpoint"
	fi
done

grep -F '[ -n "$PUBLIC_ENDPOINT" ] || return 0' "$installer" >/dev/null ||
	fail "an upgrade without an endpoint would not preserve the existing value"
grep -F 'run cp "$cloud_sync_env_backup" "$CLOUD_SYNC_ENV"' "$installer" >/dev/null ||
	fail "installer rollback does not restore the previous endpoint"
grep -F 'run chmod 0640 "$CLOUD_SYNC_ENV"' "$installer" >/dev/null ||
	fail "restored endpoint permissions are not protected"
grep -F 'LimitMEMLOCK=64M' "$installer" >/dev/null ||
	fail "generated server unit has no transaction agent memlock limit"
grep -F 'SYSCTL_POLICY=/usr/lib/sysctl.d/60-candy-server.conf' "$installer" >/dev/null ||
	fail "installer has no persistent QUIC sysctl policy"
grep -F 'UDP_BUFFER_MAX_BYTES=16777216' "$installer" >/dev/null ||
	fail "installer has the wrong QUIC socket maximum"
grep -F 'target_rmem_max=$previous_rmem_max' "$installer" >/dev/null ||
	fail "installer does not preserve a higher receive buffer maximum"
grep -F 'target_wmem_max=$previous_wmem_max' "$installer" >/dev/null ||
	fail "installer does not preserve a higher send buffer maximum"
grep -F 'net.core.rmem_max = $target_rmem_max' "$installer" >/dev/null ||
	fail "installer does not persist the effective receive buffer maximum"
grep -F 'net.core.wmem_max = $target_wmem_max' "$installer" >/dev/null ||
	fail "installer does not persist the effective send buffer maximum"
if grep -F 'AmbientCapabilities=' "$installer" >/dev/null; then
	fail "installer grants ambient capabilities for kernel tuning"
fi

printf '%s\n' "Candy Linux server public endpoint installer test passed"
