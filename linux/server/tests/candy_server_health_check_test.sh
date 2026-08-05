#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
health=$root/linux/server/apps/candy-server/candy-server-health-check
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-server-health-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
bin=$tmp/bin
config=$tmp/server.toml
mkdir -p "$bin"
printf '%s\n' 'listen = "0.0.0.0:8443"' > "$config"

cat > "$bin/systemctl" <<'EOF'
#!/bin/sh
[ "${FAKE_SERVICE_ACTIVE:-0}" = 1 ]
EOF
cat > "$bin/ss" <<'EOF'
#!/bin/sh
printf '%s\n' 'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port'
[ "${FAKE_LISTENER_READY:-0}" = 1 ] && printf '%s\n' 'udp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:*'
EOF
chmod 0755 "$bin/systemctl" "$bin/ss"

PATH="$bin:$PATH" CANDY_SYSTEMCTL="$bin/systemctl" CANDY_SERVER_CONFIG="$config" \
	CANDY_SERVER_HEALTH_WAIT_SECONDS=0 FAKE_SERVICE_ACTIVE=1 FAKE_LISTENER_READY=1 "$health"

if PATH="$bin:$PATH" CANDY_SYSTEMCTL="$bin/systemctl" CANDY_SERVER_CONFIG="$config" \
	CANDY_SERVER_HEALTH_WAIT_SECONDS=0 FAKE_SERVICE_ACTIVE=1 FAKE_LISTENER_READY=0 \
	"$health" > "$tmp/no-listener.out" 2>&1; then
	printf '%s\n' "health check accepted a server without a UDP listener" >&2
	exit 1
fi
grep -F 'UDP port 8443' "$tmp/no-listener.out" >/dev/null

if PATH="$bin:$PATH" CANDY_SYSTEMCTL="$bin/systemctl" CANDY_SERVER_CONFIG="$config" \
	CANDY_SERVER_HEALTH_WAIT_SECONDS=0 FAKE_SERVICE_ACTIVE=0 FAKE_LISTENER_READY=1 \
	"$health" >/dev/null 2>&1; then
	printf '%s\n' "health check accepted an inactive service" >&2
	exit 1
fi

printf '%s\n' 'listen = "0.0.0.0:not-a-port"' > "$config"
if PATH="$bin:$PATH" CANDY_SYSTEMCTL="$bin/systemctl" CANDY_SERVER_CONFIG="$config" \
	CANDY_SERVER_HEALTH_WAIT_SECONDS=0 "$health" >/dev/null 2>&1; then
	printf '%s\n' "health check accepted an invalid listen address" >&2
	exit 1
fi

printf '%s\n' "Candy Linux server listener health check test passed"
