#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
core_binary=${CANDY_CORE_BINARY:-}
required=${CANDY_CORE_DOCKER_E2E_REQUIRED:-0}
docker_image=${CANDY_CORE_DOCKER_IMAGE:-alpine:3.22}

fail() {
	printf '%s\n' "candy_core_docker_e2e: $*" >&2
	exit 1
}

skip() {
	if [ "$required" = 1 ]; then
		fail "$*"
	fi
	printf '%s\n' "Candy real Core Docker E2E skipped: $*"
	exit 0
}

[ "$required" = 0 ] || [ "$required" = 1 ] ||
	fail "CANDY_CORE_DOCKER_E2E_REQUIRED must be 0 or 1"
[ -n "$core_binary" ] || skip "CANDY_CORE_BINARY is not set"
case "$core_binary" in
	/*) ;;
	*) fail "CANDY_CORE_BINARY must be an absolute path" ;;
esac
[ -f "$core_binary" ] && [ -x "$core_binary" ] ||
	skip "Core executable is unavailable: $core_binary"
command -v docker >/dev/null 2>&1 || skip "Docker is unavailable"
docker info >/dev/null 2>&1 || skip "Docker daemon is unavailable"
command -v file >/dev/null 2>&1 || skip "file(1) is unavailable for Core platform validation"
command -v openssl >/dev/null 2>&1 || skip "OpenSSL is unavailable"

core_file=$(file "$core_binary")
case "$core_file" in
	*ELF*64-bit*x86-64*static-pie*|*ELF*64-bit*x86-64*statically\ linked*|*ELF*64-bit*x86-64*musl*) ;;
	*) skip "Core must be a Linux x86_64 musl/static ELF for the linux/amd64 E2E: $core_file" ;;
esac

tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-core-docker-e2e.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

cp "$core_binary" "$tmp/candy-core"
cp "$root/linux/server/apps/candy-server/serverd-linux" "$tmp/serverd-linux"
cp "$root/linux/client/apps/candy-client/candy-client" "$tmp/candy-client"
chmod 0755 "$tmp/candy-core" "$tmp/serverd-linux" "$tmp/candy-client"

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
	-keyout "$tmp/server.key" -out "$tmp/server.crt" \
	-subj /CN=localhost -addext subjectAltName=DNS:localhost >/dev/null 2>&1
cert_sha256=$(openssl x509 -in "$tmp/server.crt" -outform DER |
	openssl dgst -sha256 -r | awk '{ print $1 }')

cat >"$tmp/server.toml" <<'EOF'
listen = "127.0.0.1:8443"
cert_pem = "/work/server.crt"
key_pem = "/work/server.key"

[port_hopping]
ports = []

[[users]]
key_id = "docker-e2e"
secret = "docker-e2e-secret-at-least-16-bytes"
features = ["recommended"]
EOF

cat >"$tmp/client.toml" <<EOF
server = "127.0.0.1:8443"
server_name = "localhost"
server_identity = "sha256:$cert_sha256"
key_id = "docker-e2e"
secret = "docker-e2e-secret-at-least-16-bytes"

[transport]
profile = "linux"

[[forwards]]
network = "tcp"
local = "127.0.0.1:18080"
target = "127.0.0.1:8080"
EOF

cat >"$tmp/run-e2e.sh" <<'EOF'
#!/bin/sh
set -eu

server_pid=
client_pid=
echo_pid=

cleanup() {
	[ -z "$client_pid" ] || kill "$client_pid" >/dev/null 2>&1 || true
	[ -z "$server_pid" ] || kill "$server_pid" >/dev/null 2>&1 || true
	[ -z "$echo_pid" ] || kill "$echo_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

fail() {
	printf '%s\n' "container E2E: $*" >&2
	printf '%s\n' "--- server log ---" >&2
	tail -n 80 /work/server.log >&2 2>/dev/null || true
	printf '%s\n' "--- client log ---" >&2
	tail -n 80 /work/client.log >&2 2>/dev/null || true
	exit 1
}

[ "$(/work/candy-core runtime-api-version)" = 1 ] ||
	fail "real Core does not expose Process API v1"

CANDY_CORE_BINARY=/work/candy-core /work/serverd-linux \
	--config /work/server.toml --check-config >/work/server-check.log 2>&1 ||
	fail "server launcher config validation failed"
CANDY_CORE_BIN=/work/candy-core /work/candy-client \
	--config /work/client.toml --check-config >/work/client-check.log 2>&1 ||
	fail "client launcher config validation failed"

nc -lk -p 8080 -e /bin/cat >/work/echo.log 2>&1 &
echo_pid=$!
CANDY_CORE_BINARY=/work/candy-core /work/serverd-linux \
	--config /work/server.toml >/work/server.log 2>&1 &
server_pid=$!

attempt=0
while [ "$attempt" -lt 100 ]; do
	kill -0 "$server_pid" >/dev/null 2>&1 || fail "server launcher exited before listening"
	grep -Eiq '[[:xdigit:]]{8}:20FB[[:space:]]' /proc/net/udp /proc/net/udp6 2>/dev/null && break
	attempt=$((attempt + 1))
	sleep 0.1
done
[ "$attempt" -lt 100 ] || fail "server did not bind UDP 8443"

CANDY_CORE_BIN=/work/candy-core /work/candy-client \
	--config /work/client.toml >/work/client.log 2>&1 &
client_pid=$!

attempt=0
while [ "$attempt" -lt 150 ]; do
	kill -0 "$client_pid" >/dev/null 2>&1 || fail "client launcher exited before forwarding"
	grep -Eiq '[[:xdigit:]]{8}:46A0[[:space:]]' /proc/net/tcp /proc/net/tcp6 2>/dev/null && break
	attempt=$((attempt + 1))
	sleep 0.1
done
[ "$attempt" -lt 150 ] || fail "client did not bind TCP forward 18080"

payload="candy-runtime-real-core-e2e"
response=$(printf '%s' "$payload" | nc -w 8 127.0.0.1 18080) ||
	fail "TCP request through Candy failed"
[ "$response" = "$payload" ] || fail "TCP payload changed across Candy tunnel"

printf '%s\n' "Candy real Core server/client TCP forwarding E2E passed"
EOF
chmod 0755 "$tmp/run-e2e.sh"

docker run --rm --platform linux/amd64 \
	-v "$tmp:/work" \
	"$docker_image" /work/run-e2e.sh
