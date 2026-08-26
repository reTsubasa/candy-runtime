#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-core-manager-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
bin="$tmp/bin"
cores="$tmp/cores"
core_tmp="$tmp/core-tmp"
mkdir -p "$bin" "$cores" "$core_tmp"
case "$(uname -m)" in
	x86_64|amd64) test_arch=x86_64 ;;
	aarch64|arm64) test_arch=aarch64 ;;
	arm*) test_arch=arm ;;
	*) printf '%s\n' "unsupported test architecture: $(uname -m)" >&2; exit 1 ;;
esac
export TEST_CORE_ARCH="$test_arch"

cat > "$bin/jsonfilter" <<'EOF'
#!/bin/sh
file=
expression=
while [ "$#" -gt 0 ]; do
	case "$1" in
		-i) file=$2; shift 2 ;;
		-e) expression=$2; shift 2 ;;
		*) shift ;;
	esac
done
case "$expression" in
	'@.schema_version') key=schema_version ;;
	'@.process_api_version') key=process_api_version ;;
	'@.core_api_version') key=core_api_version ;;
	'@.core_version') key=core_version ;;
	'@.target_os') key=target_os ;;
	'@.target_arch') key=target_arch ;;
	'@.core.schema_version') key=schema_version ;;
	'@.core.core_api_version') key=core_api_version ;;
	'@.core.core_version') key=core_version ;;
	'@.core.target_os') sed -n 's/.*"core":{[^}]*"target_os":"\([^"]*\)".*/\1/p' "$file"; exit ;;
	'@.core.target_arch') sed -n 's/.*"core":{[^}]*"target_arch":"\([^"]*\)".*/\1/p' "$file"; exit ;;
	'@.artifact.target_os') key=target_os ;;
	'@.artifact.target_arch') key=target_arch ;;
	'@.artifact.libc') key=libc ;;
	'@.artifact.executable') key=executable ;;
	'@.artifact.executable_sha256') key=executable_sha256 ;;
	'@.state') key=state ;;
	*) exit 1 ;;
esac
sed -n "s/.*\"$key\":[ ]*\"\{0,1\}\([^\",}]*\).*/\1/p" "$file"
EOF
chmod +x "$bin/jsonfilter"

cat > "$bin/uclient-fetch" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_FETCH_LOG"
[ -n "${FAKE_FETCH_SOURCE:-}" ] || {
	while [ "$#" -gt 0 ]; do
		if [ "$1" = -O ]; then
			printf '%s\n' partial-download > "$2"
			break
		fi
		shift
	done
	exit 99
}
while [ "$#" -gt 0 ]; do
	case "$1" in
		-O) /bin/cp "$FAKE_FETCH_SOURCE" "$2"; exit $? ;;
		*) shift ;;
	esac
done
exit 99
EOF
chmod +x "$bin/uclient-fetch"

export REAL_TAR=$(command -v tar)
cat > "$bin/tar" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_TAR_LOG"
exec "$REAL_TAR" "$@"
EOF
chmod +x "$bin/tar"

cat > "$bin/timeout" <<'EOF'
#!/bin/sh
shift
exec "$@"
EOF
chmod +x "$bin/timeout"

cat > "$bin/core-signature-verifier" <<'EOF'
#!/bin/sh
[ "$(cat "$2")" = trusted-test-signature ]
EOF
chmod +x "$bin/core-signature-verifier"

cat > "$bin/usign" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$bin/usign"

cat > "$bin/runtime-health-check" <<'EOF'
#!/bin/sh
[ "$1" = client ]
EOF
chmod +x "$bin/runtime-health-check"

cat > "$bin/candy-service" <<'EOF'
#!/bin/sh
case "$1" in
	status) [ ! -f "$FAKE_SERVICE_STOPPED" ] && printf '%s\n' running ;;
	restart)
		printf '%s\n' restart >> "$FAKE_SERVICE_LOG"
		if [ -f "$FAKE_SERVICE_FAIL_ONCE" ]; then
			rm -f "$FAKE_SERVICE_FAIL_ONCE"
			exit 1
		fi
		rm -f "$FAKE_SERVICE_STOPPED"
		;;
	stop)
		printf '%s\n' stop >> "$FAKE_SERVICE_LOG"
		: >"$FAKE_SERVICE_STOPPED"
		;;
	*) exit 1 ;;
esac
EOF
chmod +x "$bin/candy-service"

make_bundle() {
	local version="$1" api="$2" bundle="$3" flavor="${4:-base}" stage executable_sha
	stage="$tmp/stage-$version-$flavor"
	rm -rf "$stage"
	mkdir -p "$stage"
	cat > "$stage/candy-core" <<EOF
#!/bin/sh
# $flavor
case "\${1:-}" in
	runtime-api-version) printf '%s\n' 1 ;;
	core-info) printf '%s\n' '{"schema_version":1,"process_api_version":1,"core_api_version":$api,"core_version":"$version","target_os":"linux","target_arch":"$TEST_CORE_ARCH","protocol_version":{"major":0,"minor":3},"features":[]}' ;;
	*) exit 64 ;;
esac
EOF
	chmod 0755 "$stage/candy-core"
	executable_sha=$(sha256sum "$stage/candy-core" | awk '{ print $1 }')
	cat > "$stage/manifest.json" <<EOF
{"schema_version":1,"process_api_version":1,"core":{"schema_version":1,"core_api_version":$api,"core_version":"$version","target_os":"linux","target_arch":"$TEST_CORE_ARCH","protocol_version":{"major":0,"minor":3},"features":[]},"artifact":{"target_os":"linux","target_arch":"$TEST_CORE_ARCH","libc":"musl","executable":"candy-core","executable_sha256":"$executable_sha"}}
EOF
	printf '%s\n' trusted-test-signature > "$stage/manifest.sig"
	# A protected signer can create a correct bundle under umask 077. Runtime
	# must normalize archive modes instead of inheriting them.
	chmod 0700 "$stage/candy-core"
	chmod 0600 "$stage/manifest.json" "$stage/manifest.sig"
	tar -czf "$bundle" -C "$stage" manifest.json manifest.sig candy-core
}

manager="$root/openwrt/client/packages/candy-client/candy-core-manager"
export PATH="$bin:$PATH"
export CANDY_CORE_ROOT="$cores"
export CANDY_CORE_TMP_ROOT="$core_tmp"
export CANDY_CORE_CURRENT_LINK="$cores/current"
export CANDY_CORE_PREVIOUS_LINK="$cores/previous"
export CANDY_SERVICE_INIT="$bin/candy-service"
export CANDY_CORE_SIGNATURE_VERIFIER="$bin/core-signature-verifier"
export CANDY_RUNTIME_HEALTH_CHECK="$bin/runtime-health-check"
export CANDY_CORE_LOCK_DIR="$tmp/core-manager.lock"
export CANDY_SERVICE_LOCK_DIR="$tmp/service.lock"
export CANDY_PROC_ROOT="$tmp/proc"
export CANDY_CORE_OPERATION_FILE="$tmp/core-operation.json"
export CANDY_CORE_ALLOW_FILE_URL=1
export CANDY_CORE_HEALTH_WAIT_SECONDS=1
export FAKE_SERVICE_LOG="$tmp/service.log"
export FAKE_SERVICE_FAIL_ONCE="$tmp/service-fail-once"
export FAKE_SERVICE_STOPPED="$tmp/service-stopped"
export FAKE_FETCH_LOG="$tmp/fetch.log"
export FAKE_TAR_LOG="$tmp/tar.log"
mkdir -p "$CANDY_PROC_ROOT"

mkdir "$CANDY_CORE_LOCK_DIR"
printf '%s\n' "$$" > "$CANDY_CORE_LOCK_DIR/pid"
printf '%s\n' '{"state":"running","action":"install","version":"0.4.0","message":"busy","updated_at":1}' > "$CANDY_CORE_OPERATION_FILE"
if "$manager" remove 0.4.0 >/dev/null 2>&1; then
	echo "concurrent Core operation bypassed the manager lock" >&2
	exit 1
fi
grep -q '"state":"running"' "$CANDY_CORE_OPERATION_FILE"
rm -f "$CANDY_CORE_LOCK_DIR/pid"
rmdir "$CANDY_CORE_LOCK_DIR"
mkdir "$CANDY_CORE_LOCK_DIR"
printf '%s\n' 99999999 > "$CANDY_CORE_LOCK_DIR/pid"

make_bundle 0.4.1 1 "$tmp/core-0.4.1.tar.gz"
sha_041=$(sha256sum "$tmp/core-0.4.1.tar.gz" | awk '{ print $1 }')
ln -s "$tmp/missing-core-directory" "$cores/0.4.8"
if "$manager" install 0.4.8 "file://$tmp/core-0.4.1.tar.gz" "$sha_041" >/dev/null 2>&1; then
	echo "dangling symbolic-link Core destination was accepted" >&2
	exit 1
fi
grep -F '"error_code":"destination_unsafe"' "$CANDY_CORE_OPERATION_FILE" >/dev/null
rm -f "$cores/0.4.8"
if CANDY_CORE_SIGNATURE_VERIFIER= CANDY_CORE_SIGNING_KEY="$tmp/missing-core-release.pub" \
	"$manager" install 0.4.1 "file://$tmp/core-0.4.1.tar.gz" "$sha_041" >/dev/null 2>&1; then
	echo "Core bundle was accepted without a signing key" >&2
	exit 1
fi
grep -F '"phase":"signature"' "$CANDY_CORE_OPERATION_FILE" >/dev/null
grep -F '"error_code":"signing_key_missing"' "$CANDY_CORE_OPERATION_FILE" >/dev/null

if CANDY_CORE_ALLOW_FILE_URL=0 "$manager" install 0.4.8 "file://$tmp/core-0.4.1.tar.gz" "$sha_041" >/dev/null 2>&1; then
	echo "local Core bundle was accepted without explicit opt-in" >&2
	exit 1
fi
if "$manager" install 0.4.8 'file://relative-core.tar.gz' "$sha_041" >/dev/null 2>&1; then
	echo "relative local Core bundle path was accepted" >&2
	exit 1
fi
ln -s "$tmp/core-0.4.1.tar.gz" "$tmp/core-link.tar.gz"
if "$manager" install 0.4.8 "file://$tmp/core-link.tar.gz" "$sha_041" >/dev/null 2>&1; then
	echo "symbolic-link local Core bundle was accepted" >&2
	exit 1
fi
: > "$tmp/empty-core.tar.gz"
if "$manager" install 0.4.8 "file://$tmp/empty-core.tar.gz" "$sha_041" >/dev/null 2>&1; then
	echo "empty local Core bundle was accepted" >&2
	exit 1
fi
if "$manager" install 0.4.8 "file://$tmp" "$sha_041" >/dev/null 2>&1; then
	echo "directory local Core bundle was accepted" >&2
	exit 1
fi
if "$manager" install 0.4.8 'https://example.invalid/core.tar.gz' "$sha_041" >/dev/null 2>&1; then
	echo "failed HTTPS fetch was accepted" >&2
	exit 1
fi
grep -F 'https://example.invalid/core.tar.gz' "$FAKE_FETCH_LOG" >/dev/null
[ -z "$(find "$core_tmp" -mindepth 1 -print -quit)" ] || {
	echo "failed HTTPS download left temporary bundle data behind" >&2
	exit 1
}
rm -f "$FAKE_FETCH_LOG"
"$manager" install 0.4.1 "file://$tmp/core-0.4.1.tar.gz" "$sha_041" >/dev/null
[ ! -e "$FAKE_FETCH_LOG" ] || {
	echo "local Core bundle unexpectedly used the network downloader" >&2
	exit 1
}
grep -F -- "-C $cores/.install-0.4.1-" "$FAKE_TAR_LOG" >/dev/null || {
	echo "Core candidate was not extracted below CORE_ROOT" >&2
	exit 1
}
grep -F -- "-oxzf $core_tmp/candy-core-manager." "$FAKE_TAR_LOG" >/dev/null || {
	echo "file URL bundle was not staged below CANDY_CORE_TMP_ROOT" >&2
	exit 1
}
[ -z "$(find "$core_tmp" -mindepth 1 -print -quit)" ] || {
	echo "successful file URL install left temporary bundle data behind" >&2
	exit 1
}

make_bundle 0.4.6 1 "$tmp/core-0.4.6.tar.gz"
sha_046=$(sha256sum "$tmp/core-0.4.6.tar.gz" | awk '{ print $1 }')
FAKE_FETCH_SOURCE="$tmp/core-0.4.6.tar.gz" \
	"$manager" install 0.4.6 'https://downloads.example.test/core.tar.gz' "$sha_046" >/dev/null
grep -F "$core_tmp/candy-core-manager." "$FAKE_FETCH_LOG" >/dev/null || {
	echo "HTTPS bundle was not downloaded below CANDY_CORE_TMP_ROOT" >&2
	exit 1
}
[ -z "$(find "$core_tmp" -mindepth 1 -print -quit)" ] || {
	echo "successful HTTPS install left temporary bundle data behind" >&2
	exit 1
}

if "$manager" install 0.4.7 "file://$tmp/core-0.4.6.tar.gz" "$(printf '0%.0s' $(seq 1 64))" >/dev/null 2>&1; then
	echo "bad file URL bundle SHA-256 was accepted" >&2
	exit 1
fi
[ -z "$(find "$core_tmp" -mindepth 1 -print -quit)" ] || {
	echo "failed file URL install left temporary bundle data behind" >&2
	exit 1
}
"$manager" activate 0.4.1 >/dev/null
[ "$(readlink "$cores/current")" = 0.4.1 ]
[ "$(ls -ld "$cores/0.4.1" | cut -c1-10)" = drwxr-xr-x ] || {
	echo "installed Core is not traversable by unprivileged Runtime services" >&2
	exit 1
}
[ "$(ls -l "$cores/0.4.1/candy-core" | cut -c1-10)" = -rwxr-xr-x ] || {
	echo "installed Core executable is not available to unprivileged Runtime services" >&2
	exit 1
}
for metadata in manifest.json manifest.sig; do
	[ "$(ls -l "$cores/0.4.1/$metadata" | cut -c1-10)" = -rw-r--r-- ] || {
		echo "installed Core metadata does not use the normalized permission policy" >&2
		exit 1
	}
done
grep -q '"state":"completed"' "$CANDY_CORE_OPERATION_FILE"
grep -q '"current_version":"0.4.1"' <<EOF
$("$manager" status)
EOF

make_bundle 0.4.1 1 "$tmp/core-0.4.1-corrected.tar.gz" corrected
sha_041_corrected=$(sha256sum "$tmp/core-0.4.1-corrected.tar.gz" | awk '{ print $1 }')
"$manager" install 0.4.1 "file://$tmp/core-0.4.1-corrected.tar.gz" "$sha_041_corrected" >"$tmp/active-replaced.out"
grep -F 'replaced active Core 0.4.1' "$tmp/active-replaced.out" >/dev/null
grep -F '# corrected' "$cores/0.4.1/candy-core" >/dev/null
[ "$(cat "$cores/0.4.1/.bundle.sha256")" = "$sha_041_corrected" ]
[ ! -f "$FAKE_SERVICE_STOPPED" ]
"$manager" install 0.4.1 "file://$tmp/core-0.4.1-corrected.tar.gz" "$sha_041_corrected" >"$tmp/active-idempotent.out"
grep -F 'bundle is already installed' "$tmp/active-idempotent.out" >/dev/null

touch "$FAKE_SERVICE_FAIL_ONCE"
if "$manager" install 0.4.1 "file://$tmp/core-0.4.1.tar.gz" "$sha_041" >"$tmp/active-replacement-failed.out" 2>&1; then
	echo "unhealthy active Core replacement was accepted" >&2
	exit 1
fi
grep -F '# corrected' "$cores/0.4.1/candy-core" >/dev/null
[ "$(cat "$cores/0.4.1/.bundle.sha256")" = "$sha_041_corrected" ]
[ ! -f "$FAKE_SERVICE_STOPPED" ]
grep -F 'previous Core restored' "$tmp/active-replacement-failed.out" >/dev/null

if "$manager" install 0.4.9 "file://$tmp/core-0.4.1.tar.gz" "$(printf '0%.0s' $(seq 1 64))" >/dev/null 2>&1; then
	echo "bad SHA-256 was accepted" >&2
	exit 1
fi

make_bundle 0.4.2 1 "$tmp/core-0.4.2.tar.gz"
sha_042=$(sha256sum "$tmp/core-0.4.2.tar.gz" | awk '{ print $1 }')
"$manager" install 0.4.2 "file://$tmp/core-0.4.2.tar.gz" "$sha_042" >/dev/null
"$manager" activate 0.4.2 >/dev/null
[ "$(readlink "$cores/current")" = 0.4.2 ]
[ "$(readlink "$cores/previous")" = 0.4.1 ]
"$manager" rollback >/dev/null
[ "$(readlink "$cores/current")" = 0.4.1 ]
[ "$(readlink "$cores/previous")" = 0.4.2 ]

make_bundle 0.4.3 1 "$tmp/core-0.4.3.tar.gz"
sha_043=$(sha256sum "$tmp/core-0.4.3.tar.gz" | awk '{ print $1 }')
"$manager" install 0.4.3 "file://$tmp/core-0.4.3.tar.gz" "$sha_043" >/dev/null
"$manager" install 0.4.3 "file://$tmp/core-0.4.3.tar.gz" "$sha_043" > "$tmp/replaced.out"
grep -F 'bundle is already installed' "$tmp/replaced.out" >/dev/null
"$manager" remove 0.4.3 >/dev/null
[ ! -e "$cores/0.4.3" ]

make_bundle 0.4.5 1 "$tmp/core-0.4.5.tar.gz"
"$manager" install-local "$tmp/core-0.4.5.tar.gz" >/dev/null
[ -x "$cores/0.4.5/candy-core" ]
grep -F '"action":"install-local"' "$CANDY_CORE_OPERATION_FILE" >/dev/null
grep -F '"version":"0.4.5"' "$CANDY_CORE_OPERATION_FILE" >/dev/null

make_bundle 0.5.0 2 "$tmp/core-bad-api.tar.gz"
sha_bad_api=$(sha256sum "$tmp/core-bad-api.tar.gz" | awk '{ print $1 }')
if "$manager" install 0.5.0 "file://$tmp/core-bad-api.tar.gz" "$sha_bad_api" >/dev/null 2>&1; then
	echo "incompatible Core API was accepted" >&2
	exit 1
fi

make_bundle 0.4.4 1 "$tmp/core-0.4.4.tar.gz"
sha_044=$(sha256sum "$tmp/core-0.4.4.tar.gz" | awk '{ print $1 }')
"$manager" install 0.4.4 "file://$tmp/core-0.4.4.tar.gz" "$sha_044" >/dev/null
touch "$FAKE_SERVICE_FAIL_ONCE"
if "$manager" activate 0.4.4 >/dev/null 2>&1; then
	echo "failed service restart did not reject Core activation" >&2
	exit 1
fi
[ "$(readlink "$cores/current")" = 0.4.1 ]
[ "$(readlink "$cores/previous")" = 0.4.2 ]

if "$manager" remove 0.4.1 >/dev/null 2>&1; then
	echo "active Core was removed" >&2
	exit 1
fi
grep -q '"state":"error"' "$CANDY_CORE_OPERATION_FILE"
grep -q '"service_running":true' <<EOF
$("$manager" status)
EOF
touch "$FAKE_SERVICE_STOPPED"
mkdir "$CANDY_SERVICE_LOCK_DIR"
printf '%s\n' "$$" > "$CANDY_SERVICE_LOCK_DIR/pid"
if "$manager" remove 0.4.1 >/dev/null 2>&1; then
	echo "current Core removal bypassed the service lifecycle lock" >&2
	exit 1
fi
[ -d "$CANDY_SERVICE_LOCK_DIR" ]
[ -d "$cores/0.4.1" ]
[ "$(readlink "$cores/current")" = 0.4.1 ]
rm -f "$CANDY_SERVICE_LOCK_DIR/pid"
rmdir "$CANDY_SERVICE_LOCK_DIR"

mkdir -p "$CANDY_PROC_ROOT/4242"
ln -s "$cores/0.4.1/candy-core" "$CANDY_PROC_ROOT/4242/exe"
if "$manager" remove 0.4.1 >/dev/null 2>&1; then
	echo "current Core was removed while its executable was in use" >&2
	exit 1
fi
[ ! -e "$CANDY_SERVICE_LOCK_DIR" ]
[ -d "$cores/0.4.1" ]
[ "$(readlink "$cores/current")" = 0.4.1 ]
rm -f "$CANDY_PROC_ROOT/4242/exe"
rmdir "$CANDY_PROC_ROOT/4242"

mkdir "$tmp/failing-remove-bin"
cat > "$tmp/failing-remove-bin/rm" <<'EOF'
#!/bin/sh
[ "$*" != "-rf $FAKE_REMOVE_TARGET" ] || exit 1
exec /bin/rm "$@"
EOF
chmod +x "$tmp/failing-remove-bin/rm"
if PATH="$tmp/failing-remove-bin:$PATH" FAKE_REMOVE_TARGET="$cores/0.4.1" \
	"$manager" remove 0.4.1 >/dev/null 2>&1; then
	echo "failed current Core directory removal was accepted" >&2
	exit 1
fi
[ ! -e "$CANDY_SERVICE_LOCK_DIR" ]
[ -d "$cores/0.4.1" ]
[ "$(readlink "$cores/current")" = 0.4.1 ]
[ "$(readlink "$cores/previous")" = 0.4.2 ]

"$manager" remove 0.4.1 >/dev/null
[ ! -e "$cores/0.4.1" ]
[ ! -e "$cores/current" ]
[ "$(readlink "$cores/previous")" = 0.4.2 ]
grep -q '"service_running":false' <<EOF
$("$manager" status)
EOF
if PATH="$tmp/failing-remove-bin:$PATH" FAKE_REMOVE_TARGET="$cores/0.4.2" \
	"$manager" remove 0.4.2 >/dev/null 2>&1; then
	echo "failed rollback Core directory removal was accepted" >&2
	exit 1
fi
[ -d "$cores/0.4.2" ]
[ "$(readlink "$cores/previous")" = 0.4.2 ]
"$manager" remove 0.4.2 >/dev/null
[ ! -e "$cores/0.4.2" ]
[ ! -e "$cores/previous" ]
final_status=$($manager status)
grep -q '"current_version":null' <<EOF
$final_status
EOF
grep -q '"previous_version":null' <<EOF
$final_status
EOF
installed_section=$(printf '%s\n' "$final_status" | sed -n 's/.*,"installed"://p')
! printf '%s' "$installed_section" | grep -q '"version":"0.4.1"'
! printf '%s' "$installed_section" | grep -q '"version":"0.4.2"'
printf '%s' "$installed_section" | grep -q '"version":"0.4.4"'
printf '%s' "$installed_section" | grep -q '"version":"0.4.5"'

[ "$(wc -l < "$FAKE_SERVICE_LOG")" -ge 3 ]

launcher_core="$tmp/launcher-core"
launcher_log="$tmp/launcher.log"
cat > "$launcher_core" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$CANDY_LAUNCHER_LOG"
[ "${1:-}" != runtime-api-version ] || printf '%s\n' 1
EOF
chmod 0755 "$launcher_core"
export CANDY_CORE_BIN="$launcher_core"
export CANDY_LAUNCHER_LOG="$launcher_log"
sh "$root/openwrt/client/packages/candy-client/candy-client" --config /tmp/client.json --check-config
sh "$root/openwrt/client/packages/candy-client/candy-sdwan" --config /tmp/sdwan.toml
grep -Fx 'client --config /tmp/client.json --check-config' "$launcher_log" >/dev/null
grep -Fx 'client sdwan --config /tmp/sdwan.toml' "$launcher_log" >/dev/null
[ "$(grep -Fxc runtime-api-version "$launcher_log")" -eq 2 ]

mismatched_core="$tmp/mismatched-core"
cat > "$mismatched_core" <<'EOF'
#!/bin/sh
[ "${1:-}" = runtime-api-version ] && printf '%s\n' 2
EOF
chmod 0755 "$mismatched_core"
if CANDY_CORE_BIN="$mismatched_core" sh "$root/openwrt/client/packages/candy-client/candy-client" --check-config >/dev/null 2>&1; then
	echo "client launcher accepted an incompatible Core process API" >&2
	exit 1
fi

if grep -En 'libcandy_core|CANDY_CORE_SRC|git (clone|checkout)' \
	"$manager" \
	"$root/openwrt/client/packages/candy-client/Makefile" \
	"$root/openwrt/client/packages/candy-client/candy-client" \
	"$root/openwrt/client/packages/candy-client/candy-sdwan" >/dev/null 2>&1; then
	echo "OpenWrt Runtime references Core source or the obsolete shared-library artifact" >&2
	exit 1
fi

printf '%s\n' "OpenWrt Candy Core process manager and launcher test passed"
