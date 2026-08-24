#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
manager=$root/linux/server/apps/candy-server/candy-core-manager
launcher=$root/linux/server/apps/candy-server/serverd-linux
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-linux-core-manager-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() {
	printf '%s\n' "candy_core_manager_test: $*" >&2
	exit 1
}

file_mode() {
	if stat -c '%a' "$1" >/dev/null 2>&1; then
		stat -c '%a' "$1"
	else
		stat -f '%Lp' "$1"
	fi
}

case "$(uname -m)" in
	x86_64|amd64) host_arch=x86_64 ;;
	aarch64|arm64) host_arch=aarch64 ;;
	*) host_arch=$(uname -m) ;;
esac

bin=$tmp/bin
cores=$tmp/cores
config=$tmp/server.toml
service_state=$tmp/service.state
service_log=$tmp/service.log
role_log=$tmp/role.log
mkdir -p "$bin" "$cores"
printf '%s\n' 'listen = "127.0.0.1:8443"' > "$config"
printf '%s\n' active > "$service_state"

cat > "$bin/signature-verifier" <<'EOF'
#!/bin/sh
[ "$(cat "$2")" = trusted-linux-core-signature ]
EOF
chmod 0755 "$bin/signature-verifier"

cat > "$bin/systemctl" <<'EOF'
#!/bin/sh
set -eu
command=$1
shift
printf '%s\n' "$command $*" >> "$FAKE_SERVICE_LOG"
case "$command" in
	is-active) [ "$(cat "$FAKE_SERVICE_STATE")" = active ] ;;
	stop) printf '%s\n' inactive > "$FAKE_SERVICE_STATE" ;;
	start)
		if [ -f "$FAKE_SERVICE_FAIL_START" ]; then
			exit 1
		fi
		printf '%s\n' active > "$FAKE_SERVICE_STATE"
		;;
	*) exit 64 ;;
esac
EOF
chmod 0755 "$bin/systemctl"

cat > "$bin/server-health-check" <<'EOF'
#!/bin/sh
[ "$(cat "$FAKE_SERVICE_STATE")" = active ]
EOF
chmod 0755 "$bin/server-health-check"

make_bundle() {
	version=$1
	core_api=$2
	process_api=$3
	arch=$4
	server_result=$5
	bundle=$6
	libc=${7:-gnu}
	stage=$tmp/stage-$version-$$
	mkdir -p "$stage"
	cat > "$stage/candy-core" <<EOF
#!/bin/sh
set -eu
case "\${1:-}" in
	runtime-api-version) printf '%s\n' $process_api ;;
	core-info) printf '%s\n' '{"schema_version":1,"process_api_version":$process_api,"core_api_version":$core_api,"core_version":"$version","target_os":"linux","target_arch":"$arch","protocol_version":{"major":0,"minor":3},"features":[]}' ;;
	server)
		shift
		printf '%s\n' "\$*" >> "\$FAKE_ROLE_LOG"
		case "\$*" in
			*--preflight*)
				if [ -n "\${FAKE_EXPECT_CURRENT:-}" ] &&
					[ "\$(readlink "\$CANDY_CORE_CURRENT_LINK")" != "\$FAKE_EXPECT_CURRENT" ]; then
					exit 52
				fi
				exit "\${FAKE_PREFLIGHT_RESULT:-$server_result}"
				;;
			*--check-config*) exit "\${FAKE_CHECK_RESULT:-$server_result}" ;;
			*) exit "\${FAKE_SERVER_RUN_EXIT:-0}" ;;
		esac
		;;
	*) exit 64 ;;
esac
EOF
	chmod 0755 "$stage/candy-core"
	executable_sha=$(sha256sum "$stage/candy-core" | awk '{ print $1 }')
	cat > "$stage/manifest.json" <<EOF
{"schema_version":1,"process_api_version":$process_api,"core":{"schema_version":1,"core_api_version":$core_api,"core_version":"$version","target_os":"linux","target_arch":"$arch","protocol_version":{"major":0,"minor":3},"features":[]},"artifact":{"target_os":"linux","target_arch":"$arch","libc":"$libc","executable":"candy-core","executable_sha256":"$executable_sha"}}
EOF
	printf '%s\n' trusted-linux-core-signature > "$stage/manifest.sig"
	tar -czf "$bundle" -C "$stage" manifest.json manifest.sig candy-core
	rm -rf "$stage"
}

export PATH="$bin:$PATH"
export CANDY_CORE_ROOT="$cores"
export CANDY_CORE_CURRENT_LINK="$cores/current"
export CANDY_CORE_PREVIOUS_LINK="$cores/previous"
export CANDY_CORE_SIGNATURE_VERIFIER="$bin/signature-verifier"
export CANDY_CORE_TARGET_ARCH="$host_arch"
export CANDY_CORE_TARGET_LIBC=gnu
export CANDY_SERVER_LAUNCHER="$launcher"
export CANDY_SERVER_CONFIG="$config"
export CANDY_SYSTEMCTL="$bin/systemctl"
export CANDY_SERVER_HEALTH_CHECK="$bin/server-health-check"
export CANDY_CORE_LOCK_DIR="$tmp/core-manager.lock"
export FAKE_SERVICE_STATE="$service_state"
export FAKE_SERVICE_LOG="$service_log"
export FAKE_SERVICE_FAIL_START="$tmp/fail-start"
export FAKE_ROLE_LOG="$role_log"

bundle_1=$tmp/core-1.0.0.tar.gz
make_bundle 1.0.0 1 1 "$host_arch" 0 "$bundle_1"
sha_1=$(sha256sum "$bundle_1" | awk '{ print $1 }')
"$manager" install 1.0.0 "$bundle_1" "$sha_1" >/dev/null
[ "$(file_mode "$cores/1.0.0")" = 755 ] || fail "installed Core directory is not service-readable"
[ "$(file_mode "$cores/1.0.0/candy-core")" = 755 ] || fail "installed Core executable mode is invalid"
"$manager" activate 1.0.0 >/dev/null
[ "$(readlink "$cores/current")" = 1.0.0 ] || fail "first Core was not activated"
grep -F -- '--check-config' "$role_log" >/dev/null || fail "activation skipped server config validation"
grep -F -- '--preflight' "$role_log" >/dev/null || fail "activation skipped server preflight"
[ "$(cat "$service_state")" = active ] || fail "server service was not restarted"

run_log=$tmp/run.log
if CANDY_CORE_ROOT="$cores" FAKE_ROLE_LOG="$run_log" FAKE_SERVER_RUN_EXIT=27 \
	"$launcher" --config "$config"; then
	fail "activated Core server exit was not forwarded"
else
	status=$?
fi
[ "$status" -eq 27 ] || fail "activated Core server exited $status, expected 27"
grep -Fx -- "--config $config" "$run_log" >/dev/null || fail "Runtime launcher did not execute the activated Core server role"

bundle_2=$tmp/core-1.0.1.tar.gz
make_bundle 1.0.1 1 1 "$host_arch" 0 "$bundle_2"
sha_2=$(sha256sum "$bundle_2" | awk '{ print $1 }')
"$manager" install 1.0.1 "$bundle_2" "$sha_2" >/dev/null
"$manager" activate 1.0.1 >/dev/null
[ "$(readlink "$cores/current")" = 1.0.1 ] || fail "second Core was not activated"
[ "$(readlink "$cores/previous")" = 1.0.0 ] || fail "previous Core was not preserved"

bundle_bad_role=$tmp/core-1.0.2.tar.gz
make_bundle 1.0.2 1 1 "$host_arch" 51 "$bundle_bad_role"
sha_bad_role=$(sha256sum "$bundle_bad_role" | awk '{ print $1 }')
"$manager" install 1.0.2 "$bundle_bad_role" "$sha_bad_role" >/dev/null
if FAKE_CHECK_RESULT=0 FAKE_PREFLIGHT_RESULT=51 FAKE_EXPECT_CURRENT=1.0.1 \
	"$manager" activate 1.0.2 > "$tmp/bad-role.out" 2>&1; then
	fail "Core with failed server preflight was activated"
fi
[ "$(readlink "$cores/current")" = 1.0.1 ] || fail "failed activation did not restore current Core"
[ "$(readlink "$cores/previous")" = 1.0.0 ] || fail "failed activation did not restore rollback Core"
[ "$(cat "$service_state")" = active ] || fail "failed activation did not restore the old service"
grep -F 'current Core preserved' "$tmp/bad-role.out" >/dev/null || fail "failed activation error is not actionable"

bundle_bad_api=$tmp/core-2.0.0.tar.gz
make_bundle 2.0.0 2 1 "$host_arch" 0 "$bundle_bad_api"
sha_bad_api=$(sha256sum "$bundle_bad_api" | awk '{ print $1 }')
if "$manager" install 2.0.0 "$bundle_bad_api" "$sha_bad_api" >/dev/null 2>&1; then
	fail "incompatible Core API bundle was accepted"
fi

bundle_bad_process=$tmp/core-1.1.0.tar.gz
make_bundle 1.1.0 1 2 "$host_arch" 0 "$bundle_bad_process"
sha_bad_process=$(sha256sum "$bundle_bad_process" | awk '{ print $1 }')
if "$manager" install 1.1.0 "$bundle_bad_process" "$sha_bad_process" >/dev/null 2>&1; then
	fail "incompatible process API bundle was accepted"
fi

bundle_static_musl=$tmp/core-1.1.1.tar.gz
make_bundle 1.1.1 1 1 "$host_arch" 0 "$bundle_static_musl" musl
sha_static_musl=$(sha256sum "$bundle_static_musl" | awk '{ print $1 }')
"$manager" install 1.1.1 "$bundle_static_musl" "$sha_static_musl" >/dev/null ||
	fail "portable musl Core was rejected on a GNU/Linux host"

bundle_gnu=$tmp/core-1.1.2.tar.gz
make_bundle 1.1.2 1 1 "$host_arch" 0 "$bundle_gnu" gnu
sha_gnu=$(sha256sum "$bundle_gnu" | awk '{ print $1 }')
if CANDY_CORE_TARGET_LIBC=musl "$manager" install 1.1.2 "$bundle_gnu" "$sha_gnu" >/dev/null 2>&1; then
	fail "GNU Core was accepted on a musl host"
fi

if "$manager" install 1.2.0 "$bundle_1" "$(printf '0%.0s' $(seq 1 64))" >/dev/null 2>&1; then
	fail "bundle with incorrect outer SHA-256 was accepted"
fi

malicious=$tmp/malicious.tar.gz
malicious_stage=$tmp/malicious-stage
mkdir -p "$malicious_stage"
printf '%s\n' escape > "$malicious_stage/escape"
tar -czf "$malicious" -C "$malicious_stage" --transform='s|escape|../escape|' escape 2>/dev/null || true
if [ -s "$malicious" ] && "$manager" install 1.3.0 "$malicious" "$(sha256sum "$malicious" | awk '{ print $1 }')" >/dev/null 2>&1; then
	fail "bundle with an unsafe archive path was accepted"
fi

symlink_bundle=$tmp/symlink.tar.gz
symlink_stage=$tmp/symlink-stage
mkdir -p "$symlink_stage"
printf '%s\n' '{}' > "$symlink_stage/manifest.json"
printf '%s\n' trusted-linux-core-signature > "$symlink_stage/manifest.sig"
ln -s /bin/sh "$symlink_stage/candy-core"
tar -czf "$symlink_bundle" -C "$symlink_stage" manifest.json manifest.sig candy-core
if "$manager" install 1.3.1 "$symlink_bundle" "$(sha256sum "$symlink_bundle" | awk '{ print $1 }')" >/dev/null 2>&1; then
	fail "bundle with a symbolic-link executable was accepted"
fi

hardlink_bundle=$tmp/hardlink.tar.gz
hardlink_stage=$tmp/hardlink-stage
mkdir -p "$hardlink_stage"
printf '%s\n' '{}' > "$hardlink_stage/manifest.json"
printf '%s\n' trusted-linux-core-signature > "$hardlink_stage/manifest.sig"
ln "$hardlink_stage/manifest.json" "$hardlink_stage/candy-core"
tar -czf "$hardlink_bundle" -C "$hardlink_stage" manifest.json manifest.sig candy-core
if "$manager" install 1.3.2 "$hardlink_bundle" "$(sha256sum "$hardlink_bundle" | awk '{ print $1 }')" >/dev/null 2>&1; then
	fail "bundle with a hard-linked executable was accepted"
fi

"$manager" rollback >/dev/null
[ "$(readlink "$cores/current")" = 1.0.0 ] || fail "rollback did not activate the previous Core"
[ "$(readlink "$cores/previous")" = 1.0.1 ] || fail "rollback did not retain the replaced Core"

status_json=$("$manager" status)
printf '%s' "$status_json" | jq -e '.current_version == "1.0.0" and .previous_version == "1.0.1" and .required_core_process_api_version == 1' >/dev/null ||
	fail "manager status is incomplete"

printf '%s\n' "Candy Linux server Core bundle integration test passed"
