#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-update-manager-test.XXXXXX")
tmp=$(CDPATH= cd -- "$tmp" && pwd -P)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
bin=$tmp/bin
state=$tmp/state
assets=$tmp/assets
mkdir -p "$bin" "$state" "$assets"

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
	'@.core.releases.*.version') expression='.core.releases[].version' ;;
	@.*) expression=".${expression#@.}" ;;
esac
if [ -n "$file" ]; then
	jq -r "$expression" "$file"
else
	jq -r "$expression"
fi
EOF
chmod 0755 "$bin/jsonfilter"

cat > "$bin/uclient-fetch" <<'EOF'
#!/bin/sh
destination=
url=
while [ "$#" -gt 0 ]; do
	case "$1" in
		-O) destination=$2; shift 2 ;;
		-q) shift ;;
		*) url=$1; shift ;;
	esac
done
printf '%s\n' "$url" >> "$FAKE_FETCH_LOG"
[ -z "${FAKE_FETCH_DEST_LOG:-}" ] || printf '%s %s\n' "$url" "$destination" >> "$FAKE_FETCH_DEST_LOG"
case "$url" in
	*/candy-core-*.tar.gz)
		if [ "${FAKE_FETCH_FAIL_CORE:-0}" = 1 ]; then
			printf '%s\n' partial-core-download > "$destination"
			exit 95
		fi
	;;
esac
case "$url" in
	https://raw.githubusercontent.com/reTsubasa/candy-release/refs/heads/main/channels/stable.json) source=$FAKE_CATALOG ;;
	https://raw.githubusercontent.com/reTsubasa/candy-release/refs/heads/main/channels/stable.json.sig) source=$FAKE_CATALOG_SIGNATURE ;;
	https://github.com/reTsubasa/candy-release/releases/download/*) source="$FAKE_ASSET_DIR/${url##*/}" ;;
	*) exit 92 ;;
esac
[ -f "$source" ] || exit 93
cp "$source" "$destination"
EOF
chmod 0755 "$bin/uclient-fetch"

cat > "$bin/usign" <<'EOF'
#!/bin/sh
key=
message=
signature=
while [ "$#" -gt 0 ]; do
	case "$1" in
		-p) key=$2; shift 2 ;;
		-m) message=$2; shift 2 ;;
		-x) signature=$2; shift 2 ;;
		*) shift ;;
	esac
done
[ -f "$message" ] && [ "$(cat "$signature" 2>/dev/null)" = trusted-signature ] || exit 1
grep -Fx 'RWT1+qFiLjZvb7KNiVxQkJhfovyk2jBy+DEDVozcS3Z1CcxO0larkH4P' "$key" >/dev/null
EOF
chmod 0755 "$bin/usign"

cat > "$bin/candy-core-manager" <<'EOF'
#!/bin/sh
case "$1" in
	status) printf '%s\n' '{"schema_version":1,"current_version":"0.3.4","installed":[{"version":"0.3.4","active":true,"rollback":false,"managed":true},{"version":"0.3.5","active":false,"rollback":false,"managed":false}],"operation":{"state":"completed","action":"remove","version":"0.3.9"}}' ;;
	install)
		printf '%s\n' "$*" >> "$FAKE_CORE_LOG"
		case "$3" in file:///*) [ -f "${3#file://}" ] ;; *) exit 1 ;; esac
		if [ "${FAKE_CORE_INSTALL_FAIL:-0}" = 1 ]; then
			printf '%s\n' '{"schema_version":2,"state":"error","action":"install","version":"0.3.5","message":"failed","phase":"install","error_code":"test_failure","detail":"simulated Core manager failure","updated_at":1}' > "$CANDY_CORE_OPERATION_FILE"
			exit 96
		fi
		;;
	install-local)
		printf '%s\n' "$*" >> "$FAKE_CORE_LOG"
		[ -f "$2" ] || exit 1
		printf '%s\n' '{"schema_version":2,"state":"completed","action":"install-local","version":"0.3.6","message":"installed","phase":"install","error_code":"","detail":"","updated_at":1}' > "$CANDY_CORE_OPERATION_FILE"
		;;
	*) printf '%s\n' "$*" >> "$FAKE_CORE_LOG"; exit 94 ;;
esac
EOF
chmod 0755 "$bin/candy-core-manager"

cat > "$bin/apk" <<'EOF'
#!/bin/sh
case "$1" in
	version)
		[ "$2" = -t ] || exit 1
		node -e 'const a=process.argv[1].match(/\d+/g).map(Number),b=process.argv[2].match(/\d+/g).map(Number); for(let i=0;i<Math.max(a.length,b.length);i++){if((a[i]||0)!=(b[i]||0)){process.stdout.write((a[i]||0)>(b[i]||0)?">\n":"<\n");process.exit(0)}}process.stdout.write("=\n")' "$3" "$4"
		;;
	adbdump)
		name=$(basename "$2")
		case "$name" in
			candy-client-*) package=candy-client; arch=${FAKE_APK_ARCH:-x86_64}; version=${name#candy-client-}; version=${version%.apk} ;;
			luci-app-candy-*) package=luci-app-candy; arch=noarch; version=${name#luci-app-candy-}; version=${version%.apk} ;;
			*) exit 1 ;;
		esac
		printf 'info:\n  name: %s\n  version: %s\n  arch: %s\n' "$package" "$version" "$arch"
		;;
	add)
		printf '%s\n' "$*" >> "$FAKE_APK_LOG"
		for argument in "$@"; do
			case "${argument##*/}" in
				candy-client-*.apk)
					version=${argument##*/candy-client-}; version=${version%.apk}
					printf '%s\n' "$version" > "$FAKE_INSTALLED_VERSION"
					if [ "${FAKE_APK_AUTOSTART:-0}" = 1 ] && [ "${argument##*/}" = candy-client-0.4.0-r3.apk ]; then
						printf '%s\n' 1 > "$FAKE_SERVICE_RUNNING"
					fi
					;;
			esac
		done
		;;
	*) exit 1 ;;
esac
EOF
chmod 0755 "$bin/apk"

cat > "$bin/candy-service" <<'EOF'
#!/bin/sh
printf '%s\n' "$1" >> "$FAKE_SERVICE_LOG"
case "$1" in
	enabled) [ "$(cat "$FAKE_SERVICE_ENABLED")" = 1 ] ;;
	running) [ "$(cat "$FAKE_SERVICE_RUNNING")" = 1 ] ;;
	enable) printf '%s\n' 1 > "$FAKE_SERVICE_ENABLED" ;;
	disable) printf '%s\n' 0 > "$FAKE_SERVICE_ENABLED" ;;
	start) printf '%s\n' 1 > "$FAKE_SERVICE_RUNNING" ;;
	stop) printf '%s\n' 0 > "$FAKE_SERVICE_RUNNING" ;;
	*) exit 1 ;;
esac
EOF
chmod 0755 "$bin/candy-service"

cat > "$bin/candy-health" <<'EOF'
#!/bin/sh
[ "$1" = client ] || exit 1
[ "$(cat "$FAKE_SERVICE_RUNNING")" = 1 ] || exit 1
if [ "${FAKE_FAIL_TARGET_HEALTH:-0}" = 1 ] && [ "$(cat "$FAKE_INSTALLED_VERSION")" = 0.4.0-r3 ]; then
	exit 1
fi
EOF
chmod 0755 "$bin/candy-health"

printf '%s\n' runtime-client-r3 > "$assets/candy-client-0.4.0-r3.apk"
printf '%s\n' runtime-luci-r3 > "$assets/luci-app-candy-0.4.0-r3.apk"
printf '%s\n' runtime-client-r1 > "$assets/candy-client-0.4.0-r1.apk"
printf '%s\n' runtime-luci-r1 > "$assets/luci-app-candy-0.4.0-r1.apk"
printf '%s\n' runtime-client-r2 > "$assets/candy-client-0.4.0-r2.apk"
printf '%s\n' runtime-luci-r2 > "$assets/luci-app-candy-0.4.0-r2.apk"
printf '%s\n' core-0.3.4 > "$assets/candy-core-0.3.4-x86_64-unknown-linux-musl.tar.gz"
printf '%s\n' core-0.3.5 > "$assets/candy-core-0.3.5-x86_64-unknown-linux-musl.tar.gz"
printf '%s\n' core-arm-0.3.5 > "$assets/candy-core-0.3.5-armv7-unknown-linux-musleabihf.tar.gz"

file_sha() { sha256sum "$1" | awk '{ print $1 }'; }
file_size() { wc -c < "$1" | tr -d ' '; }

make_catalog() {
	sequence=$1
	runtime_revision=$2
	core_version=$3
	core_url_mode=${4:-trusted}
	runtime_display=0.4.0-r$runtime_revision
	client_file="$assets/candy-client-$runtime_display.apk"
	luci_file="$assets/luci-app-candy-$runtime_display.apk"
	core_file="$assets/candy-core-$core_version-x86_64-unknown-linux-musl.tar.gz"
	core_url="https://github.com/reTsubasa/candy-release/releases/download/core-v$core_version/candy-core-$core_version-x86_64-unknown-linux-musl.tar.gz"
	[ "$core_url_mode" = trusted ] || core_url="https://example.invalid/candy-core.tar.gz"
	current_entry=
	if [ "$runtime_revision" != 2 ]; then
		current_entry="\"v0_4_0_r2\":{\"version\":\"0.4.0\",\"revision\":2,\"display_version\":\"0.4.0-r2\",\"commit\":\"test\",\"targets\":{\"openwrt_25_12_4_x86_64\":{\"openwrt_release\":\"25.12.4\",\"target\":\"x86/64\",\"arch\":\"x86_64\",\"package_format\":\"apk\",\"candy_client\":{\"url\":\"https://github.com/reTsubasa/candy-release/releases/download/runtime-v0.4.0-r2/candy-client-0.4.0-r2.apk\",\"sha256\":\"$(file_sha "$assets/candy-client-0.4.0-r2.apk")\",\"size\":$(file_size "$assets/candy-client-0.4.0-r2.apk")},\"luci_app_candy\":{\"url\":\"https://github.com/reTsubasa/candy-release/releases/download/runtime-v0.4.0-r2/luci-app-candy-0.4.0-r2.apk\",\"sha256\":\"$(file_sha "$assets/luci-app-candy-0.4.0-r2.apk")\",\"size\":$(file_size "$assets/luci-app-candy-0.4.0-r2.apk")}}}},"
	fi
	cat > "$FAKE_CATALOG" <<EOF
{"schema_version":1,"sequence":$sequence,"channel":"stable","published_at":"2026-08-05T02:00:00Z","runtime":{"latest":"v0_4_0_r$runtime_revision","releases":{$current_entry"v0_4_0_r$runtime_revision":{"version":"0.4.0","revision":$runtime_revision,"display_version":"$runtime_display","commit":"test","targets":{"openwrt_25_12_4_x86_64":{"openwrt_release":"25.12.4","target":"x86/64","arch":"x86_64","package_format":"apk","candy_client":{"url":"https://github.com/reTsubasa/candy-release/releases/download/runtime-v$runtime_display/candy-client-$runtime_display.apk","sha256":"$(file_sha "$client_file")","size":$(file_size "$client_file")},"luci_app_candy":{"url":"https://github.com/reTsubasa/candy-release/releases/download/runtime-v$runtime_display/luci-app-candy-$runtime_display.apk","sha256":"$(file_sha "$luci_file")","size":$(file_size "$luci_file")}}}}}},"core":{"latest":"v$(printf '%s' "$core_version" | tr . _)","releases":{"v$(printf '%s' "$core_version" | tr . _)":{"version":"$core_version","commit":"test","process_api_version":1,"core_api_version":1,"protocol_version":"0.3","targets":{"linux_musl_x86_64":{"target":"x86_64-unknown-linux-musl","os":"linux","libc":"musl","arch":"x86_64","url":"$core_url","sha256":"$(file_sha "$core_file")","size":$(file_size "$core_file")}}}}}}
EOF
	core_key="v$(printf '%s' "$core_version" | tr . _)"
	jq --arg key "$core_key" --arg version "$core_version" '
		.core.releases[$key].abi_profiles.cloud_control_linux_glibc_x86_64 = {
			artifact_kind: "shared-library",
			target: "x86_64-unknown-linux-gnu",
			os: "linux",
			libc: "glibc",
			arch: "x86_64",
			library: "libcandy_core_cloud.so",
			module_abi_version: 1,
			build_request_schema: "candy-core-cloud-build-v1",
			url: ("https://github.com/reTsubasa/candy-release/releases/download/core-v" + $version + "/candy-core-" + $version + "-cloud-abi-x86_64-unknown-linux-gnu.tar.gz"),
			sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			size: 1024
		} |
		.core_modules = {
			latest: "v0_3_10",
			releases: {
				v0_3_10: {
					version: "0.3.10",
					legacy: true,
					url: "https://github.com/reTsubasa/candy-release/releases/download/core-cloud-module-v0.3.10/candy-core-cloud-module-0.3.10-x86_64-unknown-linux-gnu.tar.gz"
				}
			}
		} |
		.core.releases.v0_3_9 = (.core.releases[$key] |
			.version = "0.3.9" |
			.targets.linux_musl_x86_64.url = "https://github.com/reTsubasa/candy-release/releases/download/core-v0.3.9/candy-core-0.3.9-x86_64-unknown-linux-musl.tar.gz")
	' "$FAKE_CATALOG" > "$FAKE_CATALOG.next"
	mv "$FAKE_CATALOG.next" "$FAKE_CATALOG"
	printf '%s\n' trusted-signature > "$FAKE_CATALOG_SIGNATURE"
}

manager=$root/openwrt/client/packages/candy-client/candy-update-manager
export PATH="$bin:$PATH"
export CANDY_UPDATE_STATE_ROOT="$state"
export CANDY_UPDATE_CATALOG_KEY="$root/openwrt/client/packages/candy-client/catalog-release.pub"
export CANDY_UPDATE_OPERATION_FILE="$tmp/operation.json"
export CANDY_CORE_OPERATION_FILE="$tmp/core-operation.json"
export CANDY_UPDATE_LOCK_DIR="$tmp/update.lock"
export CANDY_UPDATE_UPLOAD_ROOT="$tmp/uploads"
export CANDY_UPDATE_CORE_STAGING_ROOT="$tmp/core-staging"
export CANDY_CORE_MANAGER="$bin/candy-core-manager"
export CANDY_UPDATE_TEST_PLATFORM=1
export CANDY_UPDATE_TEST_OPENWRT_RELEASE=25.12.4
export CANDY_UPDATE_TEST_TARGET=x86/64
export CANDY_UPDATE_TEST_ARCH=x86_64
export FAKE_CATALOG="$tmp/stable.json"
export FAKE_CATALOG_SIGNATURE="$tmp/stable.json.sig"
export FAKE_ASSET_DIR="$assets"
export FAKE_FETCH_LOG="$tmp/fetch.log"
export FAKE_FETCH_DEST_LOG="$tmp/fetch-destination.log"
export FAKE_CORE_LOG="$tmp/core.log"
export FAKE_APK_LOG="$tmp/apk.log"
export FAKE_SERVICE_LOG="$tmp/service.log"
export FAKE_SERVICE_ENABLED="$tmp/service.enabled"
export FAKE_SERVICE_RUNNING="$tmp/service.running"
export FAKE_INSTALLED_VERSION="$tmp/installed-version"
export FAKE_APK_AUTOSTART=0
export CANDY_UPDATE_SERVICE_INIT="$bin/candy-service"
export CANDY_UPDATE_HEALTH_CHECK="$bin/candy-health"
export CANDY_UPDATE_CONFIG_FILE="$tmp/candy.config"
# Keep this fixture independent from the package revision used by the caller
# or by a release workflow environment.
export CANDY_RUNTIME_VERSION=0.4.0
export CANDY_RUNTIME_RELEASE=2
export CANDY_UPDATE_HEALTH_WAIT_SECONDS=1
printf '%s\n' 1 > "$FAKE_SERVICE_ENABLED"
printf '%s\n' 1 > "$FAKE_SERVICE_RUNNING"
printf '%s\n' 0.4.0-r2 > "$FAKE_INSTALLED_VERSION"
printf '%s\n' test-config > "$CANDY_UPDATE_CONFIG_FILE"

make_catalog 1 3 0.3.5
"$manager" check >/dev/null
[ "$(cat "$state/sequence")" = 1 ]
[ "$(stat -c '%a' "$state" 2>/dev/null || stat -f '%Lp' "$state")" = 700 ]
grep -Fx 'https://raw.githubusercontent.com/reTsubasa/candy-release/refs/heads/main/channels/stable.json' "$FAKE_FETCH_LOG" >/dev/null
grep -q '"catalog_valid":true' <<EOF
$("$manager" status)
EOF
grep -q '"core":{"schema_version":1' <<EOF
$("$manager" status)
EOF
grep -q '"version":"0.3.5"' <<EOF
$("$manager" status)
EOF
status_json=$("$manager" status)
[ "$(printf '%s' "$status_json" | jq -r '.core_candidates[] | select(.version == "0.3.9") | .installed')" = false ] || {
	echo "Core operation history incorrectly marked an uninstalled version as installed" >&2
	exit 1
}

"$manager" check >/dev/null
sed 's/2026-08-05T02:00:00Z/2026-08-05T02:00:01Z/' "$FAKE_CATALOG" > "$tmp/changed.json"
cp "$tmp/changed.json" "$FAKE_CATALOG"
if "$manager" check >/dev/null 2>&1; then
	echo "same-sequence changed catalog was accepted" >&2
	exit 1
fi

make_catalog 2 3 0.3.5
"$manager" check >/dev/null
make_catalog 1 3 0.3.5
if "$manager" check >/dev/null 2>&1; then
	echo "catalog sequence rollback was accepted" >&2
	exit 1
fi
[ "$(cat "$state/sequence")" = 2 ]

make_catalog 3 3 0.3.5 evil
if "$manager" check >/dev/null 2>&1; then
	echo "catalog with a non-release Core URL was accepted" >&2
	exit 1
fi

make_catalog 3 3 0.3.5
printf '%s\n' bad-signature > "$FAKE_CATALOG_SIGNATURE"
if "$manager" check >/dev/null 2>&1; then
	echo "catalog with an invalid signature was accepted" >&2
	exit 1
fi
printf '%s\n' trusted-signature > "$FAKE_CATALOG_SIGNATURE"

if CANDY_UPDATE_TEST_TARGET=x86/generic "$manager" check >/dev/null 2>&1; then
	echo "catalog check accepted the wrong OpenWrt target" >&2
	exit 1
fi

# The same signed release entry must resolve to the IPQ40xx Runtime package
# and ARMv7 musl Core without weakening the x86_64 validation path.
arm_core="$assets/candy-core-0.3.5-armv7-unknown-linux-musleabihf.tar.gz"
jq --arg core_url "https://github.com/reTsubasa/candy-release/releases/download/core-v0.3.5/candy-core-0.3.5-armv7-unknown-linux-musleabihf.tar.gz" \
	--arg core_sha "$(file_sha "$arm_core")" --argjson core_size "$(file_size "$arm_core")" '
	.runtime.releases.v0_4_0_r3.targets.openwrt_25_12_4_arm_cortex_a7_neon_vfpv4 =
		(.runtime.releases.v0_4_0_r3.targets.openwrt_25_12_4_x86_64 |
		 .target = "ipq40xx/generic" | .arch = "arm_cortex-a7_neon-vfpv4" |
		 .candy_client.url = (.candy_client.url | sub("\\.apk$"; "-ipq40xx-generic-arm_cortex-a7_neon-vfpv4.apk")) |
		 .luci_app_candy.url = (.luci_app_candy.url | sub("\\.apk$"; "-ipq40xx-generic-arm_cortex-a7_neon-vfpv4.apk"))) |
	.core.releases.v0_3_5.targets.linux_musl_armv7 = {
		target:"armv7-unknown-linux-musleabihf",os:"linux",libc:"musl",arch:"arm",
		url:$core_url,sha256:$core_sha,size:$core_size
	}' "$FAKE_CATALOG" > "$tmp/arm-catalog.json"
cp "$tmp/arm-catalog.json" "$FAKE_CATALOG"
CANDY_UPDATE_TEST_TARGET=ipq40xx/generic CANDY_UPDATE_TEST_ARCH=armv7l "$manager" check >/dev/null
CANDY_UPDATE_TEST_TARGET=ipq40xx/generic CANDY_UPDATE_TEST_ARCH=arm_cortex-a7_neon-vfpv4 "$manager" check >/dev/null

"$manager" check >/dev/null

# A live update lock must block before any volatile Core staging is created.
mkdir "$CANDY_UPDATE_LOCK_DIR"
printf '%s\n' "$$" > "$CANDY_UPDATE_LOCK_DIR/pid"
if "$manager" install-core v0_3_5 >/dev/null 2>&1; then
	echo "concurrent Core update bypassed the live update lock" >&2
	exit 1
fi
[ ! -e "$CANDY_UPDATE_CORE_STAGING_ROOT" ]
rm -f "$CANDY_UPDATE_LOCK_DIR/pid"
rmdir "$CANDY_UPDATE_LOCK_DIR"

# Configured staging roots must be private real directories outside persistent
# update state. A symlink or a state-backed path is rejected before download.
mkdir -m 0700 "$tmp/staging-target"
ln -s "$tmp/staging-target" "$tmp/staging-link"
if CANDY_UPDATE_CORE_STAGING_ROOT="$tmp/staging-link" "$manager" install-core v0_3_5 >/dev/null 2>&1; then
	echo "symbolic-link Core staging root was accepted" >&2
	exit 1
fi
[ -z "$(find "$tmp/staging-target" -mindepth 1 -print 2>/dev/null | sed -n '1p')" ]
mkdir -m 0755 "$tmp/staging-open"
if CANDY_UPDATE_CORE_STAGING_ROOT="$tmp/staging-open" "$manager" install-core v0_3_5 >/dev/null 2>&1; then
	echo "non-private Core staging root was accepted" >&2
	exit 1
fi
if CANDY_UPDATE_CORE_STAGING_ROOT="$state/core-staging" "$manager" install-core v0_3_5 >/dev/null 2>&1; then
	echo "persistent update state was accepted as the Core staging root" >&2
	exit 1
fi

# Partial downloads and downstream Core-manager failures must leave the
# volatile staging root empty.
if FAKE_FETCH_FAIL_CORE=1 "$manager" install-core v0_3_5 >/dev/null 2>&1; then
	echo "failed Core download was accepted" >&2
	exit 1
fi
[ -d "$CANDY_UPDATE_CORE_STAGING_ROOT" ]
[ -z "$(find "$CANDY_UPDATE_CORE_STAGING_ROOT" -mindepth 1 -print 2>/dev/null | sed -n '1p')" ]
if FAKE_CORE_INSTALL_FAIL=1 "$manager" install-core v0_3_5 >/dev/null 2>&1; then
	echo "failed Core manager installation was accepted" >&2
	exit 1
fi
[ -z "$(find "$CANDY_UPDATE_CORE_STAGING_ROOT" -mindepth 1 -print 2>/dev/null | sed -n '1p')" ]

"$manager" install-core v0_3_5 >/dev/null
grep -Eq '^install 0\.3\.5 file:///.+ [0-9a-f]{64}$' "$FAKE_CORE_LOG"
grep -E "^install 0\\.3\\.5 file://$CANDY_UPDATE_CORE_STAGING_ROOT/\\.core-[0-9]+/core\\.tar\\.gz [0-9a-f]{64}$" "$FAKE_CORE_LOG" >/dev/null
grep -E "candy-core-0\\.3\\.5-x86_64-unknown-linux-musl\\.tar\\.gz $CANDY_UPDATE_CORE_STAGING_ROOT/\\.core-[0-9]+/core\\.tar\\.gz$" "$FAKE_FETCH_DEST_LOG" >/dev/null
[ -z "$(find "$CANDY_UPDATE_CORE_STAGING_ROOT" -mindepth 1 -print 2>/dev/null | sed -n '1p')" ]
for residual in "$state"/.core-*; do
	[ ! -e "$residual" ] && [ ! -L "$residual" ] || { echo "Core download was staged in persistent update state" >&2; exit 1; }
done
! grep -F 'activate' "$FAKE_CORE_LOG" >/dev/null
grep -F 'releases/download/core-v0.3.5/candy-core-0.3.5-x86_64-unknown-linux-musl.tar.gz' "$FAKE_FETCH_LOG" >/dev/null
if grep -E 'core-cloud-module-v|cloud-abi' "$FAKE_FETCH_LOG" >/dev/null; then
	echo "OpenWrt update manager consumed a Cloud ABI or legacy module artifact" >&2
	exit 1
fi

"$manager" install-runtime v0_4_0_r3 >/dev/null
grep -F 'add --allow-untrusted ' "$FAKE_APK_LOG" >/dev/null
grep -F 'candy-client-0.4.0-r3.apk' "$FAKE_APK_LOG" >/dev/null
grep -F 'luci-app-candy-0.4.0-r3.apk' "$FAKE_APK_LOG" >/dev/null
grep -Fx stop "$FAKE_SERVICE_LOG" >/dev/null
grep -Fx disable "$FAKE_SERVICE_LOG" >/dev/null
grep -Fx enable "$FAKE_SERVICE_LOG" >/dev/null
grep -Fx start "$FAKE_SERVICE_LOG" >/dev/null
[ "$(cat "$CANDY_UPDATE_CONFIG_FILE")" = test-config ]

# OpenWrt's default APK post-upgrade hook starts init scripts. The update
# manager must adopt that healthy instance instead of starting it a second
# time while it is still transitioning through procd.
: > "$FAKE_SERVICE_LOG"
printf '%s\n' 1 > "$FAKE_SERVICE_RUNNING"
export FAKE_APK_AUTOSTART=1
"$manager" install-runtime v0_4_0_r3 >/dev/null
export FAKE_APK_AUTOSTART=0
grep -Fx stop "$FAKE_SERVICE_LOG" >/dev/null
grep -Fx disable "$FAKE_SERVICE_LOG" >/dev/null
grep -Fx enable "$FAKE_SERVICE_LOG" >/dev/null
if grep -Fx start "$FAKE_SERVICE_LOG" >/dev/null; then
	echo "update manager issued a duplicate start after APK post-upgrade startup" >&2
	exit 1
fi
[ "$(cat "$FAKE_SERVICE_RUNNING")" = 1 ]

apk_lines_before=$(wc -l < "$FAKE_APK_LOG" | tr -d ' ')
if FAKE_FAIL_TARGET_HEALTH=1 "$manager" install-runtime v0_4_0_r3 >/dev/null 2>&1; then
	echo "unhealthy Runtime update was accepted" >&2
	exit 1
fi
tail -n +$((apk_lines_before + 1)) "$FAKE_APK_LOG" | grep -F 'candy-client-0.4.0-r2.apk' >/dev/null
tail -n +$((apk_lines_before + 1)) "$FAKE_APK_LOG" | grep -F -- '--force-old-apk' >/dev/null
[ "$(cat "$FAKE_INSTALLED_VERSION")" = 0.4.0-r2 ]

make_catalog 4 3 0.3.4
"$manager" check >/dev/null
"$manager" install-core v0_3_4 >/dev/null
grep -Eq '^install 0\.3\.4 file:///.+ [0-9a-f]{64}$' "$FAKE_CORE_LOG"

mkdir -m 0700 "$CANDY_UPDATE_UPLOAD_ROOT"
printf '%s\n' uploaded-core > "$CANDY_UPDATE_UPLOAD_ROOT/core-test.tar.gz"
"$manager" install-core-upload "$CANDY_UPDATE_UPLOAD_ROOT/core-test.tar.gz" >/dev/null
grep -F 'install-local ' "$FAKE_CORE_LOG" >/dev/null
[ ! -e "$CANDY_UPDATE_UPLOAD_ROOT/core-test.tar.gz" ]
printf '%s\n' invalid-upload > "$tmp/outside.tar.gz"
if "$manager" install-core-upload "$tmp/outside.tar.gz" >/dev/null 2>&1; then
	echo "Core upload outside the protected staging directory was accepted" >&2
	exit 1
fi

make_catalog 5 1 0.3.5
"$manager" check >/dev/null
if "$manager" install-runtime v0_4_0_r1 >/dev/null 2>&1; then
	echo "Runtime downgrade was accepted" >&2
	exit 1
fi

# The status contract exposes the five newest compatible catalog releases,
# independently of the latest pointer.
cp "$assets/candy-core-0.3.5-x86_64-unknown-linux-musl.tar.gz" "$assets/candy-core-0.3.9-x86_64-unknown-linux-musl.tar.gz"
make_catalog 6 3 0.3.9
base_entry=$(jq -c '.core.releases.v0_3_9' "$FAKE_CATALOG")
for candidate in 0.3.4 0.3.5 0.3.6 0.3.7 0.3.8; do
	key="v$(printf '%s' "$candidate" | tr . _)"
	base_entry=$(printf '%s\n' "$base_entry" | jq -c --arg version "$candidate" '.version=$version | .targets.linux_musl_x86_64.url=("https://github.com/reTsubasa/candy-release/releases/download/core-v" + $version + "/candy-core-" + $version + "-x86_64-unknown-linux-musl.tar.gz")')
	jq --arg key "$key" --argjson entry "$base_entry" '.core.releases[$key]=$entry' "$FAKE_CATALOG" > "$FAKE_CATALOG.next"
	mv "$FAKE_CATALOG.next" "$FAKE_CATALOG"
done
jq '.core.latest="v0_3_9"' "$FAKE_CATALOG" > "$FAKE_CATALOG.next"
mv "$FAKE_CATALOG.next" "$FAKE_CATALOG"
"$manager" check >/dev/null
status=$($manager status)
printf '%s\n' "$status" | jq -e '.core_candidates | length == 5 and .[0].version == "0.3.9" and .[4].version == "0.3.5"' >/dev/null

if "$manager" install-core '../../bad' >/dev/null 2>&1; then
	echo "invalid version key was accepted" >&2
	exit 1
fi

grep -Fx 'untrusted comment: Candy release catalog 2026' "$root/openwrt/client/packages/candy-client/catalog-release.pub" >/dev/null
grep -Fx 'RWT1+qFiLjZvb7KNiVxQkJhfovyk2jBy+DEDVozcS3Z1CcxO0larkH4P' "$root/openwrt/client/packages/candy-client/catalog-release.pub" >/dev/null

printf '%s\n' "OpenWrt Candy signed update manager test passed"
