#!/bin/sh
set -eu

packages=$(CDPATH= cd -- "$(dirname -- "$0")/../packages" && pwd)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT

fail() {
	printf '%s\n' "openwrt_sdwan_cloud_activation_test: $*" >&2
	exit 1
}

jsonfilter() {
	local input= expression=
	while [ "$#" -gt 0 ]; do
		case "$1" in
			-i) input=$2; shift 2 ;;
			-e) expression=$2; shift 2 ;;
			*) return 1 ;;
		esac
	done
	jq -er ".${expression#@.}" "$input"
}

command() {
	if [ "$1" = -v ] && [ "$2" = jsonfilter ]; then
		return 0
	fi
	builtin command "$@"
}

. "$packages/candy-client/candy.init"

CANDY_SDWAN_STATE_DIR=$test_root/sdwan
CANDY_SDWAN_ACTIVATIONS_DIR=$CANDY_SDWAN_STATE_DIR/activations
CANDY_SDWAN_CANDIDATE=$CANDY_SDWAN_STATE_DIR/candidate
CANDY_SDWAN_ACTIVE=$CANDY_SDWAN_STATE_DIR/active
LOG_FILE=$test_root/candy.log
hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
delivery=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
projection=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
activation=$CANDY_SDWAN_ACTIVATIONS_DIR/$hash
mkdir -p "$activation"
printf '%s\n' 'core configuration' >"$activation/core.toml"
printf '%s\n' '{"schema_version":1}' >"$activation/declaration.json"
printf '%s\n' "{\"schema_version\":1,\"activation_id\":\"$hash\",\"delivery_etag\":\"\\\"sha256-$delivery\\\"\",\"delivery_sha256\":\"$delivery\",\"projection_publication_id\":\"11111111-2222-3333-4444-555555555555\",\"projection_content_hash\":\"$projection\",\"segment_generation\":1,\"projection_generation\":2,\"core_role\":\"client_sdwan\",\"core_config\":\"core.toml\",\"netd_declaration\":\"declaration.json\",\"grant_refresh_after_unix\":0,\"grant_expires_at_unix\":4102444800}" >"$activation/activation-v1.json"
ln -s "activations/$hash" "$CANDY_SDWAN_CANDIDATE"

load_sdwan_candidate || fail "valid authenticated activation was rejected"
[ "$CANDY_SDWAN_CANDIDATE_HASH" = "$hash" ] || fail "candidate hash was not loaded"
[ "$CANDY_SDWAN_CONFIG" = "$activation/core.toml" ] || fail "Core config was not bound to the immutable activation"
[ "$CANDY_SDWAN_DECLARATION" = "$activation/declaration.json" ] || fail "netd declaration was not bound to the immutable activation"
[ "$CANDY_SDWAN_CORE_ROLE" = client_sdwan ] || fail "Core role was not loaded"

promote_sdwan_active "activations/$hash" || fail "valid activation could not be promoted"
[ "$(readlink "$CANDY_SDWAN_ACTIVE")" = "activations/$hash" ] || fail "active pointer was not atomically promoted"

rm -f "$CANDY_SDWAN_CANDIDATE"
ln -s "../activations/$hash" "$CANDY_SDWAN_CANDIDATE"
if load_sdwan_candidate; then
	fail "candidate path traversal was accepted"
fi

rm -f "$CANDY_SDWAN_CANDIDATE"
ln -s "activations/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "$CANDY_SDWAN_CANDIDATE"
if load_sdwan_candidate; then
	fail "non-canonical activation hash was accepted"
fi

rm -f "$CANDY_SDWAN_CANDIDATE"
ln -s "activations/$hash" "$CANDY_SDWAN_CANDIDATE"
mv "$activation/core.toml" "$activation/core.toml.real"
ln -s core.toml.real "$activation/core.toml"
if load_sdwan_candidate; then
	fail "symlinked Core configuration was accepted"
fi
rm -f "$activation/core.toml"
mv "$activation/core.toml.real" "$activation/core.toml"

ordinary_touched=0
network_cleanup() { ordinary_touched=1; return 1; }
stop_candy_clients_for_fail_open() { ordinary_touched=1; return 1; }
interrupt_sdwan_processes() { :; }
sdwan_runtime_state() { :; }
sdwan_fail_open() { :; }

rm -f "$CANDY_SDWAN_CANDIDATE"
sdwan_reconcile || fail "Cloud withdrawal reconcile failed"
[ ! -e "$CANDY_SDWAN_ACTIVE" ] && [ ! -L "$CANDY_SDWAN_ACTIVE" ] || fail "withdrawal retained the active pointer"
[ "$ordinary_touched" -eq 0 ] || fail "withdrawal touched ordinary Candy"

ln -s "activations/$hash" "$CANDY_SDWAN_ACTIVE"
ln -s "activations/$hash" "$CANDY_SDWAN_CANDIDATE"
sed 's/"activation_id":"[^"]*"/"activation_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"/' \
	"$activation/activation-v1.json" >"$activation/activation-v1.json.invalid"
mv "$activation/activation-v1.json.invalid" "$activation/activation-v1.json"
if sdwan_reconcile; then
	fail "invalid candidate reconcile unexpectedly succeeded"
fi
[ "$(readlink "$CANDY_SDWAN_ACTIVE")" = "activations/$hash" ] || fail "rejected activation discarded last-good evidence"
[ ! -e "$CANDY_SDWAN_CANDIDATE" ] && [ ! -L "$CANDY_SDWAN_CANDIDATE" ] || fail "rejected candidate was left pending"
[ "$ordinary_touched" -eq 0 ] || fail "rejected activation touched ordinary Candy"

printf '%s\n' 'Candy OpenWrt Cloud activation lifecycle test passed'
