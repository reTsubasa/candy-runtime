#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fake_core="$tmp/candy-core"
printf '%s\n' '#!/bin/sh' 'case "$1" in runtime-api-version) printf 1 ;; core-info) printf '\''{"modules":["proxy","sdwan"]}'\'' ;; *) exit 0 ;; esac' >"$fake_core"
chmod 0755 "$fake_core"

"$root/scripts/runtime_preflight.sh" "$fake_core" "$root" >/dev/null
printf '%s\n' 'runtime_preflight_test: PASS'
