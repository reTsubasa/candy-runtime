#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

scripts/runtime_version_test.sh
scripts/runtime_layout_test.sh
sh -n openwrt/client/packages/candy-client/candy.init
openwrt/client/tests/init_config_test.sh
scripts/openwrt_core_manager_test.sh
openwrt/client/tests/luci_package_test.sh
openwrt/client/tests/sdwan_productization_test.sh
packaging/openwrt/tests/package_gate_test.sh
git diff --check

printf '%s\n' "Candy Runtime static verification passed"
