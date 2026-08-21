#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

# CANDY_CORE_BINARY belongs only to the optional real-Core E2E. Keep it from
# overriding the fake Core selected explicitly by deterministic launcher tests.
docker_e2e_core_binary=${CANDY_CORE_BINARY:-}
unset CANDY_CORE_BINARY

scripts/runtime_version_test.sh
scripts/runtime_layout_test.sh
linux/client/tests/candy_sdwan_runtime_test.sh
linux/server/tests/candy_server_launcher_test.sh
linux/server/tests/candy_server_product_command_test.sh
linux/server/tests/candy_core_manager_test.sh
linux/server/tests/candy_server_health_check_test.sh
linux/server/tests/install_candy_server_endpoint_test.sh
linux/server/tests/upgrade_candy_server_test.sh
linux/server/tests/join_linux_server_node_test.sh
CANDY_CORE_BINARY="$docker_e2e_core_binary" linux/server/tests/candy_core_docker_e2e.sh
packaging/linux/server_package_test.sh
sh -n openwrt/client/packages/candy-client/candy.init
openwrt/client/tests/init_config_test.sh
scripts/openwrt_core_manager_test.sh
scripts/openwrt_update_manager_test.sh
scripts/openwrt_runtime_health_check_test.sh
openwrt/client/tests/luci_package_test.sh
openwrt/client/tests/update_luci_test.sh
openwrt/client/tests/sdwan_luci_upload_test.sh
openwrt/client/tests/sdwan_productization_test.sh
packaging/openwrt/tests/package_gate_test.sh
packaging/openwrt/tests/sdk_container_profile_test.sh
packaging/openwrt/tests/runtime_release_test.sh
git diff --check

printf '%s\n' "Candy Runtime static verification passed"
