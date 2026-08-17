#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
target=${1:-x86_64-unknown-linux-gnu}
dist_root=${CANDY_LINUX_DIST_DIR:-$repo_root/dist/linux}

case "$target" in
	x86_64-unknown-linux-*) artifact_arch=x86_64 ;;
	aarch64-unknown-linux-*) artifact_arch=aarch64 ;;
	*)
		printf '%s\n' "unsupported Linux server release target: $target" >&2
		exit 1
		;;
esac

launcher=$repo_root/linux/server/apps/candy-server/serverd-linux
product_launcher=$repo_root/linux/server/apps/candy-server/candy-server
sdwan_runtime=$repo_root/linux/common/apps/candy-sdwan-runtime/candy-sdwan-runtime
sdwan_agent=${CANDY_SDWAN_AGENT_BINARY:-$repo_root/target/$target/release/candy-sdwan-agent}
netd_binary=${CANDY_NETD_BINARY:-$repo_root/target/$target/release/candy-netd}
enroll_binary=${CANDY_CLOUD_ENROLL_BINARY:-$repo_root/target/$target/release/candy-cloud-enroll}
sync_binary=${CANDY_CLOUD_SYNC_BINARY:-$repo_root/target/$target/release/candy-cloud-sync}
edge_product=$repo_root/linux/client/apps/candy/candy
edge_launcher=$repo_root/linux/client/apps/candy-client/candy-client
core_manager=$repo_root/linux/server/apps/candy-server/candy-core-manager
health_check=$repo_root/linux/server/apps/candy-server/candy-server-health-check
stage=$dist_root/server/$artifact_arch
[ -f "$launcher" ] || {
	printf '%s\n' "Linux server Runtime launcher is missing: $launcher" >&2
	exit 1
}
[ -f "$product_launcher" ] || { printf '%s\n' "Linux candy-server command is missing: $product_launcher" >&2; exit 1; }
[ -f "$sdwan_runtime" ] || { printf '%s\n' "SD-WAN Runtime helper is missing: $sdwan_runtime" >&2; exit 1; }
[ -f "$edge_product" ] || { printf '%s\n' "Linux candy command is missing: $edge_product" >&2; exit 1; }
[ -f "$edge_launcher" ] || { printf '%s\n' "Linux Edge launcher is missing: $edge_launcher" >&2; exit 1; }
[ -x "$sdwan_agent" ] && [ -x "$netd_binary" ] && [ -x "$enroll_binary" ] && [ -x "$sync_binary" ] || {
	cargo_cmd=${CARGO_BIN:-cargo}
	if command -v "$cargo_cmd" >/dev/null 2>&1; then
		"$cargo_cmd" build --manifest-path "$repo_root/Cargo.toml" --release --locked \
			--package candy-netd --package candy-sdwan-agent --package candy-cloud-enroll \
			--package candy-cloud-sync --target "$target"
	fi
}
[ -x "$sdwan_agent" ] || { printf '%s\n' "SD-WAN agent binary is missing: $sdwan_agent" >&2; exit 1; }
[ -x "$netd_binary" ] || { printf '%s\n' "candy-netd binary is missing: $netd_binary" >&2; exit 1; }
[ -x "$enroll_binary" ] || { printf '%s\n' "Cloud enrollment client is missing: $enroll_binary" >&2; exit 1; }
[ -x "$sync_binary" ] || { printf '%s\n' "Cloud Runtime synchronizer is missing: $sync_binary" >&2; exit 1; }
sh -n "$launcher"
sh -n "$product_launcher"
sh -n "$sdwan_runtime"
sh -n "$edge_product"
sh -n "$edge_launcher"
sh -n "$core_manager"
sh -n "$health_check"

rm -rf "$stage"
mkdir -p "$stage/usr/local/bin" "$stage/usr/local/libexec" "$stage/etc/candy" "$stage/systemd" "$stage/install"
install -m 0755 "$product_launcher" "$stage/usr/local/bin/candy-server"
install -m 0755 "$launcher" "$stage/usr/local/libexec/serverd-linux"
install -m 0755 "$sdwan_runtime" "$stage/usr/local/libexec/candy-sdwan-runtime"
install -m 0755 "$sdwan_agent" "$stage/usr/local/libexec/candy-sdwan-agent"
install -m 0755 "$netd_binary" "$stage/usr/local/libexec/candy-netd"
install -m 0755 "$enroll_binary" "$stage/usr/local/libexec/candy-cloud-enroll"
install -m 0755 "$sync_binary" "$stage/usr/local/libexec/candy-cloud-sync"
install -m 0755 "$core_manager" "$stage/usr/local/bin/candy-core-manager"
install -m 0755 "$health_check" "$stage/usr/local/libexec/candy-server-health-check"
install -m 0644 "$repo_root/linux/server/docker/server.example.toml" \
	"$stage/etc/candy/server.toml.example"
install -m 0640 "$repo_root/linux/server/packaging/cloud-sync.env.example" \
	"$stage/etc/candy/cloud-sync.env.example"
install -m 0644 "$repo_root/linux/server/packaging/candy-server.service" \
	"$stage/systemd/candy-server.service"
install -m 0644 "$repo_root/linux/server/packaging/candy-netd.service" \
	"$stage/systemd/candy-netd.service"
install -m 0644 "$repo_root/linux/server/packaging/candy-cloud-sync.service" \
	"$stage/systemd/candy-cloud-sync.service"
install -m 0644 "$repo_root/linux/client/packaging/candy-cloud-sync.timer" \
	"$stage/systemd/candy-cloud-sync.timer"
install -m 0644 "$repo_root/linux/server/packaging/candy.tmpfiles" "$stage/systemd/candy.tmpfiles"
install -m 0755 "$repo_root/linux/server/packaging/install-candy-server.sh" \
	"$stage/install/install-candy-server.sh"
install -m 0755 "$repo_root/linux/server/packaging/upgrade-candy-server.sh" \
	"$stage/install/upgrade-candy-server.sh"
install -m 0644 "$repo_root/linux/server/README.md" "$stage/README.md"
install -m 0644 "$repo_root/VERSION" "$stage/VERSION"

bundle=$dist_root/candy-server-runtime-$artifact_arch.tar.gz
COPYFILE_DISABLE=1 tar --no-xattrs -C "$stage" -czf "$bundle" .

# Publish the product command as the architecture-qualified Runtime artifact.
# Core remains a separate native artifact managed through the signed channel.
install -m 0755 "$product_launcher" "$dist_root/candy-server-$artifact_arch"

edge_stage=$dist_root/client/$artifact_arch
rm -rf "$edge_stage"
mkdir -p "$edge_stage/usr/local/bin" "$edge_stage/usr/local/libexec" "$edge_stage/etc/candy" "$edge_stage/systemd"
install -m 0755 "$edge_product" "$edge_stage/usr/local/bin/candy"
install -m 0755 "$edge_launcher" "$edge_stage/usr/local/libexec/candy-client"
install -m 0755 "$sdwan_runtime" "$edge_stage/usr/local/libexec/candy-sdwan-runtime"
install -m 0755 "$sdwan_agent" "$edge_stage/usr/local/libexec/candy-sdwan-agent"
install -m 0755 "$netd_binary" "$edge_stage/usr/local/libexec/candy-netd"
install -m 0755 "$enroll_binary" "$edge_stage/usr/local/libexec/candy-cloud-enroll"
install -m 0755 "$sync_binary" "$edge_stage/usr/local/libexec/candy-cloud-sync"
install -m 0644 "$repo_root/linux/client/packaging/client.example.toml" "$edge_stage/etc/candy/client.toml.example"
install -m 0644 "$repo_root/linux/client/packaging/candy-client.service" "$edge_stage/systemd/candy-client.service"
install -m 0644 "$repo_root/linux/client/packaging/candy-netd.service" "$edge_stage/systemd/candy-netd.service"
install -m 0644 "$repo_root/linux/client/packaging/candy-sdwan.service" "$edge_stage/systemd/candy-sdwan.service"
install -m 0644 "$repo_root/linux/client/packaging/candy-cloud-sync.service" "$edge_stage/systemd/candy-cloud-sync.service"
install -m 0644 "$repo_root/linux/client/packaging/candy-cloud-sync.timer" "$edge_stage/systemd/candy-cloud-sync.timer"
install -m 0644 "$repo_root/linux/client/packaging/sdwan-agent.env.example" "$edge_stage/etc/candy/sdwan-agent.env.example"
install -m 0644 "$repo_root/linux/client/packaging/candy.sysusers" "$edge_stage/systemd/candy.sysusers"
install -m 0644 "$repo_root/linux/client/packaging/candy.tmpfiles" "$edge_stage/systemd/candy.tmpfiles"
install -m 0644 "$repo_root/VERSION" "$edge_stage/VERSION"

printf '%s\n' "Linux server Runtime package staged in $stage"
printf '%s\n' "Linux server Runtime bundle staged in $bundle"
printf '%s\n' "Linux Edge Runtime package staged in $edge_stage"
printf '%s\n' "Core binary intentionally excluded; activate it under /opt/candy/cores/current"
