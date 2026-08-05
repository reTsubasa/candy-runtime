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
core_manager=$repo_root/linux/server/apps/candy-server/candy-core-manager
health_check=$repo_root/linux/server/apps/candy-server/candy-server-health-check
stage=$dist_root/server/$artifact_arch
[ -f "$launcher" ] || {
	printf '%s\n' "Linux server Runtime launcher is missing: $launcher" >&2
	exit 1
}
sh -n "$launcher"
sh -n "$core_manager"
sh -n "$health_check"

mkdir -p "$stage/usr/local/bin" "$stage/usr/local/libexec" "$stage/etc/candy" "$stage/systemd" "$stage/install"
install -m 0755 "$launcher" "$stage/usr/local/bin/serverd-linux"
install -m 0755 "$core_manager" "$stage/usr/local/bin/candy-core-manager"
install -m 0755 "$health_check" "$stage/usr/local/libexec/candy-server-health-check"
install -m 0644 "$repo_root/linux/server/docker/server.example.toml" \
	"$stage/etc/candy/server.toml.example"
install -m 0644 "$repo_root/linux/server/packaging/candy-server.service" \
	"$stage/systemd/candy-server.service"
install -m 0755 "$repo_root/linux/server/packaging/install-candy-server.sh" \
	"$stage/install/install-candy-server.sh"
install -m 0755 "$repo_root/linux/server/packaging/upgrade-candy-server.sh" \
	"$stage/install/upgrade-candy-server.sh"
install -m 0644 "$repo_root/linux/server/README.md" "$stage/README.md"
install -m 0644 "$repo_root/VERSION" "$stage/VERSION"

# Keep the established release artifact name while its contents become the
# architecture-neutral Runtime launcher. Core remains a separate native artifact.
install -m 0755 "$launcher" "$dist_root/serverd-linux-$artifact_arch"

printf '%s\n' "Linux server Runtime package staged in $stage"
printf '%s\n' "Core binary intentionally excluded; activate it under /opt/candy/cores/current"
