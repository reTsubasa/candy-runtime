#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
installer=${CANDY_INSTALLER_PATH:-$script_dir/install-candy-server.sh}

if [ ! -f "$installer" ]; then
	printf '%s\n' "upgrade-candy-server: installer not found: $installer" >&2
	exit 1
fi

case "${1:-}" in
	--artifact-file|--artifact-url|--version) ;;
	*)
		printf '%s\n' \
			"usage: upgrade-candy-server.sh (--artifact-file PATH | --artifact-url URL | --version VERSION) [installer options]" >&2
		exit 2
		;;
esac

exec sh "$installer" "$@"
