#!/bin/sh
set -eu
runtime=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 "$runtime/scripts/shared_pool_gate.py" "$@"
