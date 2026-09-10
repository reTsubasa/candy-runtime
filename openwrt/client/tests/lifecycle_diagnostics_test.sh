#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
init=$root/packages/candy-client/candy.init
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
eval "$(sed -n '/^stop_supervised_child()/,/^}/p; /^sdwan_owned_core_pids()/,/^}/p; /^clear_orphan_sdwan_cores()/,/^}/p; /^wait_for_sdwan_pid_query()/,/^}/p' "$init")"
log_event() { printf '%s\n' "$*" >> "$tmp/events"; }
CANDY_PROC_ROOT=$tmp/proc
CANDY_CORE_BIN=/usr/lib/candy/cores/current/candy-core
CANDY_SDWAN_ACTIVATIONS_DIR=/etc/candy/sdwan/activations
CANDY_SDWAN_STOP_WAIT_SECONDS=0
mkdir -p "$tmp/proc/100" "$tmp/proc/101" "$tmp/proc/102"
printf '%s\000' "$CANDY_CORE_BIN" client sdwan run --config "$CANDY_SDWAN_ACTIVATIONS_DIR/long-activation/core.toml" > "$tmp/proc/100/cmdline"
printf '%s\000' "$CANDY_CORE_BIN" server --config /etc/unrelated.toml > "$tmp/proc/101/cmdline"
printf '%s\000' "$CANDY_CORE_BIN" client sdwan verify --config "$CANDY_SDWAN_ACTIVATIONS_DIR/long-activation/core.toml" > "$tmp/proc/102/cmdline"
test "$(sdwan_owned_core_pids)" = 100
printf 'PPid:\t42\n' > "$tmp/proc/100/status"
if clear_orphan_sdwan_cores; then echo 'accepted a live Core owner' >&2; exit 1; fi
grep -q 'error_code=live_core_owner' "$tmp/events"
printf 'PPid:\t1\n' > "$tmp/proc/100/status"
(
    kill() { test "$1:$2" = '-TERM:100'; rm "$tmp/proc/100/cmdline"; }
    clear_orphan_sdwan_cores
)

# Real signals: the supervisor must outlive a child that drains after TERM.
sh -c 'trap "sleep 1; exit 0" TERM; echo ready; while :; do sleep 1; done' > "$tmp/ready" &
child=$!
while [ ! -s "$tmp/ready" ]; do sleep 1; done
stop_supervised_child "$child" 5
if kill -0 "$child" 2>/dev/null; then echo 'child survived supervisor stop' >&2; exit 1; fi

sh -c 'trap "" TERM; echo ready; exec sleep 30' > "$tmp/ignored" &
child=$!
while [ ! -s "$tmp/ignored" ]; do sleep 1; done
stop_supervised_child "$child" 1
if kill -0 "$child" 2>/dev/null; then echo 'TERM-ignoring child survived stop deadline' >&2; exit 1; fi
grep -q 'error_code=child_term_timeout' "$tmp/events"
echo 'OpenWrt lifecycle diagnostics tests passed'
