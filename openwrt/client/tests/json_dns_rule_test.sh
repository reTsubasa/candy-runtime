#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../packages/candy-client" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

# Execute each production serializer, including quotes in historical logs.
for source in candy.init candy-core-manager candy-update-manager; do
  eval "$(sed -n '/^json_string()/,/^}/p' "$root/$source")"
  sample=$(printf 'event="node_connect_failed" path=C:\\core\tline\r\ncontrol:\001\b\f\n\nX')
  sample=${sample%X}
  printf '%s' "$sample" > "$tmp/input"
  json_string "$sample" > "$tmp/encoded"
  jq -e --rawfile expected "$tmp/input" '. == $expected' "$tmp/encoded" >/dev/null
done

eval "$(sed -n '/^refresh_node_status()/,/^}/p' "$root/candy.init")"
NODE_STATUS_FILE=$tmp/status.json
CANDY_VERSION=0.4.0
CANDY_RELEASE=154
atomic_temp_path() { printf '%s\n' "$1.next"; }
atomic_commit_file() { mv "$1" "$2"; }
config_foreach() { :; }
write_runtime_status() { printf '%s' '"runtime":{}'; }
write_dns_status() { printf '%s' '"dns":{}'; }
write_geo_status() { printf '%s' '"geo":{}'; }
write_gfwlist_status() { printf '%s' '"gfwlist":{}'; }
write_diagnostics_status() { printf '"diagnostics":'; json_string 'event="node_connect_failed"'; }
jsonfilter() { jq -e . "$2"; }
log_error() { printf '%s\n' "$*" >> "$tmp/errors"; }
refresh_node_status
jq -e '.release == "154" and .diagnostics == "event=\"node_connect_failed\""' "$NODE_STATUS_FILE" >/dev/null
cp "$NODE_STATUS_FILE" "$tmp/previous.json"
write_diagnostics_status() { printf '%s' '"diagnostics":"invalid"quote"'; }
if refresh_node_status; then echo 'Malformed status was published' >&2; exit 1; fi
cmp "$NODE_STATUS_FILE" "$tmp/previous.json"
grep -q 'code=status_json_invalid' "$tmp/errors"

eval "$(sed -n '/^write_dns_rule()/,/^}/p; /^dns_rule_error()/,/^}/p' "$root/candy.init")"
log_warn() { printf '%s\n' "$*" >> "$tmp/warnings"; }
log_error() { printf '%s\n' "$*" >> "$tmp/errors"; }
config_get() {
  local value
  [ "$2" = rule0 ] || [ "$2" = node0 ] || { echo 'DNS section argument missing' >&2; exit 1; }
  case "$2:$3" in
    rule0:type) value=$TEST_KIND ;;
    rule0:domain) value=$TEST_DOMAIN ;;
    rule0:target) value=$TEST_TARGET ;;
    node0:name) value='Node "zero"' ;;
    *) exit 1 ;;
  esac
  eval "$1=\$value"
}
uci() { [ "$*" = '-q get candy.node0' ] && printf '%s\n' node; }
reset() { FIRST_DNS_RULE=1; CANDY_CONFIG_RULE_ERROR=0; TEST_KIND=domain-suffix; TEST_DOMAIN=example.com; TEST_TARGET=direct; }

reset
write_dns_rule rule0 > "$tmp/rule"
jq -e '.type == "domain-suffix" and .domain == "example.com" and .target == "direct"' "$tmp/rule" >/dev/null
reset; TEST_KIND=domain; TEST_TARGET=node0
write_dns_rule rule0 > "$tmp/rule"
jq -e '.type == "domain" and .target.node == "Node \"zero\""' "$tmp/rule" >/dev/null
reset; TEST_DOMAIN=
write_dns_rule rule0 > "$tmp/rule"
[ ! -s "$tmp/rule" ] && [ "$CANDY_CONFIG_RULE_ERROR" = 0 ] && [ "$FIRST_DNS_RULE" = 1 ]
grep -q 'code=dns_rule_draft_skipped.*section=rule0' "$tmp/warnings"
for invalid in domain type target missing; do
  reset
  case "$invalid" in
    domain) TEST_DOMAIN='bad/domain' ;;
    type) TEST_KIND=invalid ;;
    target) TEST_TARGET=absent ;;
    missing) TEST_DOMAIN=; TEST_TARGET=node0 ;;
  esac
  write_dns_rule rule0 > "$tmp/rule" 2> "$tmp/detail"
  [ "$CANDY_CONFIG_RULE_ERROR" = 1 ] && [ ! -s "$tmp/rule" ]
  grep -q 'code=dns_rule_.* module=config section=rule0 detail=' "$tmp/detail"
done
printf '%s\n' 'Runtime JSON escaping and DNS rule generation regressions passed'
(
  eval "$(sed -n '/^provider_file_mtime()/,/^}/p; /^provider_update_due()/,/^}/p' "$root/candy.init")"
  printf '%s\n' rules > "$tmp/provider"
  stat() { return 127; }
  lua() { cat >/dev/null; date +%s; }
  if provider_update_due "$tmp/provider" 24; then echo 'Fresh provider is incorrectly due without stat' >&2; exit 1; fi
  lua() { cat >/dev/null; echo 1; }
  provider_update_due "$tmp/provider" 24
  lua() { return 1; }
  if provider_update_due "$tmp/provider" 24; then echo 'Missing timestamp triggered a repeated download' >&2; exit 1; fi
  provider_update_due "$tmp/missing-provider" 24
)
printf '%s\n' 'Provider scheduling without stat regressions passed'
if [ "${CANDY_JSON_BUSYBOX_TEST:-0}" != 1 ] && command -v busybox >/dev/null 2>&1; then
  mkdir "$tmp/busybox-bin"
  ln -s "$(command -v busybox)" "$tmp/busybox-bin/awk"
  CANDY_JSON_BUSYBOX_TEST=1 PATH="$tmp/busybox-bin:$PATH" sh "$0"
fi
