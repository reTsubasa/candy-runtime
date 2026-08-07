#!/bin/sh
set -eu

rulesets=${1:-}

fail() {
	printf '%s\n' "verify_bootstrap_rulesets: $*" >&2
	exit 1
}

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print tolower($1) }'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{ print tolower($1) }'
	else
		fail "sha256sum or shasum is required"
	fi
}

[ -n "$rulesets" ] || fail "usage: $0 RULESET_DIRECTORY"
[ -d "$rulesets" ] || fail "ruleset directory is missing: $rulesets"
command -v jq >/dev/null 2>&1 || fail "jq is required to validate ruleset metadata"
command -v python3 >/dev/null 2>&1 || fail "python3 is required to validate CIDR semantics"

cidr_file=$rulesets/cn-ip.cidr
domain_file=$rulesets/gfwlist.domains
checksum_file=$rulesets/SHA256SUMS
provenance_file=$rulesets/PROVENANCE.md
manifest_file=$rulesets/manifest.json
for path in "$cidr_file" "$domain_file" "$checksum_file" "$provenance_file" "$manifest_file"; do
	[ -s "$path" ] || fail "required ruleset asset is missing or empty: $path"
	[ ! -L "$path" ] || fail "ruleset asset must not be a symbolic link: $path"
done

tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-rulesets.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//; /^[[:space:]]*$/d' "$cidr_file" > "$tmp/cidrs"
LC_ALL=C sort -u "$tmp/cidrs" > "$tmp/cidrs.unique"

python3 - "$tmp/cidrs.unique" <<'PY' > "$tmp/cidr-counts" || fail "China IP bootstrap contains malformed CIDRs"
import ipaddress
import sys

path = sys.argv[1]
counts = {4: 0, 6: 0}
seen = set()
with open(path, encoding="ascii") as source:
    for line_number, raw in enumerate(source, 1):
        value = raw.rstrip("\n")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise SystemExit(f"cn-ip.cidr:{line_number}: {error}: {value}")
        if network in seen:
            raise SystemExit(f"cn-ip.cidr:{line_number}: duplicate semantic network: {value}")
        seen.add(network)
        counts[network.version] += 1
if not counts[4] or not counts[6]:
    raise SystemExit("cn-ip.cidr must contain both IPv4 and IPv6 networks")
print(counts[4], counts[6])
PY

read -r cidr_v4 cidr_v6 < "$tmp/cidr-counts"
cidr_total=$((cidr_v4 + cidr_v6))

sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//; /^[[:space:]]*$/d' "$domain_file" > "$tmp/domains"
LC_ALL=C sort -u "$tmp/domains" > "$tmp/domains.unique"
awk '
function invalid(message) {
	printf "gfwlist.domains:%d: %s: %s\n", NR, message, $0 > "/dev/stderr"
	exit 1
}
{
	if (length($0) > 253 || $0 !~ /^([a-z0-9][a-z0-9-]*\.)*[a-z0-9][a-z0-9-]*$/) invalid("invalid normalized domain")
	labels = split($0, label, ".")
	for (i = 1; i <= labels; i++) {
		if (length(label[i]) > 63 || label[i] ~ /-$/) invalid("invalid DNS label")
	}
}
' "$tmp/domains.unique" || fail "GFWList bootstrap contains malformed domains"
domain_count=$(wc -l < "$tmp/domains.unique" | tr -d ' ')

jq -e '
  .schema_version == 1 and
  (.generated_at | type == "string" and length > 0) and
  (.providers.cn_ip.source_url | startswith("https://")) and
  (.providers.gfwlist.source_url | startswith("https://"))
' "$manifest_file" >/dev/null || fail "ruleset manifest schema is invalid"
manifest_cidr_total=$(jq -er '.providers.cn_ip.entries.total' "$manifest_file")
manifest_cidr_v4=$(jq -er '.providers.cn_ip.entries.ipv4' "$manifest_file")
manifest_cidr_v6=$(jq -er '.providers.cn_ip.entries.ipv6' "$manifest_file")
manifest_domain_count=$(jq -er '.providers.gfwlist.entries.total' "$manifest_file")
[ "$cidr_total" -eq "$manifest_cidr_total" ] || fail "China IP total differs from the reviewed manifest"
[ "$cidr_v4" -eq "$manifest_cidr_v4" ] || fail "China IP IPv4 count differs from the reviewed manifest"
[ "$cidr_v6" -eq "$manifest_cidr_v6" ] || fail "China IP IPv6 count differs from the reviewed manifest"
[ "$domain_count" -eq "$manifest_domain_count" ] || fail "GFWList count differs from the reviewed manifest"

manifest_cidr_sha=$(jq -er '.providers.cn_ip.installed_sha256' "$manifest_file")
manifest_domain_sha=$(jq -er '.providers.gfwlist.installed_sha256' "$manifest_file")
[ "$(sha256_file "$cidr_file")" = "$manifest_cidr_sha" ] || fail "China IP file differs from the reviewed manifest digest"
[ "$(sha256_file "$domain_file")" = "$manifest_domain_sha" ] || fail "GFWList file differs from the reviewed manifest digest"

expected_entries=0
while read -r expected name extra; do
	[ -n "$expected" ] || continue
	case "$expected" in \#*) continue ;; esac
	[ -z "${extra:-}" ] || fail "invalid checksum line for $name"
	case "$name" in cn-ip.cidr|gfwlist.domains) ;; *) fail "unexpected checksum target: $name" ;; esac
	printf '%s' "$expected" | grep -Eq '^[0-9a-fA-F]{64}$' || fail "invalid SHA-256 for $name"
	actual=$(sha256_file "$rulesets/$name")
	[ "$actual" = "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" ] || fail "$name does not match its pinned SHA-256"
	expected_entries=$((expected_entries + 1))
done < "$checksum_file"
[ "$expected_entries" -eq 2 ] || fail "SHA256SUMS must cover exactly the two runtime provider files"

printf '%s\n' "Verified rulesets: cn-ip=$cidr_total (IPv4=$cidr_v4 IPv6=$cidr_v6), gfwlist=$domain_count"
