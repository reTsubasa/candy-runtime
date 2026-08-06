#!/bin/sh
set -eu

rulesets=${1:-}
min_cidr_total=${CANDY_MIN_CN_IP_ENTRIES:-5000}
min_cidr_v4=${CANDY_MIN_CN_IPV4_ENTRIES:-4000}
min_cidr_v6=${CANDY_MIN_CN_IPV6_ENTRIES:-1500}
min_domains=${CANDY_MIN_GFWLIST_ENTRIES:-4000}

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

validate_threshold() {
	case "$2" in
		''|*[!0-9]*|0) fail "$1 must be a positive integer" ;;
	esac
}

[ -n "$rulesets" ] || fail "usage: $0 RULESET_DIRECTORY"
[ -d "$rulesets" ] || fail "ruleset directory is missing: $rulesets"
for value in \
	"cn-ip total:$min_cidr_total" \
	"cn-ip IPv4:$min_cidr_v4" \
	"cn-ip IPv6:$min_cidr_v6" \
	"gfwlist:$min_domains"; do
	validate_threshold "${value%%:*}" "${value#*:}"
done

cidr_file=$rulesets/cn-ip.cidr
domain_file=$rulesets/gfwlist.domains
checksum_file=$rulesets/SHA256SUMS
provenance_file=$rulesets/PROVENANCE.md
for path in "$cidr_file" "$domain_file" "$checksum_file" "$provenance_file"; do
	[ -s "$path" ] || fail "required ruleset asset is missing or empty: $path"
	[ ! -L "$path" ] || fail "ruleset asset must not be a symbolic link: $path"
done

tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-rulesets.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//; /^[[:space:]]*$/d' "$cidr_file" > "$tmp/cidrs"
LC_ALL=C sort -u "$tmp/cidrs" > "$tmp/cidrs.unique"

awk '
function invalid(message) {
	printf "cn-ip.cidr:%d: %s: %s\n", NR, message, $0 > "/dev/stderr"
	exit 1
}
{
	slash = index($0, "/")
	if (!slash || index(substr($0, slash + 1), "/")) invalid("invalid CIDR separator")
	address = substr($0, 1, slash - 1)
	prefix = substr($0, slash + 1)
	if (prefix !~ /^[0-9]+$/) invalid("invalid prefix")
	if (index(address, ":")) {
		if (address !~ /^[0-9A-Fa-f:]+$/ || prefix + 0 > 128 || gsub(/:/, ":", address) < 2) invalid("invalid IPv6 CIDR")
		v6++
		next
	}
	if (address !~ /^[0-9.]+$/ || prefix + 0 > 32) invalid("invalid IPv4 CIDR")
	count = split(address, octets, ".")
	if (count != 4) invalid("invalid IPv4 address")
	for (i = 1; i <= 4; i++) {
		if (octets[i] !~ /^[0-9]+$/ || octets[i] + 0 > 255) invalid("invalid IPv4 octet")
	}
	v4++
}
END {
	if (!v4 || !v6) exit 1
	printf "%d %d\n", v4, v6
}
' "$tmp/cidrs.unique" > "$tmp/cidr-counts" || fail "China IP bootstrap contains malformed CIDRs"

read -r cidr_v4 cidr_v6 < "$tmp/cidr-counts"
cidr_total=$((cidr_v4 + cidr_v6))
[ "$cidr_total" -ge "$min_cidr_total" ] || fail "China IP bootstrap has only $cidr_total unique entries"
[ "$cidr_v4" -ge "$min_cidr_v4" ] || fail "China IP bootstrap has only $cidr_v4 unique IPv4 entries"
[ "$cidr_v6" -ge "$min_cidr_v6" ] || fail "China IP bootstrap has only $cidr_v6 unique IPv6 entries"

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
[ "$domain_count" -ge "$min_domains" ] || fail "GFWList bootstrap has only $domain_count unique entries"

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
