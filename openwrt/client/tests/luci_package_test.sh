#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../packages" && pwd)
app_dir=$repo_root/luci-app-candy

fail() {
	printf '%s\n' "openwrt_candy_luci_package_test: $*" >&2
	exit 1
}

assert_file() {
	test -f "$repo_root/$1" || fail "missing $1"
}

assert_contains() {
	file=$1
	pattern=$2
	grep -Eq "$pattern" "$repo_root/$file" || fail "$file missing pattern: $pattern"
}

assert_not_contains() {
	file=$1
	pattern=$2
	if grep -Eq "$pattern" "$repo_root/$file"; then
		fail "$file contains forbidden pattern: $pattern"
	fi
}

assert_count() {
	file=$1
	pattern=$2
	expected=$3
	actual=$(grep -Ec "$pattern" "$repo_root/$file" || true)
	[ "$actual" -eq "$expected" ] || fail "$file pattern count $pattern expected $expected got $actual"
}

assert_before() {
	file=$1
	first=$2
	second=$3
	first_line=$(grep -nE "$first" "$repo_root/$file" | head -1 | cut -d: -f1 || true)
	second_line=$(grep -nE "$second" "$repo_root/$file" | head -1 | cut -d: -f1 || true)
	[ -n "$first_line" ] || fail "$file missing first pattern for order check: $first"
	[ -n "$second_line" ] || fail "$file missing second pattern for order check: $second"
	[ "$first_line" -lt "$second_line" ] || fail "$file expected $first before $second"
}

makefile=luci-app-candy/Makefile
client_makefile=candy-client/Makefile
config=candy-client/candy.config
init=candy-client/candy.init
po=luci-app-candy/po/zh-cn/candy.zh-cn.po
po2lmo_c=luci-app-candy/tools/po2lmo/src/po2lmo.c
po2lmo_lmo=luci-app-candy/tools/po2lmo/src/template_lmo.c
po2lmo_h=luci-app-candy/tools/po2lmo/src/template_lmo.h
controller=luci-app-candy/root/usr/lib/lua/luci/controller/candy.lua
process_helper=luci-app-candy/root/usr/lib/lua/luci/candy/process.lua
client=luci-app-candy/root/usr/lib/lua/luci/model/cbi/candy/client.lua
nodes=luci-app-candy/root/usr/lib/lua/luci/model/cbi/candy/nodes.lua
dns=luci-app-candy/root/usr/lib/lua/luci/model/cbi/candy/dns.lua
advanced=luci-app-candy/root/usr/lib/lua/luci/model/cbi/candy/advanced.lua
rules=luci-app-candy/root/usr/lib/lua/luci/view/candy/rules.htm
status=luci-app-candy/root/usr/lib/lua/luci/view/candy/status.htm
core_view=luci-app-candy/root/usr/lib/lua/luci/view/candy/core.htm
update_view=luci-app-candy/root/usr/lib/lua/luci/view/candy/update.htm
diagnostics=luci-app-candy/root/usr/lib/lua/luci/view/candy/diagnostics.htm
dns_tunnel_status=luci-app-candy/root/usr/lib/lua/luci/view/candy/dns_tunnel_status.htm
logs=luci-app-candy/root/usr/lib/lua/luci/view/candy/log.htm

assert_file "candy-client/rulesets/cn-ip.cidr"
assert_file "candy-client/rulesets/gfwlist.domains"
assert_file "candy-client/rulesets/PROVENANCE.md"
assert_file "candy-client/rulesets/SHA256SUMS"
"$repo_root/../../../packaging/openwrt/build/verify_bootstrap_rulesets.sh" "$repo_root/candy-client/rulesets" >/dev/null ||
	fail "bootstrap ruleset validation failed"
assert_contains "$client_makefile" 'rulesets/PROVENANCE\.md'
assert_contains "$client_makefile" 'rulesets/SHA256SUMS'
assert_contains "$config" "geo_update_url 'https://gaoyifan\.github\.io/china-operator-ip/china46\.txt'"
assert_contains "$config" "geo_auto_update '1'"
assert_contains "$config" "gfwlist_auto_update '1'"
assert_contains "$config" "block_quic '0'"
assert_contains "$config" "^config node 'hk_1'$"
assert_contains "$config" "^[[:space:]]*list node 'hk_1'$"
assert_not_contains "$config" "^config[[:space:]][^[:space:]]+[[:space:]]+'[^']*-[^']*'$"
assert_contains "$process_helper" 'exec_with_timeout\(argv, options\.timeout\)'
assert_contains "$controller" 'process\.capture\(\{ CORE_MANAGER, "status" \}, \{ timeout = 3 \}\)'

lua_syntax_file=$(mktemp)
trap 'rm -f "$lua_syntax_file"' EXIT HUP INT TERM
node - "$repo_root" "$lua_syntax_file" "$status" "$diagnostics" "$core_view" "$update_view" <<'EOF'
const fs = require("node:fs");

const root = process.argv[2];
const outputPath = process.argv[3];
let lua = "";

for (const templatePath of process.argv.slice(4)) {
	const source = fs.readFileSync(root + "/" + templatePath, "utf8");
	lua += "\n-- " + templatePath + "\n";
	for (const match of source.matchAll(/<%([=+:#]?)([\s\S]*?)%>/g)) {
		const [, marker, body] = match;
		if (marker === "") lua += body + "\n";
		if (marker === "=") lua += "do local __candy_template_value = (" + body + ") end\n";
	}
}

fs.writeFileSync(outputPath, lua);
EOF
luac -p "$lua_syntax_file" || fail "LuCI templates contain invalid Lua template code"

node - "$repo_root" "$status" <<'EOF'
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const root = process.argv[2];
const statusPath = process.argv[3];
const source = fs.readFileSync(root + "/" + statusPath, "utf8");
assert.ok(!source.includes("Passive transport status"), "overview must not render passive transport status");
assert.ok(!source.includes("candy-status-passive-"), "overview must not own passive field ids");
assert.ok(!source.includes("candyOverviewRenderPassive"), "overview must not own passive refresh rendering");
assert.ok(source.includes("<%:Candy version%>"), "overview must show the OpenWrt package version");
assert.ok(source.includes("<%:Core version%>"), "overview must show the independent Core version");
assert.ok(source.includes("candy-status-client-version"), "overview must expose the product version refresh target");
assert.ok(source.includes("candy-status-core-version"), "overview must expose the Core version refresh target");
assert.ok(source.includes("data.release"), "overview must include the OpenWrt package revision");
assert.ok(source.includes("manifest.core.features"), "feature cards must come from the active Core manifest");
assert.ok(source.includes("definition.status_key || definition.id"), "feature runtime evidence must use the Core status mapping");
assert.ok(source.includes("candy-overview-section"), "overview sections must have explicit vertical spacing");
for (const featureDetail of ["definition.description", "definition.activation", "candyOverviewFeatureEvidence", "candy-feature-evidence"]) {
	assert.ok(!source.includes(featureDetail), "overview feature cards must omit detail: " + featureDetail);
}
assert.ok(!source.includes("candyOverviewFeatureNames"), "OpenWrt must not maintain a protocol feature catalog");
assert.ok(!source.includes("effective UDP multiplier is 1"), "OpenWrt must not embed Core activation details");
assert.ok(!source.includes("LuCI version"), "overview must not duplicate package versions");
assert.ok(source.includes("Server version"), "overview must show the negotiated server software version");
assert.ok(!source.includes("Runtime mode"), "overview must hide internal runtime modes");
assert.ok(!source.includes("UDP packet multiplier"), "overview must hide negotiated packet multipliers");
assert.ok(!source.includes("Candy 0.3.4 records BBR fallback evidence"), "overview must omit the BBR promotional description");
assert.ok(source.includes('id="candy-sdwan-status"'), "overview must expose the conditional SD-WAN section");
const match = source.match(/<script type="text\/javascript">([\s\S]*?)<\/script>/);
assert.ok(match, "status page JavaScript was not found");
const script = match[1].replace(/<%=([\s\S]*?)%>/g, (_, expression) => {
	if (expression.includes("build_url")) return "test";
	return JSON.stringify("test");
});

class Element {
	constructor() {
		this.children = [];
		this._textContent = "";
		this.className = "";
		this.style = {};
		this.attributes = {};
	}
	set textContent(value) {
		this._textContent = value;
		this.children = [];
	}
	get textContent() {
		return this._textContent;
	}
	appendChild(child) {
		this.children.push(child);
		return child;
	}
	get firstChild() { return this.children[0] || null; }
	removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
	setAttribute(name, value) { this.attributes[name] = String(value); }
}

const elements = new Map();
const requests = [];
const intervals = [];
const timers = [];
class FakeXMLHttpRequest {
	constructor() {
		this.readyState = 0;
		this.status = 0;
		this.responseText = "";
		this.aborted = false;
		requests.push(this);
	}
	open() {}
	send() {}
	abort() {
		this.aborted = true;
	}
	respond(status, data) {
		this.status = status;
		this.responseText = JSON.stringify(data);
		this.readyState = 4;
		this.onreadystatechange();
	}
}

const context = {
	XMLHttpRequest: FakeXMLHttpRequest,
	Date: { now: () => 1 },
	document: {
		getElementById(id) {
			if (!elements.has(id)) elements.set(id, new Element());
			return elements.get(id);
		},
		createElement: () => new Element(),
		createTextNode: text => ({ textContent: text })
	},
	isFinite,
	setInterval(callback, delay) {
		intervals.push({ callback, delay });
		return intervals.length;
	},
	setTimeout(callback, delay) {
		const timer = { callback, delay };
		timers.push(timer);
		return timer;
	},
	clearTimeout(timer) {
		const index = timers.indexOf(timer);
		if (index !== -1) timers.splice(index, 1);
	}
};
vm.runInNewContext(script, context, { filename: statusPath });

assert.equal(context.candyOverviewClientVersion({ version: "0.4.0", release: "1" }), "0.4.0-r1");
assert.equal(context.candyOverviewClientVersion({ version: "0.4.0-r1", release: "1" }), "0.4.0-r1");
assert.equal(context.candyOverviewClientVersion({ version: "0.4.0" }), "0.4.0");

assert.equal(requests.length, 1, "initial refresh must issue one request");
const requestA = requests[0];
context.refreshCandyOverviewStatus();
assert.equal(requests.length, 2, "manual refresh must issue request B");
const requestB = requests[1];
assert.equal(requestA.aborted, true, "request B must abort request A");

const response = (version, status, updated, nodes = []) => ({
	version,
	core: { current_version: "core-" + version, current_manifest: { core: { features: [] } } },
	service: { status, enabled: status !== "stopped" },
	runtime: {
		mode: "stable",
		performance: updated === undefined ? {} : { passive: { updated_unix_ms: updated } }
	},
	nodes
});
requestB.respond(200, response("new", "running", 20, [{
		state: "ready", name: "node-b", server: "203.0.113.1:8443", server_version: "0.3.1", groups: ["Video", "Proxy"],
	url_test: { status: "ok", latency_ms: 42 }, active_tcp_flows: 3, active_udp_flows: 2,
		passive: { local: { smoothed_rtt_micros: 12345, goodput_bps: 1000 } }, reconnects: 1
}]));
requestA.respond(200, response("old", "stopped", 10));
assert.equal(elements.get("candy-status-client-version").textContent, "new",
	"late request A must not overwrite newer request B");
assert.equal(elements.get("candy-status-core-version").textContent, "core-new");
const nodeCells = elements.get("candy-status-nodes").children[0].children;
assert.equal(nodeCells.length, 7, "node status must include the server version in its operational summary");
assert.equal(nodeCells[3].textContent, "0.3.1");
assert.equal(nodeCells[4].textContent, "Video, Proxy");
assert.equal(nodeCells[5].textContent, "12.35 ms");
assert.equal(nodeCells[6].textContent, "42 ms");

context.refreshCandyOverviewStatus();
requests[2].respond(200, response("stopped", "stopped"));
assert.equal(elements.get("candy-status-client-version").textContent, "stopped",
	"a current response without passive status must still update ordinary fields");
assert.equal(elements.get("candy-sdwan-status").style.display, "none",
	"SD-WAN status must stay hidden without a valid running status");
assert.equal(elements.get("candy-status-service").className, "label");
assert.equal(elements.get("candy-status-nodes").children[0].children.length, 1,
	"a current response without passive status must still replace nodes");

context.candyOverviewRenderSdwan({
	enabled: true,
	phase: "ready",
	site: "edge-1",
	active_hub: "hub-1",
	counters: {},
	last_failover: {}
});
assert.equal(elements.get("candy-sdwan-status").style.display, "",
	"SD-WAN status must appear for a valid running status");
context.candyOverviewRenderSdwan({ enabled: true, phase: "unavailable" });
assert.equal(elements.get("candy-sdwan-status").style.display, "none",
	"SD-WAN status must hide when runtime status becomes unavailable");

context.candyOverviewRenderFeatures({ core: { features: [{
	id: "future_feature", status_key: "future_status", name: "Future feature",
	description: "Owned by Core", activation: "Core-defined condition"
}] } }, [{ passive: { features: { future_status: { supported: true, authorized: true, active: false, evidence: 7 } } } }]);
assert.equal(elements.get("candy-protocol-features").style.display, "");
assert.equal(elements.get("candy-status-features").children.length, 1);
assert.equal(elements.get("candy-status-features").children[0].children[0].children[0].textContent, "Future feature");
assert.equal(elements.get("candy-status-features").children[0].className, "candy-feature-card inactive");
assert.equal(elements.get("candy-status-features").children[0].children.length, 1,
	"overview feature cards must only render the feature header and status");

context.refreshCandyOverviewStatus();
requests[3].respond(200, response("restarted", "running", 5));
assert.equal(elements.get("candy-status-client-version").textContent, "restarted");

context.refreshCandyOverviewStatus();
requests[4].respond(200, response("service-newer", "starting", 4));
assert.equal(elements.get("candy-status-client-version").textContent, "service-newer",
	"an old passive timestamp must not block ordinary field updates");
assert.equal(elements.get("candy-status-service").className, "label warning");

context.refreshCandyOverviewStatus();
requests[5].respond(200, response("invalid-passive", "running", "invalid"));
assert.equal(elements.get("candy-status-client-version").textContent, "invalid-passive");

context.refreshCandyOverviewStatus();
requests[6].respond(200, response("after-invalid", "running", 1));
assert.equal(elements.get("candy-status-client-version").textContent, "after-invalid");

context.refreshCandyOverviewStatus();
requests[7].respond(503, response("error", "stopped"));
assert.equal(elements.get("candy-status-client-version").textContent, "after-invalid",
	"an HTTP error must not clear the last applied status");
assert.equal(intervals.length, 0, "status refresh must not use an overlapping interval");
assert.equal(timers.length, 1, "only one follow-up refresh timer may be scheduled");
EOF

node - "$repo_root" "$diagnostics" <<'EOF'
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const root = process.argv[2];
const diagnosticsPath = process.argv[3];
const source = fs.readFileSync(root + "/" + diagnosticsPath, "utf8");
assert.ok(source.includes("Per-node passive diagnostics"), "diagnostics must render per-node passive status");
assert.ok(source.includes("Service resources"), "diagnostics must separate process resources");
assert.ok(source.includes("candy-diagnostics-nodes"), "diagnostics must expose the node table");
assert.ok(source.includes("candyDiagnosticsRender"), "diagnostics must own passive refresh rendering");
for (const testPoint of ["vultr-tokyo", "linode-singapore", "hetzner-ashburn", "ovh-france", "serverius-netherlands"]) {
	assert.ok(source.includes('value="' + testPoint + '"'), "diagnostics must expose test point: " + testPoint);
}
assert.ok(source.includes("100 MiB"), "congestion comparison must use a 100 MiB transfer cap");
assert.ok(source.includes("test_point="), "congestion comparison must submit the selected test point");
for (const usefulField of ["Overall performance trends", "Latency quality", "Delivery", "Flight control", "Transport state", "Path"]) {
	assert.ok(source.includes(usefulField), "diagnostics must retain useful transport field: " + usefulField);
}
for (const redundantField of ["Client UDP multiplier", "Server UDP multiplier", "Peer directional goodput", "Peer trust", "Fallback reason", "Last updated"]) {
	assert.ok(!source.includes(redundantField), "diagnostics must hide redundant or unavailable field: " + redundantField);
}
for (const oldText of ["Weak-link probe", "Run Video/CDN probe", "Video/CDN probe"]) {
	assert.ok(!source.includes(oldText), "diagnostics must remove old probe UI: " + oldText);
}

const match = source.match(/<script type="text\/javascript">([\s\S]*?)<\/script>/);
assert.ok(match, "diagnostics page JavaScript was not found");
const script = match[1].replace(/<%=([\s\S]*?)%>/g, (_, expression) => {
	if (expression.includes("build_url")) return "test";
	return JSON.stringify("test");
});

class Element {
	constructor() {
		this.children = [];
		this._textContent = "";
		this.className = "";
		this.style = {};
		this.attributes = {};
	}
	set textContent(value) {
		this._textContent = value;
		this.children = [];
	}
	get textContent() {
		return this._textContent;
	}
	appendChild(child) {
		this.children.push(child);
		return child;
	}
	get firstChild() { return this.children[0] || null; }
	removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
	setAttribute(name, value) { this.attributes[name] = String(value); }
}

const elements = new Map();
const requests = [];
const timers = [];
class FakeXMLHttpRequest {
	constructor() {
		this.readyState = 0;
		this.status = 0;
		this.responseText = "";
		this.aborted = false;
		requests.push(this);
	}
	open() {}
	send() {}
	abort() {
		this.aborted = true;
	}
	respond(status, data) {
		this.status = status;
		this.responseText = JSON.stringify(data);
		this.readyState = 4;
		this.onreadystatechange();
	}
}

const context = {
	XMLHttpRequest: FakeXMLHttpRequest,
	Date,
	document: {
		getElementById(id) {
			if (!elements.has(id)) elements.set(id, new Element());
			return elements.get(id);
		},
		createElement: () => new Element(),
		createElementNS: () => new Element(),
		createTextNode: value => { const node = new Element(); node.textContent = value; return node; }
	},
	isFinite,
	setTimeout(callback, delay) {
		const timer = { callback, delay };
		timers.push(timer);
		return timer;
	},
	clearTimeout(timer) {
		const index = timers.indexOf(timer);
		if (index !== -1) timers.splice(index, 1);
	}
};
vm.runInNewContext(script, context, { filename: diagnosticsPath });

assert.equal(requests.length, 1, "initial diagnostics refresh must issue one request");
const requestA = requests[0];
context.refreshCandyDiagnosticsStatus();
assert.equal(requests.length, 2, "manual diagnostics refresh must issue request B");
const requestB = requests[1];
assert.equal(requestA.aborted, true, "request B must abort request A");

const response = updated => ({
	process: { cpu_percent: 1.5, resident_memory_bytes: 2048 },
	nodes: ["hk", "sg"].map((name, index) => ({
		id: name,
		state: "ready",
		passive: {
			updated_unix_ms: updated + index,
			local: {
				smoothed_rtt_micros: 12345 + index, rtt_variance_micros: 2000,
				goodput_bps: 1500000, lost_packets: index,
				cwnd_bytes: 65536, bytes_in_flight: 32768, pacing_rate_bps: 3000000, bandwidth_estimate_bps: 2500000,
				congestion_mode: "probe-bw", recovery_state: "none", path_mtu: 1400, mtu_fallback_events: 1
			},
			applied_transport: { congestion: index === 0 ? "candy-bbr" : "cubic", client_udp_multiplier: 2, server_udp_multiplier: 3 },
			fallback_reason: index === 0 ? null : "candy-bbr-runtime-fallback",
			peer: { goodput_bps_tx: 1000, goodput_bps_rx: 2000, trusted: true }
		}
	}))
});

requestB.respond(200, response(1700000000000));
const requestCongestionStatus = requests[2];
assert.ok(requestCongestionStatus, "initial congestion test status request must be issued");
requestCongestionStatus.respond(200, { state: "idle" });
requestA.respond(200, response(1600000000000));
assert.equal(elements.get("candy-diagnostics-process-cpu").textContent, "1.5 %");
assert.equal(elements.get("candy-diagnostics-process-rss").textContent, "2.0 KiB");
const rows = elements.get("candy-diagnostics-nodes").children;
assert.equal(rows.length, 2, "diagnostics must render one row per node");
assert.equal(rows[0].children[0].textContent, "hk");
assert.match(rows[0].children[2].textContent, /12\.35 ms/);
assert.match(rows[0].children[2].textContent, /2\.00 ms/);
assert.equal(rows[0].children.length, 7, "diagnostics must keep the node table compact");
assert.match(rows[0].children[3].textContent, /1\.5 Mbps/);
assert.match(rows[0].children[4].textContent, /32\.0 KiB \/ 64\.0 KiB \(50 %\)/);
assert.match(rows[0].children[5].textContent, /Candy BBR/);
for (const phase of ["startup", "drain", "probe-bw", "probe-bw-refill", "probe-bw-up", "probe-bw-down", "probe-bw-cruise", "probe-rtt"]) {
	assert.equal(context.candyDiagnosticsMappedText(context.candyDiagnosticsLabels.congestionModes, phase), "test");
}
assert.equal(context.candyDiagnosticsMappedText(context.candyDiagnosticsLabels.congestionModes, "future-phase"), "future-phase",
	"unknown future congestion phases must remain visible");
assert.match(rows[1].children[5].textContent, /CUBIC/, "passive diagnostics must show the effective CUBIC controller");
assert.equal(rows[1].children[0].textContent, "sg");

context.refreshCandyDiagnosticsStatus();
requests[3].respond(200, { runtime: { performance: {} } });
assert.equal(elements.get("candy-diagnostics-nodes").children.length, 1, "missing status must replace stale rows");
assert.equal(elements.get("candy-diagnostics-process-rss").textContent, "-");
assert.equal(timers.length, 1, "only one diagnostics follow-up refresh timer may be scheduled");
EOF

for file in "$makefile" "$config" "$init" "$po" "$po2lmo_c" "$po2lmo_lmo" "$po2lmo_h" "$process_helper" "$controller" "$nodes" "$dns" "$advanced" "$rules" "$status" "$core_view" "$update_view" "$diagnostics" "$dns_tunnel_status" "$logs"; do
	assert_file "$file"
done

assert_contains "$process_helper" 'nixio\.fork\(\)'
assert_contains "$process_helper" 'nixio\.exec'
assert_contains "$process_helper" 'nixio\.pipe\(\)'
assert_contains "$process_helper" 'nixio\.open\([^,]+, output_mode, "rw-------"\)'
assert_not_contains "$process_helper" '/tmp/candy-luci-process'
assert_contains "candy-client/Makefile" '^define Package/candy-client/conffiles$'
assert_contains "candy-client/Makefile" '^/etc/config/candy$'
for file in "$controller" "$dns" "$nodes" "$advanced"; do
	assert_contains "$file" 'require "luci\.candy\.process"'
	assert_not_contains "$file" 'luci\.sys\.(call|exec)'
done
if grep -R -E 'luci\.sys\.(call|exec)' "$app_dir/root/usr/lib/lua/luci" >/dev/null 2>&1; then
	fail "LuCI contains shell-based process execution outside the argv helper"
fi

assert_contains "$makefile" '^PKG_NAME:=luci-app-candy$'
assert_contains "$makefile" '^PKG_VERSION:=0\.4\.0$'
assert_contains "$makefile" '^PKG_RELEASE:=9$'
assert_contains "$client_makefile" '^PKG_RELEASE:=9$'
assert_contains "$client_makefile" 'USERID:=candy-sdwan=789:candy-sdwan=789'
assert_not_contains "$client_makefile" 'adduser -S'
assert_contains "$client_makefile" 'id -u candy-sdwan'
assert_contains "$client_makefile" '/etc/passwd'
assert_contains "$client_makefile" '/etc/group'
client_version=$(sed -n 's/^PKG_VERSION:=//p' "$repo_root/$client_makefile")
luci_version=$(sed -n 's/^PKG_VERSION:=//p' "$repo_root/$makefile")
[ "$client_version" = "$luci_version" ] || fail "Candy client and LuCI versions differ: $client_version != $luci_version"
client_release=$(sed -n 's/^PKG_RELEASE:=//p' "$repo_root/$client_makefile")
luci_release=$(sed -n 's/^PKG_RELEASE:=//p' "$repo_root/$makefile")
[ "$client_release" = "$luci_release" ] || fail "Candy client and LuCI build releases differ: $client_release != $luci_release"
assert_contains "$makefile" 'define Package/luci-app-candy$'
assert_contains "$makefile" 'DEPENDS:=.*\+candy-client'
assert_contains "$makefile" 'DEPENDS:=.*\+luci-base'
assert_contains "$makefile" 'DEPENDS:=.*\+luci-compat'
assert_contains "$makefile" 'define Build/Prepare'
assert_contains "$makefile" '\$\(CP\) \$\(CURDIR\)/root \$\(PKG_BUILD_DIR\)'
assert_contains "$makefile" 'po/zh-cn/\*\.po'
assert_contains "$makefile" '\$\(HOSTCC\).*-o \$\(PKG_BUILD_DIR\)/po2lmo'
assert_contains "$makefile" '\$\(PKG_BUILD_DIR\)/po2lmo \$\(po\)'
assert_contains "$makefile" '/usr/lib/lua/luci/i18n'
assert_contains "$makefile" '\*\.zh-cn\.lmo'
assert_contains "$makefile" '\$\(CP\) \$\(PKG_BUILD_DIR\)/root/\* \$\(1\)/'

assert_contains "$config" "option value 'GEOIP,CN,DIRECT,no-resolve'"
assert_contains "$config" "option value 'MATCH,Proxy'"
assert_contains "$nodes" 'o\.datatype = "ipaddrport"'
assert_not_contains "$nodes" 'o\.datatype = "hostport"'
assert_contains "$nodes" 'DynamicList, "port_hopping_port"'
assert_contains "$nodes" 'o\.datatype = "port"'
assert_contains "$nodes" 'Value, "port_hopping_interval_seconds"'
assert_contains "$nodes" 'o\.datatype = "range\(30,86400\)"'

assert_contains "$po2lmo_c" 'Apache License'
assert_contains "$po2lmo_lmo" 'lmo_archive'
assert_contains "$po2lmo_h" 'lmo_canon_hash'

assert_contains "$po" '^"Language: zh_CN\\n"$'
for msgid in \
	"Candy" \
	"Overview" \
	"Policy" \
	"DNS" \
	"Nodes" \
	"Runtime mode" \
	"Version" \
	"Build" \
	"Advanced" \
	"Fallback mode" \
	"Stable mode" \
	"Performance mode" \
	"Stable performance" \
	"Maximum throughput" \
	"Weak link" \
	"UDP impaired" \
	"CPU limited" \
	"Completed" \
	"Failed" \
	"Missing selected node" \
	"Invalid input" \
	"Not run" \
	"Unknown" \
	"Healthy" \
	"High jitter" \
	"Client packet multiplier" \
	"Server packet multiplier" \
	"UDP packet multiplier" \
	"TCP path, blocks browser QUIC/UDP, best compatibility." \
	"UDP TProxy path, better throughput and latency when UDP is healthy." \
	"China IP bypass" \
	"Provider update URL" \
	"Provider status" \
	"Entry count" \
	"Diagnostics" \
	"Link conclusion" \
	"Suggested packet multiplier" \
	"Effective packet multiplier" \
	"Not a weak link: keep the current packet multiplier." \
	"Weak link: adjust the packet multiplier to the suggested value." \
	"UDP is impaired: avoid high performance UDP mode until the path recovers." \
	"Logs" \
	"Traffic log" \
	"System service events" \
	"No service log for this boot yet." \
	"No traffic decisions for this boot yet. New transparent proxy flows are recorded with time, source, destination, matched rule, and outbound." \
	"Running" \
	"Stopping" \
	"Invalid reason" \
	"Why the result cannot drive packet multiplier policy yet." \
	"Reconnect policy" \
	"Last connection error" \
	"Manual update" \
	"Rules" \
	"Debug logs" \
	"Add rule" \
	"Copy rules" \
	"Download rules" \
	"Invalid rule value" \
	"Policy name" \
	"Selection policy" \
	"Node pool" \
	"Tune weak-link performance and transport capture." \
	"These settings affect packet redundancy and lane selection. Leave them on auto unless diagnostics show a weak-link problem." \
	"Capture LAN DNS" \
	"DNS status" \
	"Applied" \
	"Latency" \
	"Last error" \
	"Last updated" \
	"Recommended general configuration" \
	"Quick actions" \
	"Stable mode" \
	"Performance mode" \
	"Trace from overview" \
	"Advanced DNS policy" \
	"Transport and TProxy" \
	"DNS blackhole: remote DNS can break all lookups when the local DNS forwarder is unhealthy. QUIC: browsers prefer UDP/443 for Google and YouTube, so an unstable UDP data path can look like the internet is down. LAN DNS: clients may use external DNS and bypass router policy unless port 53 is captured. AAAA: IPv6 answers can bypass an IPv4-only proxy path, so Candy filters AAAA only while it is active."; do
	assert_contains "$po" "^msgid \"$msgid\"$"
done
for msgstr in \
	"概览" \
	"流量策略" \
	"DNS" \
	"节点" \
	"运行模式" \
	"版本" \
	"构建号" \
	"高级" \
	"自动回退模式" \
	"稳定模式" \
	"性能策略" \
	"TCP 路径" \
	"UDP TProxy 路径" \
	"中国 IP 分流" \
	"Provider 更新地址" \
	"Provider 状态" \
	"条目数" \
	"诊断" \
	"客户端发包倍率" \
	"服务端发包倍率" \
	"UDP 发包倍率" \
	"DNS 追踪" \
	"追踪域名" \
	"追踪结果" \
	"链路结论" \
	"建议发包倍率" \
	"当前生效倍率" \
	"非弱网：保持当前发包倍率。" \
	"弱网：按建议值调整发包倍率。" \
	"网络工具" \
	"Ping / Traceroute 结果" \
	"运行 Ping / Traceroute" \
	"日志" \
	"用户流量日志" \
	"重连策略" \
	"最后连接错误" \
	"手动更新" \
	"规则" \
	"调试日志" \
	"服务状态" \
	"DNS 状态" \
	"已应用" \
	"延迟" \
	"最后错误" \
	"添加规则" \
	"复制规则" \
	"下载规则" \
	"规则值无效" \
	"策略名" \
	"选择策略" \
	"节点池" \
	"本地转发" \
	"接管 LAN DNS" \
	"推荐通用配置" \
	"快捷操作" \
	"概览追踪" \
	"高级 DNS 策略" \
	"传输与 TProxy" \
	"DNS 黑洞"; do
	assert_contains "$po" "msgstr \".*$msgstr"
done

grep -RhoE 'translate\("[^"]+"\)|_\("[^"]+"\)|<%:[^%]+%>' "$repo_root/luci-app-candy/root" \
	| sed -E 's/.*translate\("([^"]+)"\).*/\1/; s/.*_\("([^"]+)"\).*/\1/; s/.*<%:([^%]+)%>.*/\1/' \
	| sort -u \
	| while IFS= read -r msgid; do
		grep -Fqx "msgid \"$msgid\"" "$repo_root/$po" || fail "$po missing msgid: $msgid"
	done

assert_contains "$controller" 'module\("luci.controller.candy"'
assert_contains "$controller" '/etc/config/candy'
assert_contains "$controller" '\{"admin", "services", "candy"\}.*_\("Candy"\)'
for route in overview traffic dns_geo nodes diagnostics logs advanced core; do
	assert_contains "$controller" "\"$route\""
done
assert_contains "$controller" '\{"admin", "services", "candy", "overview"\}.*_\("Overview"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "traffic"\}.*_\("Policy"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "dns_geo"\}.*_\("DNS"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "nodes"\}.*_\("Nodes"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "diagnostics"\}.*_\("Diagnostics"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "logs"\}.*_\("Logs"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "advanced"\}.*_\("Advanced"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "core"\}.*_\("Core"\)'
assert_not_contains "$controller" '\{"admin", "services", "candy", "status"\}'
assert_not_contains "$controller" '\{"admin", "services", "candy", "rules"\}'
assert_not_contains "$controller" '\{"admin", "services", "candy", "geo"\}'
assert_not_contains "$controller" '\{"admin", "services", "candy", "dns"\}'
assert_not_contains "$controller" '\{"admin", "services", "candy", "client"\}'
assert_contains "$controller" 'action_rules_import'
assert_contains "$controller" 'action_rules_export'
assert_contains "$controller" 'action_status_json'
for action in core_status core_activate core_rollback core_remove; do
	assert_contains "$controller" "action_$action"
done
assert_contains "$controller" 'status\.core = read_core_status\(\)'
assert_contains "$controller" 'CORE_MANAGER = "/usr/libexec/candy-core-manager"'
assert_not_contains "$controller" 'pidof.*candy-client'
assert_not_contains "$status" 'pidof.*candy-client'
assert_contains "$controller" 'REQUEST_METHOD.*POST'
assert_contains "$controller" 'action_runtime_mode'
assert_contains "$controller" 'udp_client_multiplier'
assert_contains "$controller" 'udp_server_multiplier'
assert_contains "$controller" 'action_geo_update'
assert_contains "$controller" 'action_gfwlist_update'
assert_not_contains "$controller" 'action_link_probe'
assert_not_contains "$controller" 'action_cdn_probe'
assert_contains "$controller" 'action_traffic_log_active'
assert_contains "$controller" 'Cache-Control'
assert_contains "$controller" 'application/json'
assert_contains "$controller" '/tmp/candy\.lifecycle'
assert_contains "$controller" 'mark_service_transition'
assert_contains "$controller" 'read_service_transition'
assert_contains "$controller" 'apply_service_transition'
assert_contains "$controller" 'transition\.state'
assert_contains "$controller" 'sync_node_states_with_service'
assert_contains "$controller" 'service == "running"'
assert_contains "$controller" 'service == "starting"'
assert_contains "$controller" 'SERVICE_LIFECYCLE_TTL = 10'
assert_before "$controller" 'mark_service_transition\(action\)' 'candy_service_async\(action\)'
assert_contains "$controller" 'transition.state == "starting" and "starting" or "stopped"'
assert_contains "$status" 'service_status ~= "stopped" or transition.state == "starting"'
assert_contains "$controller" 'status\.runtime\.multi_node'
assert_contains "$controller" 'node.state = "connecting"'
assert_contains "$controller" 'rules_unchanged'
assert_not_contains "$controller" 'local argv = \{ "/usr/bin/candy-client", "--config", "/var/run/candy/runtime\.json"'
assert_not_contains "$controller" 'link probe'
assert_not_contains "$controller" 'cdn_probe'
assert_contains "$controller" '/tmp/candy-traffic-log\.enabled'
assert_contains "$controller" '/tmp/candy-traffic\.log'
assert_contains "$controller" 'Cache-Control'
assert_not_contains "$controller" 'action_diagnostics_bundle'
assert_not_contains "$controller" 'action_dns_trace'
assert_not_contains "$controller" 'action_network_check'
assert_not_contains "$controller" 'egress-dns'
assert_not_contains "$controller" 'ping -c 4'
assert_not_contains "$controller" 'traceroute'
assert_contains "$controller" 'sync_geo_bypass_rule'
assert_contains "$controller" 'normalize_geo_update_url'
assert_contains "$controller" 'normalize_gfwlist_update_url'
assert_contains "$controller" 'https://'
assert_contains "$controller" 'redirect_geo\("failed"\)'
assert_contains "$controller" 'uci:delete_all\("candy", "rule"\)'
assert_contains "$controller" 'GEOIP,CN,DIRECT,no-resolve'
assert_contains "$controller" 'uci:reorder\("candy", keep_geo, first_match_index\)'
assert_contains "$controller" 'allowed = \{'
assert_contains "$controller" 'start = true'
assert_contains "$controller" 'stop = true'
assert_contains "$controller" 'restart = true'
assert_contains "$controller" '/etc/init.d/candy'
assert_not_contains "$controller" 'reload = true'
assert_not_contains "$controller" '/etc/init.d/carrier'
assert_not_contains "$controller" '%q'
assert_not_contains "$dns" '%q'
assert_contains "$controller" 'run_argv'
assert_contains "$dns" 'process\.run'
assert_contains "$controller" 'url:match\("\^https://'
assert_contains "$controller" 'PASSIVE_STATUS_FILE = "/var/run/candy/passive-status\.json"'
assert_contains "$controller" 'MAX_PASSIVE_STATUS_BYTES = 262144'
assert_contains "$controller" 'contains_credential_field'
assert_contains "$controller" 'read_multi_node_passive_status'
assert_contains "$controller" 'runtime\.multi_node = nil'
assert_contains "$dns" 'normalize_resolver_list'
assert_not_contains "$controller" 'luci\.sys\.call\(cmd\)'
assert_not_contains "$dns" 'luci\.sys\.call\(cmd\)'

assert_contains "$nodes" 'Map\("candy"'
for field in mode selected_group selected_node; do
	assert_not_contains "$nodes" "\"$field\""
done
assert_contains "$nodes" 'uci:foreach\("candy", "node"'
assert_contains "$nodes" 'translate\("Node pool"\)'
assert_contains "$nodes" 'translate\("Node groups"\)'
assert_contains "$nodes" 'translate\("Group name"\)'
assert_contains "$nodes" 'translate\("Algorithm"\)'
assert_contains "$nodes" 'type\(value\) == "table" and value or \{ value \}'
assert_contains "$nodes" 'for _, node_id in ipairs\(values\) do'
assert_contains "$nodes" 'self\.map\.uci:get\(self\.config, node_id\)'
assert_not_contains "$nodes" 'uci:get\("candy", value\)'
assert_contains "$nodes" 'sectionhead = translate\("Group name"\)'
assert_contains "$nodes" 'function unique_section_id\(prefix\)'
assert_contains "$nodes" 'unique_section_id\("node"\)'
assert_contains "$nodes" 'unique_section_id\("group"\)'
assert_contains "$nodes" 'self\.map:set\(id, nil, self\.sectiontype\)'
assert_contains "$nodes" 'self\.map:set\(id, "type", "round-robin"\)'
assert_contains "$nodes" 's:option\(Value, "name", translate\("Group name"\)\)'
for algorithm in select load-balance round-robin consistent-hash fallback url-test; do
	assert_contains "$nodes" "o:value\(\"$algorithm\""
done
assert_not_contains "$nodes" 'value == "select"'
assert_not_contains "$nodes" 'value == "load-balance"'
assert_not_contains "$nodes" 'self\.map:set\(id, "name", id\)'
assert_not_contains "$nodes" 'self\.map:set\(id, "key_id", id\)'
assert_not_contains "$nodes" 's:option\(DummyValue, "__policy_name"'
assert_not_contains "$nodes" 'candy-auto-section-id'
assert_not_contains "$nodes" 'function autoSectionIds'
assert_not_contains "$nodes" 'cbi-section-create'
assert_not_contains "$nodes" '"node-"'
assert_not_contains "$nodes" '"policy-"'
assert_not_contains "$nodes" 'Displayed node name used inside groups and runtime status'
assert_not_contains "$nodes" 'translate\("Local forwards'
assert_not_contains "$nodes" 'o:value\("global"'
assert_not_contains "$nodes" 'o:value\("direct"'
for field in dns_remote dns_capture_lan filter_aaaa auto_firewall redirect_tcp transparent_tcp_port block_quic redirect_udp transparent_udp_port tproxy_mark; do
	assert_not_contains "$nodes" "\"$field\""
done
for section in node group; do
	assert_contains "$nodes" "TypedSection, \"$section\""
done
assert_not_contains "$nodes" 'TypedSection, "forward"'
assert_not_contains "$nodes" 'TypedSection, "rule"'
assert_contains "$nodes" 'process\.run\(\{ "/etc/init.d/candy", "reload_runtime" \}, \{ background = true \}\)'
assert_not_contains "$nodes" '/etc/init.d/candy reload'
assert_not_contains "$nodes" '/etc/init.d/carrier'
assert_contains "$nodes" 'process\.run\(\{ "/etc/init.d/candy", "status" \}\)'

assert_contains "$dns" 'Map\("candy"'
assert_contains "$dns" 'translate\("DNS"\)'
assert_contains "$dns" 'DOMESTIC_RESOLVERS_DEFAULT = "system,223\.5\.5\.5:53,119\.29\.29\.29:53"'
assert_contains "$dns" 'FOREIGN_RESOLVER_DEFAULT = "8\.8\.8\.8:53"'
assert_contains "$dns" 'normalize_resolver_list'
assert_contains "$dns" 'token == "system"'
assert_not_contains "$dns" 'o:value\("system"'
for field in dns_remote dns_capture_lan dns_split dns_domestic_resolvers dns_egress_resolver bypass_china_ip; do
	assert_contains "$dns" "\"$field\""
done
for field in filter_aaaa dns_mode dns_unknown_strategy dns_answer_geo_validate dns_foreign_strategy dns_bootstrap_resolvers dns_cache dns_cache_max_entries dns_bind_answers_to_route dns_ttl_cap_seconds dns_negative_ttl_seconds geo_update_url geo_auto_update geo_update_interval_hours gfwlist_update_url gfwlist_auto_update gfwlist_update_interval_hours; do
	assert_not_contains "$dns" "\"$field\""
done
assert_contains "$dns" 'sync_geo_bypass_rule'
assert_contains "$dns" 'GEOIP,CN,DIRECT,no-resolve'
assert_contains "$dns" 'dns_tunnels'
assert_contains "$dns" 'PASSIVE_STATUS_FILE = "/var/run/candy/passive-status\.json"'
assert_not_contains "$dns" 'Long-lived DNS tunnel'
assert_contains "$dns" 'tunnel\.connected'
assert_contains "$dns" 'tunnel\.resolver'
assert_contains "$dns" 'candy/dns_tunnel_status'
assert_contains "$dns_tunnel_status" '<%:Node%>'
assert_contains "$dns_tunnel_status" '<%:Status%>'
assert_contains "$dns_tunnel_status" '<%:Resolver%>'
assert_contains "$dns_tunnel_status" 'candy-dns-tunnel-state'
assert_contains "$dns_tunnel_status" 'luci\.xml\.pcdata'
for field in block_quic redirect_udp transparent_udp_port tproxy_mark; do
	assert_not_contains "$dns" "\"$field\""
done
assert_contains "$dns" 'process\.run\(\{ "/etc/init.d/candy", "status" \}\)'
assert_contains "$dns" 'process\.run\(\{ "/etc/init.d/candy", "reload_runtime" \}, \{ background = true \}\)'
assert_not_contains "$dns" '/etc/init.d/candy reload'
assert_not_contains "$dns" '/etc/init.d/carrier'

assert_contains "$advanced" 'Map\("candy"'
assert_contains "$advanced" 'translate\("Advanced"\)'
assert_not_contains "$advanced" '"runtime_mode"'
assert_not_contains "$advanced" 'value\("fallback"'
for field in performance_mode lanes udp_client_multiplier udp_server_multiplier; do
	assert_not_contains "$advanced" "\"$field\""
done
for field in redirect_udp transparent_udp_port block_quic tproxy_mark filter_aaaa gfwlist_update_url gfwlist_auto_update gfwlist_update_interval_hours dns_mode dns_unknown_strategy dns_answer_geo_validate dns_bootstrap_resolvers dns_cache dns_cache_max_entries dns_bind_answers_to_route dns_ttl_cap_seconds dns_negative_ttl_seconds geo_update_url geo_auto_update geo_update_interval_hours; do
	assert_contains "$advanced" "\"$field\""
done
assert_contains "$advanced" 'translate\("Transport and TProxy"\)'
assert_contains "$advanced" '"congestion_profile"'
assert_not_contains "$advanced" 'value\("cubic"'
assert_not_contains "$advanced" 'set\("candy", section, "congestion", "cubic"\)'
assert_contains "$advanced" 'set\("candy", section, "congestion", "candy-bbr"\)'
assert_contains "$advanced" 'translate\("DNS expert settings"\)'
assert_contains "$advanced" 'translate\("Provider updates"\)'
assert_not_contains "$advanced" 'translate\("Weak-link performance"\)'
assert_not_contains "$advanced" 'translate\("Local forwards"\)'
assert_not_contains "$advanced" 'TypedSection, "forward"'
assert_contains "$advanced" 'process\.run\(\{ "/etc/init.d/candy", "restart_queued" \}, \{ background = true \}\)'
assert_not_contains "$advanced" '/etc/init.d/carrier'

assert_contains "$controller" '"geo", "update", "cn-ip"'
assert_contains "$controller" '"dns", "update", "gfwlist"'
assert_contains "$controller" 'output = "/tmp/candy-geo-update\.log", append = true'
assert_contains "$controller" 'output = "/tmp/candy-gfwlist-update\.log", append = true'
assert_contains "$process_helper" 'options\.append and "a" or "w"'
assert_contains "$controller" 'CONGESTION_TEST_POINTS'
assert_contains "$controller" 'formvalue\("test_point"\)'
assert_contains "$controller" '"congestion_test", test_point'
assert_contains "$init" 'provider_update_loop'
assert_contains "$init" 'CANDY_DNS_LISTEN=.*127\.0\.0\.1:15353'
assert_contains "$init" 'run_client\(\)'
assert_contains "$init" 'procd_set_param command "\$CANDY_INIT_SELF" run_client'
assert_contains "$init" 'procd_set_param user root'
assert_contains "$init" 'migrate_reserved_dns_forward'
assert_contains "$init" 'forward local listen conflicts with reserved Candy DNS listener'
assert_contains "$init" 'skip_reserved_forward'
assert_contains "$init" 'CANDY_LIFECYCLE_FILE'
assert_contains "$init" 'write_lifecycle_state restart starting'
assert_contains "$init" 'write_lifecycle_state stop stopping'
assert_contains "$init" 'write_lifecycle_state start running'
assert_contains "$init" 'write_lifecycle_state stop stopped'
assert_contains "$init" 'gfwlist_update_interval_hours'
assert_contains "$init" 'geo_update_interval_hours'
assert_contains "$init" 'dns update gfwlist'
assert_contains "$init" 'geo update cn-ip'
assert_contains "$init" 'congestion-test --test-point "\$test_point" --samples 1 --max-bytes 104857600 --timeout-ms 60000'
assert_contains "$init" 'congestion-test --help'
assert_contains "$init" 'update Core to 0\.3\.5 or newer'
assert_not_contains "$init" 'congestion-test --samples 1 --max-bytes 2097152'
if [ -e "$repo_root/luci-app-candy/root/usr/lib/lua/luci/model/cbi/candy/geo.lua" ]; then
	fail "GEO model must be merged into DNS & GEO"
fi

if [ -e "$repo_root/$client" ]; then
	fail "Client model must be split into nodes/groups and rules"
fi

for view in "$status" "$diagnostics" "$rules"; do
	assert_contains "$view" 'require "luci.xml"'
	assert_contains "$view" 'xml\.pcdata'
	assert_not_contains "$view" 'luci\.util\.pcdata'
	assert_not_contains "$view" 'carrier'
done

assert_contains "$status" '/tmp/candy\.nodes'
assert_contains "$status" 'status_json'
assert_contains "$status" 'candy-status-service'
assert_contains "$status" 'Stopping'
assert_contains "$status" 'transition\.state == "stopping"'
assert_contains "$status" 'os\.time\(\) - tonumber\(transition\.updated_at\) <= 10'
assert_contains "$status" 'refreshCandyOverviewStatus'
assert_contains "$status" 'candyOverviewRequestGeneration'
assert_contains "$status" 'setTimeout\(refreshCandyOverviewStatus, 2000\)'
assert_not_contains "$status" 'setInterval\(refreshCandyOverviewStatus, 2000\)'
assert_contains "$status" '<h2 name="content">Candy</h2>'
assert_contains "$status" 'candy-logo'
assert_contains "$status" 'candy-logo-mark'
assert_contains "$status" 'flex-direction: column'
assert_contains "$status" 'text-align: center'
assert_not_contains "$status" 'Candy 0\.3\.4 records BBR fallback evidence and automatically retries Candy BBR after a bounded CUBIC cooldown\.'
assert_contains "$status" 'id="candy-sdwan-status"'
assert_contains "$status" 'sdwan\.enabled === true'
assert_not_contains "$status" 'Smart DNS/GEO'
assert_not_contains "$status" 'Weak-link QoS'
assert_not_contains "$status" 'Video/CDN diagnostics'
assert_contains "$status" 'candy-overview-actions'
assert_contains "$status" 'candy-feature-grid'
assert_contains "$status" 'candy-feature-card\.active'
assert_contains "$status" 'candy-feature-card\.unauthorized'
assert_contains "$status" 'grid-template-columns: minmax\(0, 1fr\) auto'
assert_contains "$status" 'align-items: start'
assert_contains "$status" 'min-height: 2\.5em'
assert_contains "$status" 'candy-feature-badge\.active'
assert_contains "$status" 'badge\.className = "candy-feature-badge " \+ state'
assert_contains "$status" 'candy-feature-card\.active \{ border-color: #b8ddc3; background: #f4fbf6; \}'
assert_contains "$status" 'candy-feature-card\.active::before \{ background: #238636; \}'
assert_contains "$status" 'authorized \? "inactive" : "unauthorized"'
assert_contains "$status" 'Supported, inactive'
assert_contains "$status" 'Supported, not authorized'
assert_not_contains "$status" 'candyOverviewFeatureEvidence'
assert_not_contains "$status" 'definition\.description'
assert_not_contains "$status" 'definition\.activation'
assert_contains "$status" 'candy-overview-section'
assert_contains "$status" 'manifest && manifest\.core && manifest\.core\.features'
assert_contains "$status" 'definition\.status_key \|\| definition\.id'
assert_not_contains "$status" 'candyOverviewFeatureNames'
assert_not_contains "$status" 'Fragment frame bytes'
assert_not_contains "$status" 'Early streams opened'
assert_not_contains "$status" 'Fallback transitions'
assert_not_contains "$status" '<th class="th"><%:Supported%></th>'
assert_not_contains "$status" '<th class="th"><%:Authorized%></th>'
assert_not_contains "$status" 'border-bottom: 1px solid #444;'
assert_contains "$status" 'action.*restart'
assert_contains "$status" 'action.*start'
assert_contains "$status" 'action.*stop'
assert_not_contains "$status" '<%:Quick actions%>'
assert_contains "$status" 'require "luci.jsonc"'
assert_contains "$status" 'jsonc\.parse'
assert_contains "$status" 'status\.nodes'
assert_not_contains "$status" 'runtime_performance\.passive'
assert_not_contains "$status" 'candy-status-passive'
assert_not_contains "$status" 'candyOverviewRenderPassive'
assert_not_contains "$status" 'link probe'
assert_not_contains "$status" 'cdn probe'

assert_contains "$status" 'node\.groups'
assert_contains "$status" 'node\.url_test'
assert_not_contains "$status" 'node\.active_tcp_flows'
assert_not_contains "$status" 'node\.active_udp_flows'
assert_contains "$status" 'node\.server_version'
assert_not_contains "$status" 'node\.reconnects'
assert_not_contains "$status" 'node\.last_error'
assert_not_contains "$status" 'status\.dns'

assert_contains "$core_view" 'core_status'
assert_not_contains "$core_view" 'core_install'
assert_not_contains "$core_view" 'Install Core bundle'
assert_not_contains "$core_view" 'Bundle URL'
assert_not_contains "$core_view" 'candy-core-install-submit'
assert_contains "$core_view" 'core_activate'
assert_contains "$core_view" 'core_rollback'
assert_contains "$core_view" 'core_remove'
assert_contains "$core_view" 'current_manifest'
assert_contains "$core_view" 'process_api_version'
assert_contains "$core_view" 'protocol_version'
assert_contains "$core_view" 'target_arch'
assert_contains "$update_view" 'data\.core && data\.core\.installed'
assert_contains "$update_view" 'candy-update-core-installed'
assert_contains "$update_view" 'candyUpdateCorePageUrl'
assert_contains "$update_view" 'installedCore && !installedCore\.active'
assert_contains "$update_view" 'candyUpdateLink'
assert_not_contains "$status" 'status\.diagnostics'
assert_not_contains "$status" 'runtime_mode'
assert_contains "$status" 'status\.version'
assert_not_contains "$status" 'status\.build_id'
assert_contains "$status" '<%:Candy version%>'
assert_contains "$status" '<%:Core version%>'
assert_not_contains "$status" '<%:Client version%>'
assert_not_contains "$status" '<%:LuCI version%>'
assert_contains "$status" 'candy-status-client-version'
assert_not_contains "$status" 'candy-status-luci-version'
assert_not_contains "$status" '<%:UDP packet multiplier%>'
assert_not_contains "$status" 'diagnostics\.udp_redundancy'
assert_not_contains "$status" 'runtime_performance\.udp_client_multiplier'
assert_not_contains "$status" '<%:Runtime mode%>'
assert_not_contains "$status" 'name="runtime_mode"'
assert_not_contains "$status" 'value="stable"'
assert_not_contains "$status" 'value="performance"'
assert_not_contains "$status" 'diagnostics_bundle'
assert_not_contains "$status" 'dns_trace'
assert_not_contains "$status" '<%:Export diagnostic bundle%>'
assert_not_contains "$status" '<%:DNS trace%>'
assert_not_contains "$status" '<%:Trace from overview%>'
assert_not_contains "$status" 'TCP path, blocks browser QUIC/UDP'
assert_not_contains "$status" 'UDP TProxy path, better throughput'
assert_not_contains "$status" 'dns\.remote'
assert_not_contains "$status" 'dns\.capture_lan'
assert_not_contains "$status" 'dns\.filter_aaaa'
assert_not_contains "$status" 'dns\.applied'
assert_not_contains "$status" 'dns\.config_path'
assert_not_contains "$status" '<%:DNS status%>'
assert_not_contains "$status" '<%:Diagnostics%>'
assert_not_contains "$status" '<%:Weak-link probe%>'
assert_not_contains "$status" '<%:Security smoke%>'
assert_not_contains "$status" '<%:Provider freshness%>'
assert_contains "$status" '<%:Node status%>'
assert_contains "$status" '<%:Node groups%>'
assert_contains "$status" '<%:URL latency%>'
assert_contains "$status" '<%:Local RTT%>'
assert_not_contains "$status" '<%:URL Test status%>'
assert_not_contains "$status" '<%:Active TCP flows%>'
assert_not_contains "$status" '<%:Active UDP flows%>'
assert_contains "$status" '<%:Server version%>'
assert_not_contains "$status" '<%:Throughput%>'
assert_not_contains "$status" 'localStatus\.goodput_bps'
assert_not_contains "$status" '<%:Send rate%>'
assert_not_contains "$status" '<%:Receive rate%>'
assert_not_contains "$status" '<%:Reconnects%>'
assert_not_contains "$status" '<%:Last error%>'
assert_not_contains "$status" '<%:Selected node%>'
assert_not_contains "$status" '<%:Video score%>'
assert_not_contains "$status" '<%:CDN score%>'
assert_not_contains "$status" '<%:TTFB%>'
assert_not_contains "$status" '<%:Probe%>'
assert_not_contains "$status" '<%:Reconnect policy%>'
assert_not_contains "$status" '<%:Last connection error%>'
assert_not_contains "$status" 'diagnostics\.weak_link_probe'
assert_not_contains "$status" 'diagnostics\.security_smoke'
assert_not_contains "$status" 'diagnostics\.dns_trace'
assert_not_contains "$status" 'diagnostics\.provider_freshness'
assert_not_contains "$status" 'diagnostics\.reconnect_policy'
assert_not_contains "$status" '/tmp/candy\.log'
assert_not_contains "$status" '/var/run/candy/runtime\.json'
assert_not_contains "$status" 'logread'
assert_not_contains "$status" 'netstat -lnp'
assert_not_contains "$status" "ps 2>/dev/null"
assert_not_contains "$status" '<%:Logs and diagnostics%>'
assert_not_contains "$status" 'line:match\("\^\(\[\^\\t\]\*\)\\t'

assert_count "$diagnostics" '<div class="cbi-map">' 4
assert_contains "$diagnostics" '<%:Diagnostics%>'
assert_contains "$diagnostics" '<%:Service resources%>'
assert_contains "$diagnostics" '<%:Per-node passive diagnostics%>'
assert_contains "$diagnostics" 'runtime_performance\.passive'
assert_contains "$diagnostics" 'node\.passive'
assert_contains "$diagnostics" 'candyDiagnosticsRender'
assert_contains "$diagnostics" 'setTimeout\(refreshCandyDiagnosticsStatus, 2000\)'
assert_not_contains "$diagnostics" 'setInterval\(refreshCandyDiagnosticsStatus, 2000\)'
assert_contains "$diagnostics" 'candy-diagnostics-nodes'
assert_contains "$diagnostics" 'candy-diagnostics-process-cpu'
assert_contains "$diagnostics" 'candy-diagnostics-process-rss'
assert_contains "$diagnostics" 'smoothed_rtt_micros'
assert_contains "$diagnostics" 'cwnd_bytes'
assert_contains "$diagnostics" 'pacing_rate_bps'
assert_contains "$diagnostics" 'bandwidth_estimate_bps'
assert_contains "$diagnostics" 'congestion_mode'
assert_contains "$diagnostics" 'recovery_state'
assert_contains "$diagnostics" 'path_mtu'
assert_contains "$diagnostics" 'applied\.congestion'
assert_contains "$diagnostics" 'process_status\.cpu_percent'
assert_contains "$diagnostics" 'resident_memory_bytes'
assert_contains "$diagnostics" 'goodput_bps'
assert_not_contains "$diagnostics" 'client_udp_multiplier'
assert_not_contains "$diagnostics" 'server_udp_multiplier'
assert_not_contains "$diagnostics" 'passive\.peer'
assert_contains "$diagnostics" 'configured_congestion|controllers'
assert_not_contains "$diagnostics" '<%:Link diagnosis%>'
assert_not_contains "$diagnostics" '<%:Link conclusion%>'
assert_not_contains "$diagnostics" '<%:Suggested packet multiplier%>'
assert_not_contains "$diagnostics" '<%:Weak-link probe%>'
assert_not_contains "$diagnostics" '<%:Run weak-link probe%>'
assert_not_contains "$diagnostics" 'name="node"'
assert_not_contains "$diagnostics" 'candy-link-probe-action'
assert_not_contains "$diagnostics" '<%:Weak-link probe result%>'
assert_not_contains "$diagnostics" '<%:Video/CDN probe%>'
assert_not_contains "$diagnostics" '<%:Run Video/CDN probe%>'
assert_not_contains "$diagnostics" '<%:Invalid reason%>'
assert_not_contains "$diagnostics" '<%:Export diagnostic bundle%>'
assert_not_contains "$diagnostics" 'weak_link_action_label'
assert_not_contains "$diagnostics" 'weak_link_probe\.status and weak_link_probe\.status ~= ""'
assert_not_contains "$diagnostics" '<th class="th"><%:Link conclusion%></th>'
assert_not_contains "$diagnostics" 'Not a weak link: keep the current packet multiplier.'
assert_not_contains "$diagnostics" 'Weak link: adjust the packet multiplier to the suggested value.'
assert_not_contains "$diagnostics" 'UDP is impaired: avoid high performance UDP mode until the path recovers.'
assert_not_contains "$diagnostics" 'Probe invalid: run weak-link probe again before changing packet multiplier.'
assert_not_contains "$diagnostics" 'UDP echo response'
assert_not_contains "$diagnostics" 'status_label'
assert_not_contains "$diagnostics" 'Probe invalid: not enough valid loss, latency, or throughput samples.'
assert_not_contains "$diagnostics" 'link_probe'
assert_not_contains "$diagnostics" 'cdn_probe'
assert_not_contains "$diagnostics" 'diagnostics_bundle'
assert_not_contains "$diagnostics" 'dns_trace'
assert_not_contains "$diagnostics" 'network_check'
assert_not_contains "$diagnostics" '<%:Trace domain%>'
assert_not_contains "$diagnostics" '<%:Trace result%>'
assert_not_contains "$diagnostics" '<%:Network tools%>'
assert_not_contains "$diagnostics" '<%:Run ping / traceroute%>'
assert_not_contains "$diagnostics" '<%:Ping / traceroute result%>'
assert_not_contains "$diagnostics" '/tmp/candy-dns-trace.log'
assert_not_contains "$diagnostics" '/tmp/candy-network-check.log'
assert_not_contains "$diagnostics" '/tmp/candy-link-probe.log'
assert_not_contains "$diagnostics" 'diagnostics\.link'
assert_not_contains "$diagnostics" 'diagnostics\.weak_link_probe'
assert_not_contains "$diagnostics" 'link_probe_result'
assert_not_contains "$diagnostics" '<%:Field%>'
assert_not_contains "$diagnostics" '<%:Meaning%>'
assert_not_contains "$diagnostics" '<%:Jitter%>'
assert_not_contains "$diagnostics" '<%:Packet loss%>'
assert_not_contains "$diagnostics" '<%:UDP impaired%>'
assert_not_contains "$diagnostics" '<%:Invalid reason%>'
assert_not_contains "$diagnostics" '<%:Effective packet multiplier%>'
assert_not_contains "$diagnostics" '<%:Provider freshness%>'
assert_not_contains "$diagnostics" '<%:Security smoke%>'
assert_not_contains "$diagnostics" '<%:Video score%>'
assert_not_contains "$diagnostics" '<%:CDN score%>'
assert_not_contains "$diagnostics" '<%:Debug logs%>'
assert_not_contains "$diagnostics" '<%:Last error%>'
assert_contains "$diagnostics" 'stroke-dasharray'
assert_contains "$diagnostics" '100000'
assert_contains "$diagnostics" 'maximum \* ratio'
assert_contains "$diagnostics" 'sharedReference'
assert_not_contains "$diagnostics" 'candy-chart-flight'
assert_contains "$diagnostics" 'table-layout: fixed'
assert_contains "$diagnostics" '<colgroup>'
assert_contains "$diagnostics" 'translate\("Goodput"\)'
assert_contains "$diagnostics" 'translate\("Estimated capacity"\)'
assert_contains "$diagnostics" 'translate\("Idle"\)'
assert_contains "$diagnostics" 'bandwidth_estimate_bps'
assert_contains "$diagnostics" 'candyDiagnosticsGoodput'
assert_not_contains "$diagnostics" 'carrier'

assert_count "$logs" '<div class="cbi-map">' 1
assert_contains "$logs" '<%:Logs%>'
assert_contains "$logs" '<%:Service log%>'
assert_contains "$logs" '<%:Traffic log%>'
assert_contains "$logs" 'System service events'
assert_contains "$logs" 'No traffic decisions for this boot yet'
assert_contains "$logs" 'traffic_log_active'
assert_contains "$logs" 'candy_traffic_log'
assert_contains "$logs" 'LOG_HISTORY_GENERATIONS = 5'
assert_contains "$logs" 'read_log_history'
assert_contains "$logs" 'LOG_READ_LIMIT = 128 \* 1024'
assert_contains "$logs" 'base .. "." .. generation'
assert_contains "$logs" 'xhr\.open\("POST"'
assert_contains "$logs" 'encodeURIComponent\(csrfToken\)'
assert_not_contains "$logs" 'writefile\("/tmp/candy-traffic\.log", ""\)'
assert_contains "$logs" 'Cache-Control'
assert_contains "$logs" 'candy-log-section \+ \.candy-log-section'
assert_contains "$logs" '/tmp/candy\.log'
assert_contains "$logs" '/tmp/candy-traffic\.log'
assert_contains "$logs" 'logread'
assert_contains "$logs" 'process\.capture\(\{ "/sbin/logread" \}\)'
assert_not_contains "$logs" 'Firewall counters'
assert_not_contains "$logs" 'nft list table inet fw4'
assert_not_contains "$logs" 'iptables -t nat -L CANDY'
assert_not_contains "$logs" '<%:System log%>'
assert_not_contains "$logs" '<%:Raw diagnostics%>'
assert_not_contains "$logs" '/var/run/candy/runtime\.json'
assert_not_contains "$logs" 'netstat -lnp'
assert_not_contains "$logs" "ps 2>/dev/null"
assert_not_contains "$logs" 'redact_runtime'
assert_not_contains "$logs" '/tmp/candy\.nodes'

assert_count "$rules" '<div class="cbi-map">' 2
assert_contains "$rules" '<%:Policy%>'
assert_not_contains "$rules" '"runtime_mode"'
assert_not_contains "$rules" 'value="stable"'
assert_not_contains "$rules" 'value="performance"'
assert_contains "$rules" '<%:Add rule%>'
assert_contains "$rules" '<%:Rules%>'
assert_not_contains "$rules" '<%:Current rules%>'
assert_not_contains "$rules" '<%:Manual edit%>'
assert_not_contains "$rules" '<%:Import / Export%>'
assert_contains "$rules" 'input type="hidden" name="rules"'
assert_contains "$rules" 'id="rules_manual"'
assert_not_contains "$rules" 'id="rules_import"'
assert_contains "$rules" '<table class="table"'
assert_contains "$rules" 'select id="rule_kind"'
assert_contains "$rules" 'input id="rule_value"'
assert_contains "$rules" 'id="rule_value_error"'
assert_contains "$rules" 'select id="rule_target"'
assert_contains "$rules" 'input id="rule_no_resolve"'
assert_contains "$rules" 'function candyRuleValidateValue'
assert_contains "$rules" 'function candyRuleIsDomain'
assert_contains "$rules" 'function candyRuleIsIpv4Cidr'
assert_contains "$rules" 'function candyRuleIsIpv6Cidr'
assert_contains "$rules" 'function candyRuleIsPort'
assert_contains "$rules" 'function buildCandyRule'
assert_contains "$rules" 'function appendCandyRule'
assert_contains "$rules" 'rule \+ "\\n" \+ current'
assert_contains "$rules" 'function syncCandyRuleTextareas'
assert_contains "$rules" 'function validateCandyRulesForSubmit'
assert_contains "$rules" 'candyRuleAllowedTargets'
assert_contains "$rules" 'Rule targets must be DIRECT, REJECT, or an existing node group\.'
assert_contains "$rules" 'function copyCandyRules'
for kind in DOMAIN DOMAIN-SUFFIX DOMAIN-KEYWORD GEOIP IP-CIDR IP-CIDR6 SRC-IP-CIDR SRC-PORT DST-PORT RULE-SET MATCH; do
	assert_contains "$rules" "value=\"$kind\""
done
assert_not_contains "$rules" 'PROCESS-NAME'
assert_not_contains "$controller" 'PROCESS-NAME'
assert_contains "$rules" 'rules_export'
assert_contains "$rules" 'rules_import'
assert_contains "$rules" '<%:Copy rules%>'
assert_contains "$rules" '<%:Download rules%>'
assert_contains "$rules" '<%:Save rules%>'
assert_contains "$rules" 'MATCH,Proxy'

lua - "$repo_root/$controller" "$repo_root/$process_helper" <<'LUA'
local controller_path = arg[1]
local process_helper_path = arg[2]
local forms = {}
local runtime_node_name = ""
local executed
local redirected

module = function() end
luci = {
	sys = {
		call = function() error("shell-call-forbidden") end,
		exec = function() return "stopped" end,
		init = { enabled = function() return true end }
	},
	http = {
		getenv = function(name) return name == "REQUEST_METHOD" and "POST" or nil end,
		formvalue = function(name) return forms[name] end,
		redirect = function(url) redirected = url end,
		header = function() end,
		prepare_content = function() end,
		write = function() end
	},
	dispatcher = {
		build_url = function(...) return table.concat({...}, "/") end,
		context = { authsession = "test-csrf-token" }
	}
}

package.preload["nixio.fs"] = function()
	return {
		access = function() return true end,
		readfile = function() return "{}" end,
		writefile = function() return true end,
		rename = function() return true end,
		unlink = function() return true end
	}
end
package.preload["luci.jsonc"] = function()
	return {
		parse = function() return { nodes = {{ name = runtime_node_name, selected = true, state = "running" }} } end,
		stringify = function() return "{}" end
	}
end
package.preload["luci.model.uci"] = function()
	return {
		cursor = function()
			return {
				get = function() return nil end,
				foreach = function(_, _, kind, callback)
					if kind == "node" then
						callback({ name = runtime_node_name, enabled = "1", server = "192.0.2.1:18443" })
					end
				end,
				set = function() end,
				commit = function() end
			}
		end
	}
end
package.preload["nixio"] = function()
	return {
		fork = function() return 0 end,
		getpid = function() return 123 end,
		open = function() return {} end,
		dup = function() return true end,
		setenv = function() return true end,
		exec = function(...)
			executed = {...}
			error("exec-stop")
		end,
		stdout = 1,
		stderr = 2
	}
end
package.preload["nixio.fs"] = function()
	return {
		readfile = function() return "" end,
		writefile = function() return true end,
		rename = function() return true end,
		unlink = function() return true end
	}
end
package.preload["luci.candy.process"] = function()
	return dofile(process_helper_path)
end

dofile(controller_path)

local provider = "https://example.test/a$(touch_x);`id`'\""
forms = { url = provider, token = "test-csrf-token" }
executed = nil
local ok, err = pcall(action_geo_update)
assert(not ok and tostring(err):match("exec%-stop"), tostring(err))
assert(executed and executed[1] == "/usr/bin/candy-client")
local saw_provider = false
for _, value in ipairs(executed) do
	if value == provider then saw_provider = true end
end
assert(saw_provider, "provider URL was not preserved literally")

for _, invalid in ipairs({
	"http://example.test/provider",
	"file:///tmp/provider",
	"https://example.test/line1\nline2"
}) do
	forms = { url = invalid, token = "test-csrf-token" }
	executed = nil
	redirected = nil
	ok, err = pcall(action_geo_update)
	assert(ok, tostring(err))
	assert(executed == nil, "invalid provider URL reached exec")
assert(redirected and (redirected:match("failed") or redirected:match("invalid")))
end
local injected = io.open("/tmp/candy-injected", "r")
assert(injected == nil, "shell expansion created injection sentinel")
LUA

lua - "$repo_root/$process_helper" <<'LUA'
local helper_path = arg[1]
local executed
package.preload["nixio"] = function()
	return {
		fork = function() return 0 end,
		open = function(path, flags, permissions)
			assert(path == "/dev/null", "argv helper redirected to an unexpected path")
			assert(flags == "w", "argv helper opened output with unexpected flags")
			assert(permissions == "rw-------", "nixio.open permissions must use the OpenWrt string format")
			return {}
		end,
		dup = function() return true end,
		setenv = function() return true end,
		exec = function(...)
			executed = {...}
			error("exec-stop")
		end,
		stdout = 1,
		stderr = 2
	}
end
package.preload["nixio.fs"] = function()
	return {
		readfile = function() return "" end,
		unlink = function() return true end
	}
end

local process = dofile(helper_path)
local dangerous = "node-$(touch /tmp/candy-process-injected)-`id`-'\";line1\nline2"
os.remove("/tmp/candy-process-injected")
local ok, err = pcall(process.run, { "/usr/bin/candy-client", "probe", dangerous })
assert(not ok and tostring(err):match("exec%-stop"), tostring(err))
assert(executed and executed[1] == "/usr/bin/candy-client")
assert(executed[2] == "probe")
assert(executed[3] == dangerous, "argv helper changed the dangerous argument")
assert(io.open("/tmp/candy-process-injected", "r") == nil, "argv helper invoked a shell")
LUA

lua - "$repo_root/$process_helper" <<'LUA'
local helper_path = arg[1]
local temp_accessed = false
local chunks = { string.rep("a", 700000), string.rep("b", 700000) }
local reader = {
	read = function()
		return table.remove(chunks, 1)
	end,
	close = function() return true end
}
local writer = { close = function() return true end }

package.preload["nixio"] = function()
	return {
		pipe = function() return reader, writer end,
		fork = function() return 4242 end,
		waitpid = function() return 4242, "exited", 0 end,
		getpid = function() return 321 end,
		stdout = 1,
		stderr = 2
	}
end
package.preload["nixio.fs"] = function()
	return {
		readfile = function() temp_accessed = true; return "victim" end,
		unlink = function() temp_accessed = true; return true end
	}
end

local victim = "/tmp/candy-luci-capture-victim"
local legacy_path = "/tmp/candy-luci-process.321.123.1"
local file = assert(io.open(victim, "w"))
file:write("untouched")
file:close()
os.remove(legacy_path)
os.execute("ln -s " .. victim .. " " .. legacy_path)

local original_time = os.time
os.time = function() return 123 end
local process = dofile(helper_path)
local ok, output = process.capture({ "/bin/example", "safe" })
os.time = original_time

assert(ok, "pipe capture did not report child success")
assert(#output == 1048576, "capture output was not bounded to 1 MiB")
assert(not temp_accessed, "capture accessed a predictable temporary path")
local victim_file = assert(io.open(victim, "r"))
assert(victim_file:read("*a") == "untouched", "capture modified symlink target")
victim_file:close()
os.remove(legacy_path)
os.remove(victim)
LUA

if grep -R "carrier" "$app_dir" >/dev/null 2>&1; then
	fail "Candy LuCI files must not reference carrier"
fi

printf '%s\n' "OpenWrt Candy LuCI package static test passed"
