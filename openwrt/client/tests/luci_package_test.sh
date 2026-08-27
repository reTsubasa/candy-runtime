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
lifecycle_view=luci-app-candy/root/usr/lib/lua/luci/view/candy/lifecycle.htm
diagnostics=luci-app-candy/root/usr/lib/lua/luci/view/candy/diagnostics.htm
dns_tunnel_status=luci-app-candy/root/usr/lib/lua/luci/view/candy/dns_tunnel_status.htm
log_view=luci-app-candy/root/usr/lib/lua/luci/view/candy/log.htm
settings=luci-app-candy/root/usr/lib/lua/luci/view/candy/settings.htm
sdwan=luci-app-candy/root/usr/lib/lua/luci/view/candy/sdwan.htm

assert_file "candy-client/rulesets/cn-ip.cidr"
assert_file "candy-client/rulesets/manifest.json"
assert_file "candy-client/rulesets/gfwlist.domains"
assert_file "candy-client/rulesets/PROVENANCE.md"
assert_file "candy-client/rulesets/SHA256SUMS"
assert_file "candy-client/core-release.pub"
assert_contains "$client_makefile" 'core-release\.pub'
"$repo_root/../../../packaging/openwrt/build/verify_bootstrap_rulesets.sh" "$repo_root/candy-client/rulesets" >/dev/null ||
	fail "bootstrap ruleset validation failed"
assert_contains "$client_makefile" 'rulesets/PROVENANCE\.md'
assert_contains "$client_makefile" 'rulesets/SHA256SUMS'
assert_contains "$config" "geo_update_url 'https://gaoyifan\.github\.io/china-operator-ip/china46\.txt'"
assert_contains "$config" "geo_auto_update '1'"
assert_contains "$config" "gfwlist_auto_update '1'"
assert_contains "$config" "block_quic '0'"
assert_not_contains "$config" "^config node 'hk_1'$"
assert_not_contains "$config" "^[[:space:]]*list node 'hk_1'$"
assert_contains "$config" "^[[:space:]]*option enabled '1'$"
assert_not_contains "$config" "^config[[:space:]][^[:space:]]+[[:space:]]+'[^']*-[^']*'$"
assert_contains "$process_helper" 'exec_with_timeout\(argv, options\.timeout\)'
assert_contains "$controller" 'process\.capture\(\{ CORE_MANAGER, "status" \}, \{ timeout = 3 \}\)'

lua_syntax_file=$(mktemp)
trap 'rm -f "$lua_syntax_file"' EXIT HUP INT TERM
node - "$repo_root" "$lua_syntax_file" "$status" "$sdwan" "$diagnostics" "$settings" "$core_view" "$update_view" "$lifecycle_view" <<'EOF'
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

node - "$repo_root" "$status" "$log_view" <<'EOF'
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const root = process.argv[2];
const statusPath = process.argv[3];
const logPath = process.argv[4];
const source = fs.readFileSync(root + "/" + statusPath, "utf8");
assert.ok(source.includes("Function coverage"), "overview must summarize configured functions");
assert.ok(source.includes("Performance"), "overview must summarize performance");
assert.ok(source.includes("Operating status"), "overview must summarize operating status");
assert.ok(source.includes("candy-metric-throughput"), "overview must expose aggregate RX/TX");
assert.ok(source.includes("goodput_bps_rx") && source.includes("goodput_bps_tx"), "overview must use directional telemetry");
assert.ok(source.includes("active_tcp_flows") && source.includes("active_udp_flows"), "overview must expose active connections");
assert.ok(source.includes("node.last_error"), "overview must expose the latest node result");
assert.ok(source.includes("setTimeout(refresh,2000)"), "overview refresh must avoid overlapping intervals");
assert.ok(source.includes("currentGeneration!==generation"), "overview must ignore stale status responses");
assert.ok(!source.includes("candy-capability-tags"), "overview must not render protocol capability matrices");
assert.ok(source.includes("values.tcp===null&&values.udp===null?labels.unreported"), "missing flow telemetry must not be rendered as zero");
assert.ok(source.includes("node.rx_bps") && source.includes("peer.goodput_bps_rx"), "overview must support flat and nested RX telemetry");
assert.ok(source.includes("node.tx_bps") && source.includes("peer.goodput_bps_tx"), "overview must support flat and nested TX telemetry");
assert.ok(source.includes("Runtime version") && source.includes("Core version"), "overview must label Runtime and Core versions explicitly");
for (const templatePath of [statusPath, logPath]) {
	const template = fs.readFileSync(root + "/" + templatePath, "utf8");
	const scripts = Array.from(template.matchAll(/<script type="text\/javascript">([\s\S]*?)<\/script>/g));
	assert.ok(scripts.length, templatePath + " must contain JavaScript");
	for (const match of scripts) {
		const script = match[1].replace(/<%=([\s\S]*?)%>/g, (_, expression) => expression.includes("build_url") ? "test" : JSON.stringify("test"));
		assert.doesNotThrow(() => new vm.Script(script), templatePath + " JavaScript must parse");
	}
}

const statusScript = source.match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1]
	.replace(/<%=([\s\S]*?)%>/g, (_, expression) => expression.includes("build_url") ? "test" : JSON.stringify("test"));
class Element {
	constructor() { this.children=[]; this.style={}; this.className=""; this._text=""; }
	set textContent(value) { this._text=String(value); this.children=[]; }
	get textContent() { return this.children.length ? this.children.map((child) => child.textContent).join("") : this._text; }
	appendChild(child) { this.children.push(child); return child; }
	setAttribute() {}
}
const elements=new Map(), requests=[];
class FakeXHR {
	constructor() { requests.push(this); this.readyState=0; this.status=0; }
	open() {}
	send() {}
	abort() {}
	respond(data) { this.status=200; this.responseText=JSON.stringify(data); this.readyState=4; this.onreadystatechange(); }
}
const context={ XMLHttpRequest:FakeXHR, Date, JSON, Array, String, Number, isFinite,
	document:{ getElementById(id){ if(!elements.has(id)) elements.set(id,new Element()); return elements.get(id); }, createElement(){ return new Element(); }, createTextNode(value){ const node=new Element(); node.textContent=value; return node; } },
	setTimeout(){ return 1; }, clearTimeout(){} };
vm.runInNewContext(statusScript,context,{filename:statusPath});
requests[0].respond({ version:"0.4.0", release:"75", service:{status:"running",enabled:true}, core:{current_version:"0.3.25"}, runtime:{mode:"fallback"}, sdwan:{phase:"registered",runtime:{state:"running"}}, overview:{configured_nodes:1,groups:1,rules:2,dns_capture:true}, nodes:[{ name:"Hong Kong",state:"ready",groups:["Proxy"],active_tcp_flows:null,active_udp_flows:null,rx_bps:12000,tx_bps:8000,passive:{smoothed_rtt_micros:12500},url_test:{status:"ok",latency_ms:42,error:""},last_error:"" }] });
const cells=elements.get("candy-status-nodes").children[0].children;
assert.equal(cells[2].textContent,"Proxy","configured node groups must remain visible");
assert.equal(cells[3].textContent,"12.5 ms","flat RTT telemetry must render");
assert.equal(cells[4].textContent,"12.0 Kbps / 8.0 Kbps","flat RX/TX telemetry must render");
assert.equal(cells[5].textContent,"test","null flow telemetry must render as Not reported");
assert.equal(cells[6].textContent,"test: 42 ms","successful URL tests must expose their result");
assert.equal(elements.get("candy-metric-flows").textContent,"test","missing aggregate flows must not become zero");
assert.equal(elements.get("candy-metric-throughput").textContent,"12.0 Kbps / 8.0 Kbps");
EOF

node - "$repo_root" "$diagnostics" <<'EOF'
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const root = process.argv[2];
const diagnosticsPath = process.argv[3];
const source = fs.readFileSync(root + "/" + diagnosticsPath, "utf8");
assert.ok(source.includes("Node telemetry"), "diagnostics must render node telemetry");
assert.ok(source.includes("Service resources"), "diagnostics must separate process resources");
assert.ok(source.includes("Node features"), "diagnostics must render node feature cards");
assert.ok(source.includes("Congestion parameter test"), "diagnostics must render the congestion parameter test");
for (const field of ["RTT / jitter", "Quality / packet loss", "RX / TX", "Transport"]) {
	assert.ok(source.includes(field), "diagnostics must expose readable telemetry field: " + field);
}
assert.ok(source.includes("candy-diagnostics-nodes"), "diagnostics must expose the node table");
assert.ok(source.includes("candyDiagnosticsRender"), "diagnostics must own passive refresh rendering");
assert.ok(source.includes('uci:foreach("candy", "node"'), "congestion comparison must use configured Candy nodes");
assert.ok(source.includes("testNodes"), "congestion comparison must label configured nodes");
assert.ok(source.includes("50 MiB"), "congestion comparison must use the node 50 MiB object over Candy QUIC");
assert.ok(source.includes("&node="), "congestion comparison must submit the selected node");
for (const externalPoint of ["vultr-tokyo", "linode-singapore", "hetzner-ashburn", "ovh-france", "serverius-netherlands"]) {
	assert.ok(!source.includes(externalPoint), "external test point remains: " + externalPoint);
}
for (const usefulField of ["Performance trends", "RTT / jitter", "Quality / packet loss", "RX / TX", "Transport"]) {
	assert.ok(source.includes(usefulField), "diagnostics must retain useful transport field: " + usefulField);
}
const sections = ["Service resources", "Performance trends", "Node telemetry", "Node features", "Congestion parameter test"].map(title => "<h3><%:" + title + "%></h3>");
for (let index = 1; index < sections.length; index++) {
	assert.ok(source.indexOf(sections[index - 1]) < source.indexOf(sections[index]), "diagnostics section order must place " + sections[index - 1] + " before " + sections[index]);
}
for (const removedSection of ["Link status", "Freshness", "Bootstrap providers", "Failure recovery", "Overall performance trends"]) {
	assert.ok(!source.includes(removedSection), "diagnostics must remove redundant section: " + removedSection);
}
for (const redundantField of ["Client UDP multiplier", "Server UDP multiplier", "Peer directional goodput", "Peer trust", "Fallback reason"]) {
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
		this.listeners = {};
	}
	set innerHTML(value) { this._textContent = value; this.children = []; }
	get innerHTML() { return this._textContent; }
	set textContent(value) {
		this._textContent = value;
		this.children = [];
	}
	get textContent() {
		return this.children.length ? this.children.map(child => child.textContent).join("") : this._textContent;
	}
	appendChild(child) {
		this.children.push(child);
		return child;
	}
	get firstChild() { return this.children[0] || null; }
	removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
	setAttribute(name, value) { this.attributes[name] = String(value); }
	addEventListener(name, callback) { this.listeners[name] = callback; }
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
	core: { current_manifest: { core: { features: [
		{ id: "metrics", short_name: "Metrics", status_key: "metrics" },
		{ id: "early_data", short_name: "Early data", status_key: "early_data" }
	] } } },
	nodes: ["hk", "sg"].map((name, index) => ({
		id: name,
		name,
		state: "ready",
		server_version: "0.3.25",
		protocol_version: { major: 0, minor: 3 },
		rx_bps: index === 0 ? 12000 : undefined,
		tx_bps: index === 0 ? 8000 : undefined,
		passive: {
			updated_unix_ms: updated + index,
			features: {
				metrics: { supported: true, authorized: true, active: true, evidence: 4 + index },
				early_data: { supported: true, authorized: index === 0, active: false, evidence: index }
			},
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
assert.equal(rows[0].children[0].children[0].textContent, "hk");
assert.match(rows[0].children[2].textContent, /12\.35 ms/);
assert.match(rows[0].children[2].textContent, /2\.00 ms/);
assert.equal(rows[0].children.length, 6, "diagnostics must keep the node table compact");
assert.notEqual(rows[0].children[1].textContent, "-", "node status must remain visible");
assert.equal(context.candyDiagnosticsPacketLoss(0), "test", "zero packet loss must have an explicit label");
assert.equal(context.candyDiagnosticsGoodput(0), "test", "zero throughput must be labelled idle");
assert.equal(context.candyDiagnosticsGoodput(null), "test", "missing throughput must be labelled not reported");
assert.match(rows[0].children[4].textContent, /12\.0 Kbps/);
assert.match(rows[0].children[4].textContent, /8\.0 Kbps/);
assert.match(rows[0].children[5].textContent, /Candy BBR/);
assert.match(rows[0].children[5].textContent, /32\.0 KiB.*64\.0 KiB.*50 %/);
for (const phase of ["startup", "drain", "probe-bw", "probe-bw-refill", "probe-bw-up", "probe-bw-down", "probe-bw-cruise", "probe-rtt"]) {
	assert.equal(context.candyDiagnosticsMappedText(context.candyDiagnosticsLabels.congestionModes, phase), "test");
}
assert.equal(context.candyDiagnosticsMappedText(context.candyDiagnosticsLabels.congestionModes, "future-phase"), "future-phase",
	"unknown future congestion phases must remain visible");
assert.match(rows[1].children[5].textContent, /CUBIC/, "passive diagnostics must show the effective CUBIC controller");
assert.equal(rows[1].children[0].children[0].textContent, "sg");
const featureCards = elements.get("candy-diagnostics-feature-cards").children;
assert.equal(featureCards.length, 2, "diagnostics must render one feature card per node");
assert.match(featureCards[0].textContent, /hk/);
assert.match(featureCards[0].textContent, /Core 0\.3\.25/);
assert.match(featureCards[0].textContent, /Metrics/);
assert.match(featureCards[0].textContent, /Early data/);
const hkFeatures = featureCards[0].children[1].children;
const sgFeatures = featureCards[1].children[1].children;
assert.equal(hkFeatures.length, 2, "each manifest feature must render once");
assert.match(hkFeatures[0].className, /active/, "active features must use the green state");
assert.match(hkFeatures[1].className, /available/, "authorized inactive features must use the blue state");
assert.match(sgFeatures[1].className, /limited/, "unauthorized negotiated features must use the yellow state");
assert.match(hkFeatures[0].attributes.title, /test.*test.*test.*test 4/, "feature details must remain available in the tooltip");
assert.equal(hkFeatures[0].children.length, 2, "feature tiles must contain only the status icon and name");
assert.ok(!source.includes("candy-feature-badges"), "feature cards must not render inline status badges");
assert.ok(!source.includes("candy-feature-evidence"), "feature cards must not render evidence as a separate row");

context.refreshCandyDiagnosticsStatus();
requests[3].respond(200, { runtime: { performance: {} } });
assert.equal(elements.get("candy-diagnostics-nodes").children.length, 1, "missing status must replace stale rows");
assert.equal(elements.get("candy-diagnostics-process-rss").textContent, "-");
assert.equal(timers.length, 1, "only one diagnostics follow-up refresh timer may be scheduled");
EOF

for file in "$makefile" "$config" "$init" "$po" "$po2lmo_c" "$po2lmo_lmo" "$po2lmo_h" "$process_helper" "$controller" "$nodes" "$dns" "$advanced" "$rules" "$status" "$core_view" "$update_view" "$lifecycle_view" "$diagnostics" "$dns_tunnel_status" "$log_view" "$settings" "$sdwan"; do
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
assert_contains "$makefile" '^PKG_RELEASE:=82$'
assert_contains "$client_makefile" '^PKG_RELEASE:=82$'
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

assert_not_contains "$config" "option value 'GEOIP,CN,DIRECT,no-resolve'"
assert_not_contains "$config" "option value 'MATCH,Proxy'"
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
	"SD-WAN" \
	"Policy" \
	"Settings" \
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
for route in overview sdwan traffic settings dns_geo nodes diagnostics logs updates advanced core; do
	assert_contains "$controller" "\"$route\""
done
assert_contains "$controller" '\{"admin", "services", "candy", "overview"\}.*_\("Overview"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "sdwan"\}.*_\("SD-WAN"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "traffic"\}.*_\("Policy"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "nodes"\}.*_\("Nodes"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "dns_geo"\}.*_\("DNS"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "logs"\}.*_\("Logs"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "updates"\}.*_\("Software updates"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "advanced"\}.*_\("Advanced settings"\)'
assert_contains "$controller" '\{"admin", "services", "candy", "diagnostics"\}.*_\("Diagnostics"\)'
for hidden_route in settings core update; do
	assert_contains "$controller" "\{\"admin\", \"services\", \"candy\", \"$hidden_route\"\}.*nil"
done
assert_count "$controller" '\{"admin", "services", "candy", "(overview|nodes|traffic|dns_geo|sdwan|logs|updates|advanced|diagnostics)"\}.*_\("(Overview|Nodes|Policy|DNS|SD-WAN|Logs|Software updates|Advanced settings|Diagnostics)"\)' 9
assert_not_contains "$controller" '\{"admin", "services", "candy", "status"\}'
assert_not_contains "$controller" '\{"admin", "services", "candy", "rules"\}'
assert_not_contains "$controller" '\{"admin", "services", "candy", "geo"\}'
assert_not_contains "$controller" '\{"admin", "services", "candy", "dns"\}'
assert_not_contains "$controller" '\{"admin", "services", "candy", "client"\}'
assert_contains "$controller" 'action_rules_import'
assert_contains "$controller" 'action_rules_export'
assert_contains "$controller" 'action_status_json'
for action in core_status core_activate core_rollback core_remove core_install; do
	assert_contains "$controller" "action_$action"
done
assert_contains "$controller" 'status\.core = read_core_status\(\)'
assert_contains "$controller" 'CORE_MANAGER = "/usr/libexec/candy-core-manager"'
assert_contains "$controller" 'CORE_UPDATE_MANAGER = "/usr/libexec/candy-update-manager"'
assert_contains "$controller" 'CORE_UPDATE_MANAGER, "status"'
assert_contains "$controller" 'CORE_UPDATE_MANAGER, "install-core", version_key'
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
assert_contains "$controller" 'action_logs_json'
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
assert_contains "$status" 'candy-status-service'
assert_contains "$controller" 'status\.runtime\.multi_node'
assert_contains "$controller" 'node.state = "connecting"'
assert_contains "$controller" 'rules_unchanged'
assert_not_contains "$controller" 'local argv = \{ "/usr/bin/candy-client", "--config", "/var/run/candy/runtime\.json"'
assert_not_contains "$controller" 'link probe'
assert_not_contains "$controller" 'cdn_probe'
assert_not_contains "$controller" '/tmp/candy-traffic-log\.enabled'
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
assert_contains "$controller" 'local configured_groups = node\.groups'
assert_contains "$controller" 'key ~= "groups" or type\(value\) ~= "table" or #value > 0'
assert_contains "$dns" 'normalize_resolver_list'
assert_contains "$dns" 'local node_uci = require "luci.model.uci".cursor\(\)'
assert_contains "$dns" 'node_uci:foreach\("candy", "node"'
assert_contains "$sdwan" 'How traffic is selected'
assert_contains "$lifecycle_view" '<%:Software updates%>'
assert_contains "$lifecycle_view" '<%\+candy/update%>'
assert_contains "$lifecycle_view" '<%\+candy/core%>'
assert_contains "$update_view" '<%:Runtime updates%>'
assert_contains "$core_view" '<%:Core lifecycle%>'
assert_contains "$sdwan" 'Candy SD-WAN connects sites through encrypted links'
assert_contains "$sdwan" 'local_egress_configured'
assert_contains "$sdwan" 'remote_egress_configured'
assert_contains "$sdwan" 'dns_configured'
assert_not_contains "$sdwan" 'Unavailable until Candy Cloud publishes'
assert_contains "$sdwan" '<%:Peer site%>'
assert_not_contains "$sdwan" '<%:Attachment ID%>'
assert_not_contains "$sdwan" 'Unnamed peer|Unnamed site|Unnamed network|short_id'
assert_contains "$sdwan" 'human_name\(peer\.name\)'
assert_contains "$sdwan" 'isUuid\(peer\.name\)'
assert_not_contains "$sdwan" 'String\(peer\.id\)\.slice'
assert_contains "$sdwan" 'candy-sdwan-long'
assert_contains "$sdwan" 'text-overflow:ellipsis'
assert_not_contains "$sdwan" 'candy-sdwan-arrow|&rarr;|&#8594;'
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
assert_not_contains "$controller" 'CONGESTION_TEST_POINTS'
assert_contains "$controller" 'formvalue\("node"\)'
assert_contains "$controller" 'uci:get\("candy", section\) ~= "node"'
assert_contains "$controller" 'uci:get\("candy", section, "name"\) or section'
assert_contains "$controller" '"congestion_test", node'
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
assert_contains "$init" 'node_id=\$\{1:-\}'
assert_contains "$init" 'congestion-test --node "\$node_id" --samples 1 --max-bytes 52428800 --timeout-ms 120000'
assert_contains "$init" 'congestion-test --help'
assert_contains "$init" 'update Core to 0\.3\.9 or newer'
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


assert_contains "$core_view" 'core_status'
assert_contains "$core_view" 'core_install'
assert_not_contains "$core_view" 'Install Core bundle'
assert_not_contains "$core_view" 'Bundle URL'
assert_not_contains "$core_view" 'candy-core-install-submit'
assert_contains "$core_view" 'core_activate'
assert_contains "$core_view" 'core_rollback'
assert_contains "$core_view" 'core_remove'
assert_contains "$core_view" 'removeCurrentConfirm'
assert_contains "$core_view" 'core\.service_running === false'
assert_not_contains "$core_view" 'data\.service_running === false'
assert_contains "$core_view" 'core\.current_manifest'
assert_contains "$core_view" 'process_api_version'
assert_contains "$core_view" 'protocol_version'
assert_contains "$core_view" 'target_arch'
assert_contains "$core_view" 'candyCoreBindForm'
assert_contains "$core_view" 'event\.preventDefault\(\)'
assert_contains "$core_view" 'X-Requested-With'
assert_not_contains "$core_view" 'location\.reload'
assert_contains "$controller" 'HTTP_X_REQUESTED_WITH.*XMLHttpRequest'
assert_not_contains "$update_view" 'data\.core && data\.core\.installed'
assert_not_contains "$update_view" 'candy-update-core-installed'
assert_contains "$update_view" 'candyUpdateCorePageUrl'
assert_contains "$update_view" 'updates.*#candy-core-lifecycle'
assert_contains "$core_view" 'id="candy-core-lifecycle"'
assert_contains "$update_view" 'data\.core_candidates'
assert_contains "$update_view" 'candidate\.update_available === true'
assert_contains "$update_view" 'candidates\.slice\(0, 5\)'
assert_contains "$update_view" 'name="version_key"'
assert_contains "$update_view" 'enctype="multipart/form-data"'
assert_contains "$update_view" 'name="core_bundle"'
assert_contains "$update_view" 'installed && !active'
assert_not_contains "$update_view" 'installedLocally'
assert_not_contains "$update_view" 'candidate\.active === true \|\|'
assert_contains "$update_view" 'candyUpdateLink'
assert_not_contains "$update_view" 'rollbackAvailable'
assert_not_contains "$update_view" 'candyUpdateLabels\.incompatible'
assert_contains "$status" 'status_json'
assert_contains "$status" '<%:Function coverage%>'
assert_contains "$status" '<%:Performance%>'
assert_contains "$status" 'candy-summary-band'
assert_contains "$status" 'candy-summary-item > span'
assert_contains "$status" 'candy-feature-band'
assert_contains "$status" 'candy-metric-throughput'
assert_contains "$status" 'candy-node-state'
assert_contains "$status" 'goodput_bps_rx'
assert_contains "$status" 'goodput_bps_tx'
assert_contains "$status" 'active_tcp_flows'
assert_contains "$status" 'active_udp_flows'
assert_contains "$status" 'node\.last_error'
assert_contains "$status" '<%:RX / TX%>'
assert_contains "$status" '<%:Connections%>'
assert_contains "$status" '<%:Latest result%>'
assert_contains "$status" 'setTimeout\(refresh,2000\)'
assert_not_contains "$status" 'candy-capability-tag|candyOverviewCapabilityTags|protocol capability'

assert_count "$diagnostics" '<div class="cbi-map candy-diagnostics-section">' 5
assert_contains "$diagnostics" '<%:Diagnostics%>'
assert_contains "$diagnostics" '<%:Service resources%>'
assert_contains "$diagnostics" '<%:Performance trends%>'
assert_contains "$diagnostics" '<%:Node telemetry%>'
assert_contains "$diagnostics" '<%:Node features%>'
assert_contains "$diagnostics" '<%:Congestion parameter test%>'
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
assert_contains "$diagnostics" 'passive\.peer'
assert_contains "$diagnostics" 'goodput_bps_rx'
assert_contains "$diagnostics" 'goodput_bps_tx'
assert_contains "$diagnostics" '<%:RTT / jitter%>'
assert_contains "$diagnostics" '<%:Quality / packet loss%>'
assert_contains "$diagnostics" '<%:RX / TX%>'
assert_contains "$diagnostics" '<%:Transport%>'
assert_contains "$diagnostics" 'candyDiagnosticsPacketLoss'
assert_contains "$diagnostics" 'candyDiagnosticsLabels\.notReported'
assert_contains "$diagnostics" 'candy-resource-band'
assert_not_contains "$diagnostics" 'candyDiagnosticsFreshness|<%:Freshness%>|candy-diagnostics-link-summary|<%:Link status%>'
assert_not_contains "$diagnostics" '<%:Bootstrap providers%>|candy-diagnostics-geo-state|candy-diagnostics-gfwlist-state'
assert_not_contains "$diagnostics" '<%:Failure recovery%>|candy-diagnostics-fault-state|candyDiagnosticsRenderRecovery'
assert_contains "$diagnostics" 'content: attr\(data-label\)'
assert_contains "$diagnostics" 'overflow-wrap: anywhere'
assert_contains "$diagnostics" 'text-overflow: ellipsis'
assert_not_contains "$diagnostics" 'candy-topology|candyDiagnosticsRenderTopology|&rarr;|&#8594;'
assert_not_contains "$diagnostics" 'client_udp_multiplier'
assert_not_contains "$diagnostics" 'server_udp_multiplier'
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
assert_contains "$diagnostics" 'translate\("Jitter"\)'
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
assert_contains "$diagnostics" 'translate\("Goodput"\)'
assert_contains "$diagnostics" 'translate\("Estimated capacity"\)'
assert_contains "$diagnostics" 'translate\("Idle"\)'
assert_contains "$diagnostics" 'bandwidth_estimate_bps'
assert_contains "$diagnostics" 'candyDiagnosticsGoodput'
assert_contains "$diagnostics" 'candy-diagnostics-feature-cards'
assert_contains "$diagnostics" 'candyDiagnosticsRenderFeatureCards'
assert_not_contains "$diagnostics" 'candy-feature-matrix-section|candyDiagnosticsRenderFeatureMatrix'
assert_not_contains "$diagnostics" 'carrier'

assert_not_contains "$diagnostics" '<%\+candy/log_panel%>'
assert_contains "$log_view" '<%:All sources%>'
assert_contains "$log_view" '<%:All levels%>'
assert_contains "$log_view" '<%:User traffic%>'
assert_contains "$log_view" 'candy-log-search'
assert_contains "$log_view" 'candy-log-auto'
assert_contains "$log_view" 'logs_json'
assert_contains "$log_view" 'entry\.source'
assert_contains "$log_view" 'entry\.level'
assert_contains "$log_view" 'entry\.result'
assert_contains "$log_view" 'entry\.detail'
assert_contains "$log_view" 'setTimeout\(refresh,3000\)'
assert_contains "$log_view" 'currentGeneration!==generation'
assert_not_contains "$log_view" '<textarea'
assert_contains "$controller" 'LOG_ENTRY_LIMIT = 500'
assert_contains "$controller" '/tmp/candy-core-manager\.log'
assert_contains "$controller" '/tmp/candy-update-manager\.log'
assert_contains "$controller" '/etc/candy/sdwan/events-v1\.log'
assert_contains "$controller" 'append_log_entries\(entries, "traffic"'
assert_contains "$controller" 'append_log_entries\(entries, "system"'
assert_contains "$controller" 'event = "runtime_fault"'
assert_contains "$controller" 'fault\.state == "active"'
assert_contains "$controller" 'event = event'
assert_contains "$controller" 'result = result'

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

node - "$repo_root/$core_view" <<'NODE'
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

let source = fs.readFileSync(process.argv[2], "utf8").match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];
source = source.replace(/"<%=[\s\S]*?%>"/g, '"/test"').replace(/<%=[\s\S]*?%>/g, '"translated"');
source = source.replace(/\nrefreshCandyCoreStatus\(\);\s*$/, "");

class Element {
	constructor(tag) { this.tagName = tag; this.children = []; this.style = {}; this.disabled = false; this._text = ""; this.dataset = {}; this.listeners = {}; this.action = "/core"; }
	appendChild(child) { this.children.push(child); return child; }
	set innerHTML(value) { this._textContent = value; this.children = []; }
	get innerHTML() { return this._textContent; }
	set textContent(value) { this._text = String(value); this.children = []; }
	get textContent() { return this._text; }
	addEventListener(name, handler) { this.listeners[name] = handler; }
	getElementsByTagName(tag) { return this.children.filter((child) => child.tagName === tag); }
}

const elements = {};
for (const id of ["candy-core-operation", "candy-core-rollback", "candy-core-installed", "candy-core-current", "candy-core-previous", "candy-core-process-api", "candy-core-api", "candy-core-protocol", "candy-core-architecture"]) elements[id] = new Element("div");
const context = {
	document: { createElement: (tag) => new Element(tag), getElementById: (id) => elements[id] || null },
	window: { confirm: () => true }, console, Date, JSON, Array, String,
	XMLHttpRequest: class {}, setTimeout: () => 1, clearTimeout: () => {}
};
vm.createContext(context); vm.runInContext(source, context);
Object.assign(context.candyCoreLabels, {
	latest: "Latest", current: "Current", installed: "Installed", yes: "Yes", no: "No",
	activate: "Activate", remove: "Remove", downloadLatest: "Download latest Core", none: "None",
	removed: "Core %s was removed", activated: "Core %s is active", installedCore: "Core %s was installed",
	downloadingCore: "Downloading and validating Core", coreReady: "Core installed; activation remains manual"
});

const data = {
	operation: {},
	core: {
		current_version: "0.3.9", previous_version: "0.3.8", service_running: false,
		operation: { state: "completed", action: "remove", version: "0.3.7", message: "untranslated internal message" },
		installed: [
			{ version: "0.3.9", active: true, rollback: false, managed: true },
			{ version: "0.3.8", active: false, rollback: true, managed: true },
			{ version: "0.3.7", active: false, rollback: false, managed: true }
		]
	},
	core_candidates: [
		{ version_key: "v0_3_10", version: "0.3.10", latest: true, installed: false, active: false, compatible: true, installable: true },
		{ version_key: "v0_3_9", version: "0.3.9", latest: false, installed: true, active: true },
		{ version_key: "v0_3_8", version: "0.3.8", latest: false, installed: true, active: false }
	]
};
context.candyCoreRender(data);
const rows = elements["candy-core-installed"].children;
assert.equal(rows.length, 3, "Core page must only render locally installed versions");
assert.deepEqual(rows.map((row) => row.children[1].children[0].children.map((tag) => tag.textContent)), [["Current"], ["Installed"], ["Installed"]]);
assert.deepEqual([...new Set(rows.flatMap((row) => row.children[1].children[0].children.map((tag) => tag.textContent)))].sort(), ["Current", "Installed"]);
assert.deepEqual(rows[0].children[3].children.map((form) => form.children[2].textContent), ["Remove"], "stopped current Core must be removable");
assert.deepEqual(rows[1].children[3].children.map((form) => form.children[2].textContent), ["Activate", "Remove"], "rollback Core must be removable");
assert.equal(elements["candy-core-operation"].textContent, "Core 0.3.7 was removed", "completed removal must use the localized operation template");

data.operation = { state: "completed", action: "install-core", version_key: "v0_3_10", updated_at: 2, message: "untranslated update message" };
data.core.operation.updated_at = 1;
context.candyCoreRender(data);
assert.equal(elements["candy-core-operation"].textContent, "Core installed; activation remains manual", "completed catalog download must use the localized operation template");

data.core.service_running = true;
context.candyCoreRender(data);
assert.equal(elements["candy-core-installed"].children[0].children[3].children.length, 0, "running current Core must not expose removal");
NODE

if grep -R "carrier" "$app_dir" >/dev/null 2>&1; then
	fail "Candy LuCI files must not reference carrier"
fi

printf '%s\n' "OpenWrt Candy LuCI package static test passed"
