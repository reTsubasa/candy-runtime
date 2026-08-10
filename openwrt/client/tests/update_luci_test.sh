#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
controller=$root/packages/luci-app-candy/root/usr/lib/lua/luci/controller/candy_update.lua
view=$root/packages/luci-app-candy/root/usr/lib/lua/luci/view/candy/update.htm
po=$root/packages/luci-app-candy/po/zh-cn/candy.zh-cn.po

for file in "$controller" "$view" "$po"; do [ -s "$file" ]; done
grep -F 'template("candy/update")' "$controller" >/dev/null
grep -F 'REQUEST_METHOD") ~= "POST"' "$controller" >/dev/null
grep -F 'formvalue("token")' "$controller" >/dev/null
grep -F 'value:match("^v[%w_]+$")' "$controller" >/dev/null
grep -F '{ UPDATE_MANAGER, "check" }' "$controller" >/dev/null
grep -F '{ UPDATE_MANAGER, "install-core", version_key }' "$controller" >/dev/null
grep -F '{ UPDATE_MANAGER, "install-core-upload", upload_path }' "$controller" >/dev/null
grep -F '{ UPDATE_MANAGER, "install-runtime", version_key }' "$controller" >/dev/null
grep -F 'luci.http.setfilehandler' "$controller" >/dev/null
grep -F '128 * 1024 * 1024' "$controller" >/dev/null
grep -F 'or "/tmp/candy-core-upload"' "$controller" >/dev/null
grep -F 'tonumber(stat.uid) ~= 0' "$controller" >/dev/null
grep -F 'fs.chmod(CORE_UPLOAD_ROOT, 448)' "$controller" >/dev/null
grep -F 'fs.chmod(upload_path, 384)' "$controller" >/dev/null
! grep -Eq 'formvalue\("(url|sha256|path)"\)' "$controller"
grep -F 'candy-update-runtime' "$view" >/dev/null
grep -F 'candy-update-core' "$view" >/dev/null
grep -F 'candy-update-core-installed' "$view" >/dev/null
grep -F 'data.core_candidates' "$view" >/dev/null
grep -F 'candidates.slice(0, 5)' "$view" >/dev/null
grep -F 'name="version_key"' "$view" >/dev/null
grep -F 'enctype="multipart/form-data"' "$view" >/dev/null
grep -F 'name="core_bundle"' "$view" >/dev/null
grep -F 'update_install_core_upload' "$view" >/dev/null
grep -F 'candy-update-catalog-actions' "$view" >/dev/null
grep -F 'candy-update-section' "$view" >/dev/null
grep -F 'data.core && data.core.installed' "$view" >/dev/null
grep -F 'installed && !active' "$view" >/dev/null
grep -F 'Review Core' "$view" "$po" >/dev/null
grep -F 'setTimeout(refreshCandyUpdateStatus, 2000)' "$view" >/dev/null
grep -F 'never activated automatically' "$view" >/dev/null
grep -F 'Update checks and installations are manual' "$view" >/dev/null
grep -F 'msgid "Updates"' "$po" >/dev/null
grep -F 'msgstr "更新"' "$po" >/dev/null

upload_root=$(mktemp -d)
trap 'rm -rf "$upload_root"' EXIT HUP INT TERM
CANDY_UPDATE_UPLOAD_ROOT=$upload_root lua - "$controller" "$upload_root" <<'LUA'
local controller, upload_root = arg[1], arg[2]
local handler, parsed, upload, token, content_length, status_code, run_call
local chmods = {}

function module() end

local function shell_quote(value)
	return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local fs = {}
function fs.access() return true end
function fs.lstat(path)
	local ok = os.execute("test -d " .. shell_quote(path))
	if ok == true or ok == 0 then return { type = "dir", uid = 0 } end
	local file = io.open(path, "rb")
	if file then file:close(); return { type = "reg" } end
	return nil
end
function fs.mkdirr(path)
	local ok = os.execute("mkdir -p " .. shell_quote(path))
	return ok == true or ok == 0
end
function fs.chmod(path, mode)
	chmods[path] = mode
	local ok = os.execute("chmod " .. string.format("%o", mode) .. " " .. shell_quote(path))
	return ok == true or ok == 0
end
function fs.unlink(path) return os.remove(path) end

package.preload["nixio.fs"] = function() return fs end
package.preload["nixio"] = function() return { getpid = function() return 4242 end } end
package.preload["luci.candy.process"] = function()
	return {
		run = function(arguments, options)
			run_call = { arguments = arguments, options = options }
			return true
		end,
		capture = function() return false end
	}
end

luci = {
	dispatcher = {
		context = { authsession = "csrf-token" },
		build_url = function() return "/updates" end
	},
	http = {
		getenv = function(name)
			if name == "REQUEST_METHOD" then return "POST" end
			if name == "CONTENT_LENGTH" then return content_length end
		end,
		setfilehandler = function(callback) handler = callback end,
		formvalue = function(name)
			if not parsed then
				parsed = true
				if upload then
					handler({ name = upload.name or "core_bundle", file = upload.filename or "core.tar.gz" }, upload.first or "abc", false)
					if upload.parse_error then error("malformed multipart body") end
					handler({ name = upload.name or "core_bundle", file = upload.filename or "core.tar.gz" }, upload.second or "def", true)
				end
			end
			if name == "token" then return token end
		end,
		status = function(code) status_code = code end,
		prepare_content = function() end,
		write = function() end,
		redirect = function() end
	}
}

assert(loadfile(controller))()

local function reset(next_upload, next_token, next_content_length)
	handler, parsed, run_call, status_code = nil, false, nil, nil
	upload, token, content_length = next_upload, next_token, next_content_length
end

reset({ first = "signed-", second = "bundle" }, "csrf-token", "128")
action_install_core_upload()
assert(status_code == nil, "successful upload must not set an error status")
assert(run_call and run_call.arguments[1] == "/usr/libexec/candy-update-manager")
assert(run_call.arguments[2] == "install-core-upload")
local staged = run_call.arguments[3]
assert(type(staged) == "string" and staged:sub(1, #upload_root + 1) == upload_root .. "/")
assert(chmods[upload_root] == 448, "upload root must be mode 0700")
assert(chmods[staged] == 384, "staged upload must be mode 0600")
assert(run_call.options.background == true and run_call.options.append == true)
local file = assert(io.open(staged, "rb")); local body = file:read("*a"); file:close()
assert(body == "signed-bundle", "multipart chunks must be streamed in order")
assert(os.remove(staged))

reset({ first = "untrusted", second = "-bundle" }, "wrong-token", "128")
action_install_core_upload()
assert(status_code == 403, "invalid CSRF token must be rejected")
assert(run_call == nil, "invalid CSRF token must not launch the manager")
for name in io.popen("find " .. shell_quote(upload_root) .. " -type f -print"):lines() do
	error("invalid CSRF upload was not deleted: " .. name)
end

reset({ first = "partial", parse_error = true }, "csrf-token", "128")
action_install_core_upload()
assert(status_code == 400, "malformed multipart input must be rejected")
assert(run_call == nil, "malformed multipart input must not launch the manager")
for name in io.popen("find " .. shell_quote(upload_root) .. " -type f -print"):lines() do
	error("malformed multipart upload was not deleted: " .. name)
end

reset({ first = "unused" }, "csrf-token", tostring(130 * 1024 * 1024))
action_install_core_upload()
assert(status_code == 413, "oversized request must be rejected")
assert(handler == nil and run_call == nil, "oversized request must be rejected before multipart parsing")
LUA

node - "$view" <<'NODE'
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

let source = fs.readFileSync(process.argv[2], "utf8").match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];
source = source.replace(/"<%=[\s\S]*?%>"/g, '"/test"').replace(/<%=[\s\S]*?%>/g, '"translated"');
source = source.replace(/\nrefreshCandyUpdateStatus\(\);\s*$/, "");

class Element {
	constructor(tag) { this.tagName = tag; this.children = []; this.style = {}; this.disabled = false; this._value = ""; this.selectedIndex = -1; this._text = ""; }
	appendChild(child) {
		this.children.push(child);
		if (this.tagName === "select" && this.selectedIndex < 0) { this.selectedIndex = 0; this._value = child.value; }
		return child;
	}
	set textContent(value) { this._text = String(value); this.children = []; if (this.tagName === "select") { this._value = ""; this.selectedIndex = -1; } }
	get textContent() { return this._text; }
	set value(value) {
		if (this.tagName !== "select") { this._value = String(value); return; }
		const index = this.children.findIndex((child) => child.value === String(value));
		this.selectedIndex = index; this._value = index >= 0 ? String(value) : "";
	}
	get value() { return this._value; }
	get options() { return this.children; }
}

const elements = {};
for (const id of ["candy-update-core", "candy-update-core-select", "candy-update-core-install", "candy-update-core-upload", "candy-update-core-installed", "candy-update-runtime", "candy-update-operation", "candy-update-catalog-valid", "candy-update-sequence", "candy-update-published", "candy-update-checked", "candy-update-platform", "candy-update-check"]) {
	elements[id] = new Element(id === "candy-update-core-select" ? "select" : "div");
}
const context = {
	document: { createElement: (tag) => new Element(tag), getElementById: (id) => elements[id] || null },
	console, Date, JSON, Array, String, Number, setTimeout: () => 1, clearTimeout: () => {}
};
vm.createContext(context); vm.runInContext(source, context);
Object.assign(context.candyUpdateLabels, {
	latest: "Latest", current: "Current", installed: "Installed", incompatible: "Incompatible",
	notInstallable: "Not installable", available: "Available", reviewCore: "Review", active: "Active",
	inactive: "Inactive", installedLocally: "Installed locally", noCompatibleCore: "None"
});

const candidates = [
	{ version_key: "v0_3_9", version: "0.3.9", process_api_version: 1, core_api_version: 1, compatible: true, installable: true, latest: true },
	{ key: "v0_3_8", version: "0.3.8", process_api_version: 1, core_api_version: 1, compatible: true, installable: true },
	{ version_key: "v0_3_7", version: "0.3.7", process_api_version: 2, core_api_version: 1, compatible: false, installable: false },
	{ version_key: "v0_3_6", version: "0.3.6", process_api_version: 1, core_api_version: 1, compatible: true, installable: false, installed: true },
	{ version_key: "v0_3_3", version: "0.3.3", process_api_version: 1, core_api_version: 1, compatible: true, installable: true },
	{ version_key: "v0_3_4", version: "0.3.4", process_api_version: 1, core_api_version: 1, compatible: true, installable: true }
];
const data = { core_candidates: candidates, core_current: "0.3.5", core: { installed: [{ version: "0.3.6", active: false }, { version: "0.3.5", active: true }] }, catalog: {}, operation: {} };
context.candyUpdateRenderCore(data, false);
assert.equal(elements["candy-update-core"].children.length, 5, "only five server candidates may be rendered");
assert.deepEqual(elements["candy-update-core-select"].options.map((option) => option.value), ["v0_3_9", "v0_3_8"]);
assert.equal(elements["candy-update-core"].children[3].children[4].children.length, 1, "installed inactive Core must link to review");
elements["candy-update-core-select"].value = "v0_3_8";
context.candyUpdateRenderCore(data, false);
assert.equal(elements["candy-update-core-select"].value, "v0_3_8", "selection must survive status refresh");
context.candyUpdateRenderCore(data, true);
assert.equal(elements["candy-update-core-select"].disabled, true);
assert.equal(elements["candy-update-core-install"].disabled, true);
context.candyUpdateRender({ operation: { state: "running" }, catalog: {} });
assert.equal(elements["candy-update-core-upload"].disabled, true);
NODE

printf '%s\n' "OpenWrt Candy update LuCI contract passed"
