module("luci.controller.candy", package.seeall)

local GEO_CN_RULE = "GEOIP,CN,DIRECT,no-resolve"
local GEO_DEFAULT_URL = "https://gaoyifan.github.io/china-operator-ip/china46.txt"
local GFWLIST_DEFAULT_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
local SERVICE_LIFECYCLE_FILE = "/tmp/candy.lifecycle"
local SERVICE_LIFECYCLE_TTL = 10
local PASSIVE_STATUS_FILE = "/var/run/candy/passive-status.json"
local MAX_PASSIVE_STATUS_BYTES = 262144
local SDWAN_STATUS_FILE = "/var/run/candy/sdwan-status.json"
local MAX_SDWAN_STATUS_BYTES = 65536
local SDWAN_RUNTIME = "/usr/libexec/candy-sdwan-runtime"
local SDWAN_BOOTSTRAP_ROOT = os.getenv("CANDY_SDWAN_BOOTSTRAP_ROOT") or "/tmp/candy-sdwan-bootstrap"
local MAX_SDWAN_BOOTSTRAP_BYTES = 16 * 1024
local SERVICE_LOG_FILE = os.getenv("CANDY_SERVICE_LOG_FILE") or "/tmp/candy.log"
local TRAFFIC_LOG_FILE = "/tmp/candy-traffic.log"
local LOG_HISTORY_GENERATIONS = 5
local LOG_READ_LIMIT = 128 * 1024
local LOG_ENTRY_LIMIT = 500
local FAULT_STATUS_FILE = "/var/lib/candy/runtime-fault.json"
local MAX_FAULT_STATUS_BYTES = 16384
local CONGESTION_TEST_LOCK_DIR = "/tmp/candy-congestion-test.lock"
local CONGESTION_TEST_RESULT_FILE = "/tmp/candy-congestion-test.json"
local CONGESTION_TEST_LOG_FILE = "/tmp/candy-congestion-test.log"
local MAX_CONGESTION_TEST_BYTES = 262144
local CORE_MANAGER = "/usr/libexec/candy-core-manager"
local CORE_UPDATE_MANAGER = "/usr/libexec/candy-update-manager"
local MAX_CORE_STATUS_BYTES = 524288
local MAX_UPDATE_STATUS_BYTES = 1024 * 1024
local process = require "luci.candy.process"
local run_argv = process.run

local function atomic_write_file(path, data)
	local nixio = require "nixio"
	local fs = require "nixio.fs"
	local tmp = string.format("%s.tmp.%d.%d", path, nixio.getpid(), os.time())
	if not fs.writefile(tmp, data) then
		return false
	end
	if not fs.rename(tmp, path) then
		fs.unlink(tmp)
		return false
	end
	return true
end

local function normalize_rule(value)
	return (value or ""):gsub("^%s+", ""):gsub("%s+$", ""):gsub("%s*,%s*", ","):upper()
end

local function is_geo_cn_rule(value)
	return normalize_rule(value) == "GEOIP,CN,DIRECT,NO-RESOLVE"
end

local function is_match_rule(value)
	return normalize_rule(value):match("^MATCH,") ~= nil
end

local function trim(value)
	return (value or ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function process_start_time(pid)
	local fs = require "nixio.fs"
	local stat = fs.readfile("/proc/" .. tostring(pid) .. "/stat") or ""
	local rest = stat:match("^%d+ %(.+%) (.+)$")
	local index = 0
	if not rest then return nil end
	for value in rest:gmatch("%S+") do
		index = index + 1
		if index == 20 then return value end
	end
	return nil
end

local function remove_stale_congestion_test_lock()
	local fs = require "nixio.fs"
	if not fs.stat(CONGESTION_TEST_LOCK_DIR) then return false end
	local pid = tonumber(trim(fs.readfile(CONGESTION_TEST_LOCK_DIR .. "/pid") or ""))
	local expected_start = trim(fs.readfile(CONGESTION_TEST_LOCK_DIR .. "/start_time") or "")
	local expected_boot = trim(fs.readfile(CONGESTION_TEST_LOCK_DIR .. "/boot_id") or "")
	local actual_start = pid and process_start_time(pid) or nil
	local actual_boot = trim(fs.readfile("/proc/sys/kernel/random/boot_id") or "")
	if actual_start and expected_start ~= "" and actual_start == expected_start and
		(expected_boot == "" or actual_boot == "" or expected_boot == actual_boot) then
		return false
	end
	fs.unlink(CONGESTION_TEST_LOCK_DIR .. "/pid")
	fs.unlink(CONGESTION_TEST_LOCK_DIR .. "/start_time")
	fs.unlink(CONGESTION_TEST_LOCK_DIR .. "/boot_id")
	fs.rmdir(CONGESTION_TEST_LOCK_DIR)
	return true
end

local function read_node_status()
	local fs = require "nixio.fs"
	local jsonc = require "luci.jsonc"
	return jsonc.parse(fs.readfile("/tmp/candy.nodes") or "") or {}
end

local function contains_credential_field(value)
	if type(value) ~= "table" then
		return false
	end
	for key, nested in pairs(value) do
		if key == "credentials" or key == "secret" or key == "auth" or key == "authentication_key" then
			return true
		end
		if contains_credential_field(nested) then
			return true
		end
	end
	return false
end

local function read_multi_node_passive_status()
	local fs = require "nixio.fs"
	local jsonc = require "luci.jsonc"
	local stat = fs.stat(PASSIVE_STATUS_FILE)
	if not stat or stat.type ~= "reg" or tonumber(stat.size or 0) > MAX_PASSIVE_STATUS_BYTES then
		return nil
	end
	local text = fs.readfile(PASSIVE_STATUS_FILE)
	if not text or #text > MAX_PASSIVE_STATUS_BYTES then
		return nil
	end
	local status = jsonc.parse(text)
	if type(status) ~= "table" or tonumber(status.schema_version) ~= 2 or type(status.nodes) ~= "table" then
		return nil
	end
	if contains_credential_field(status) then
		return nil
	end
	return status
end

local function read_sdwan_status(_uci)
	local fs = require "nixio.fs"
	local jsonc = require "luci.jsonc"
	local unavailable = { active = false, schema_version = 1, phase = "unavailable", registration = { state = "unregistered", cloud_address = "" }, runtime = { state = "unavailable" }, site = nil, segment = nil, tun = { state = "unavailable", full_duplex = nil }, peers = {}, path = nil, egress = { ["local"] = nil, remote = nil }, dns = { state = "unavailable" } }
	local stat = fs.stat(SDWAN_STATUS_FILE)
	local status
	if not stat or stat.type ~= "reg" or tonumber(stat.size or 0) > MAX_SDWAN_STATUS_BYTES then
		return unavailable
	end
	local text = fs.readfile(SDWAN_STATUS_FILE)
	if not text or #text > MAX_SDWAN_STATUS_BYTES then
		unavailable.phase = "unavailable"
		return unavailable
	end
	status = jsonc.parse(text)
	if type(status) ~= "table" or tonumber(status.schema_version) ~= 1 or contains_credential_field(status) then
		unavailable.phase = "unavailable"
		return unavailable
	end
	local function safe_string(value, limit)
		if type(value) ~= "string" or #value > (limit or 256) then return nil end
		return value
	end
	local function safe_identity_object(value)
		if type(value) == "string" then return safe_string(value, 128) end
		if type(value) ~= "table" then return nil end
		local id = safe_string(value.id, 128)
		local name = safe_string(value.name, 128)
		if not id and not name then return nil end
		return { id = id, name = name }
	end
	local registration = type(status.registration) == "table" and status.registration or {}
	local runtime = type(status.runtime) == "table" and status.runtime or {}
	local registration_state = safe_string(registration.state, 32) or "unregistered"
	if registration_state ~= "unregistered" and registration_state ~= "join-pending" and registration_state ~= "registered" then
		registration_state = "unavailable"
	end
	local result = {
		active = runtime.state == "running",
		schema_version = 1,
		phase = registration_state,
		registration = { state = registration_state, cloud_address = safe_string(registration.cloud_address, 2048) or "", last_error = safe_string(registration.last_error, 512) or "" },
		runtime = { state = safe_string(runtime.state, 32) or "unavailable", updated_at = tonumber(runtime.updated_at), last_error = safe_string(runtime.last_error, 512) or "" },
		site = safe_identity_object(status.site),
		segment = safe_identity_object(status.segment),
		tun = { state = "unavailable", full_duplex = nil },
		peers = {},
		path = nil,
		egress = { ["local"] = nil, remote = nil },
		dns = { state = "unavailable" }
	}
	if type(status.tun) == "table" then
		result.tun.state = safe_string(status.tun.state, 32) or "unavailable"
		if type(status.tun.full_duplex) == "boolean" then result.tun.full_duplex = status.tun.full_duplex end
	end
	if type(status.peers) == "table" then
		for _, peer in ipairs(status.peers) do
			if type(peer) == "table" then
				local path
				if type(peer.path) == "table" then
					local kind = safe_string(peer.path.kind, 16)
					if kind == "direct" or kind == "relay" then path = { kind = kind, state = safe_string(peer.path.state, 32) or "unavailable" } end
				end
				result.peers[#result.peers + 1] = { id = safe_string(peer.id, 128) or "", name = safe_string(peer.name, 128), state = safe_string(peer.state, 32) or "unavailable", path = path }
			end
		end
	end
	if type(status.path) == "table" then
		local kind = safe_string(status.path.kind, 16)
		if kind == "direct" or kind == "relay" then result.path = { kind = kind, state = safe_string(status.path.state, 32) or "unavailable" } end
	end
	if type(status.egress) == "table" then
		result.egress["local"] = safe_identity_object(status.egress["local"])
		result.egress.remote = safe_identity_object(status.egress.remote)
	end
	if type(status.dns) == "table" then result.dns.state = safe_string(status.dns.state, 32) or "unavailable" end
	return result
end

local function read_fault_status()
	local fs = require "nixio.fs"
	local jsonc = require "luci.jsonc"
	local stat = fs.stat(FAULT_STATUS_FILE)
	if not stat or stat.type ~= "reg" or tonumber(stat.size or 0) > MAX_FAULT_STATUS_BYTES then
		return nil
	end
	local text = fs.readfile(FAULT_STATUS_FILE)
	if not text or #text > MAX_FAULT_STATUS_BYTES then
		return nil
	end
	local status = jsonc.parse(text)
	if type(status) ~= "table" or tonumber(status.schema_version) ~= 1 then
		return nil
	end
	if type(status.reason) ~= "string" or type(status.cleanup) ~= "string" then
		return nil
	end
	return {
		schema_version = 1,
		state = status.state == "active" and "active" or "unknown",
		reason = status.reason,
		cleanup = status.cleanup,
		detail = type(status.detail) == "string" and status.detail or "",
		updated_at = tonumber(status.updated_at)
	}
end

local function read_core_status()
	local jsonc = require "luci.jsonc"
	local ok, output = process.capture({ CORE_MANAGER, "status" }, { timeout = 3 })
	if not ok or not output or #output > MAX_CORE_STATUS_BYTES then
		return {
			schema_version = 1,
			manager_api_version = 1,
			current_version = nil,
			previous_version = nil,
			current_manifest = nil,
			installed = {},
			error = "Core manager is unavailable"
		}
	end
	local status = jsonc.parse(output)
	if type(status) ~= "table" or tonumber(status.schema_version) ~= 1 or type(status.installed) ~= "table" then
		return {
			schema_version = 1,
			manager_api_version = 1,
			installed = {},
			error = "Core manager returned invalid status"
		}
	end
	return status
end

local function read_core_update_status()
	local jsonc = require "luci.jsonc"
	local ok, output = process.capture({ CORE_UPDATE_MANAGER, "status" }, { timeout = 5 })
	if not ok or not output or #output > MAX_UPDATE_STATUS_BYTES then
		return {
			schema_version = 1,
			core = read_core_status(),
			core_candidates = {},
			error = "Update manager is unavailable"
		}
	end
	local status = jsonc.parse(output)
	if type(status) ~= "table" or tonumber(status.schema_version) ~= 1 or type(status.core_candidates) ~= "table" then
		return {
			schema_version = 1,
			core = read_core_status(),
			core_candidates = {},
			error = "Update manager returned invalid status"
		}
	end
	return status
end

local function mark_service_transition(action)
	local fs = require "nixio.fs"
	local jsonc = require "luci.jsonc"
	local state = action == "stop" and "stopping" or "starting"
	atomic_write_file(SERVICE_LIFECYCLE_FILE, jsonc.stringify({
		action = action,
		state = state,
		updated_at = os.time()
	}))
end

local function read_service_transition()
	local fs = require "nixio.fs"
	local jsonc = require "luci.jsonc"
	local transition = jsonc.parse(fs.readfile(SERVICE_LIFECYCLE_FILE) or "") or {}
	local updated_at = tonumber(transition.updated_at)

	if not updated_at or os.time() - updated_at > SERVICE_LIFECYCLE_TTL then
		fs.unlink(SERVICE_LIFECYCLE_FILE)
		return nil
	end
	return transition
end

local function apply_service_transition(service, transition)
	if not transition or not transition.state then
		return service
	end
	if service == "running" then
		return service
	end
	if service == "stopped" then
		return transition.state == "starting" and "starting" or "stopped"
	end
	if transition.state == "starting" or transition.state == "stopping" then
		return transition.state
	end
	if transition.state == "running" or transition.state == "stopped" then
		return transition.state
	end
	return service
end

local function status_has_starting_node(status)
	for _, node in ipairs(status.nodes or {}) do
		if node.state == "starting" or node.state == "checking" then
			return true
		end
	end
	return false
end

local function candy_service_async(action)
	if action == "restart" then
		action = "restart_queued"
	elseif action == "reload" then
		action = "reload_runtime"
	end
	run_argv({ "/etc/init.d/candy", action }, { background = true })
end

local function candy_service_running()
	return run_argv({ "/etc/init.d/candy", "running" })
end

local function candy_service_status(status)
	local ok, output = process.capture({ "/etc/init.d/candy", "status" })
	local init_status = ok and trim(output) or ""
	if init_status == "running" or candy_service_running() then
		return "running"
	end
	if init_status == "starting" or status_has_starting_node(status or {}) then
		return "starting"
	end
	return "stopped"
end

local function sync_node_states_with_service(status, service)
	local nodes = status.nodes or {}
	if status.runtime and status.runtime.multi_node then
		return
	end

	for _, node in ipairs(nodes) do
		if node.state ~= "disabled" and node.state ~= "unused" then
			if service == "running" then
				node.state = "connecting"
			elseif service == "starting" then
				node.state = "connecting"
			elseif service == "stopping" then
				node.state = "stopping"
			else
				node.state = "down"
			end
		end
	end

	status.nodes = nodes
end

local function merge_multi_node_status(status)
	local runtime = status.runtime or {}
	local multi = runtime.multi_node
	if type(multi) ~= "table" or tonumber(multi.schema_version) ~= 2 or type(multi.nodes) ~= "table" then
		multi = read_multi_node_passive_status()
		if not multi then
			return
		end
		runtime.multi_node = multi
		status.runtime = runtime
	end

	status.nodes = status.nodes or {}
	local configured = {}
	for _, node in ipairs(status.nodes) do
		configured[tostring(node.name or "")] = node
	end

	for name, metrics in pairs(multi.nodes) do
		local node = configured[tostring(name)]
		if not node then
			node = { name = tostring(name), groups = {} }
			status.nodes[#status.nodes + 1] = node
		end
		if type(metrics) == "table" then
			local configured_groups = node.groups
			for key, value in pairs(metrics) do
				if key ~= "groups" or type(value) ~= "table" or #value > 0 then
					node[key] = value
				end
			end
			if type(node.groups) ~= "table" or #node.groups == 0 then node.groups = configured_groups or {} end
			if type(metrics.url_test) ~= "table" then
				local error_text = trim(metrics.url_test_error or "")
				local latency = tonumber(metrics.url_test_latency_ms)
				node.url_test = {
					status = error_text ~= "" and "failed" or (latency and "ok" or "not-run"),
					latency_ms = latency,
					checked_unix_ms = tonumber(metrics.url_test_checked_unix_ms),
					error = error_text
				}
			end
		end
		node.name = tostring(name)
	end

	if type(multi.process) == "table" then
		status.process = multi.process
	end
end

local function current_rules_text()
	local uci = require "luci.model.uci".cursor()
	local rules = {}

	uci:foreach("candy", "rule", function(section)
		if section.value and section.value ~= "" then
			rules[#rules + 1] = trim(section.value)
		end
	end)

	return table.concat(rules, "\n")
end

local RULE_KINDS = {
	["DOMAIN"] = true,
	["DOMAIN-SUFFIX"] = true,
	["DOMAIN-KEYWORD"] = true,
	["GEOIP"] = true,
	["IP-CIDR"] = true,
	["IP-CIDR6"] = true,
	["SRC-IP-CIDR"] = true,
	["SRC-PORT"] = true,
	["DST-PORT"] = true,
	["RULE-SET"] = true,
	["MATCH"] = true
}

local function split_rule_fields(line)
	local fields = {}
	for field in (line .. ","):gmatch("(.-),") do
		fields[#fields + 1] = trim(field)
	end
	return fields
end

local function normalized_rules_text(text)
	local rules = {}
	for line in (text or ""):gmatch("[^\r\n]+") do
		line = trim(line)
		if line ~= "" and not line:match("^#") then
			local fields = split_rule_fields(line)
			local kind = (fields[1] or ""):upper()
			local target_index = kind == "MATCH" and 2 or 3
			fields[1] = kind
			if fields[target_index] and (fields[target_index]:upper() == "DIRECT" or fields[target_index]:upper() == "REJECT") then
				fields[target_index] = fields[target_index]:upper()
			end
			if fields[target_index + 1] and fields[target_index + 1]:lower() == "no-resolve" then
				fields[target_index + 1] = "no-resolve"
			end
			rules[#rules + 1] = table.concat(fields, ",")
		end
	end
	return table.concat(rules, "\n")
end

local function validate_rules_text(uci, text)
	local groups = {}
	local last_kind
	local count = 0
	uci:foreach("candy", "group", function(section)
		local group_name = trim(section.name or section[".name"] or "")
		if group_name ~= "" then
			groups[group_name] = true
		end
	end)

	for line in text:gmatch("[^\r\n]+") do
		local fields = split_rule_fields(line)
		local kind = (fields[1] or ""):upper()
		local target_index = kind == "MATCH" and 2 or 3
		local target = fields[target_index] or ""
		local option = fields[target_index + 1]
		if not RULE_KINDS[kind] or target == "" then
			return false, "malformed"
		end
		if kind ~= "MATCH" and (fields[2] or "") == "" then
			return false, "malformed"
		end
		if #fields > target_index + 1 or (option and option:lower() ~= "no-resolve") then
			return false, "malformed"
		end
		local normalized_target = target:upper()
		if normalized_target ~= "DIRECT" and normalized_target ~= "REJECT" and not groups[target] then
			return false, "invalid_target"
		end
		last_kind = kind
		count = count + 1
	end

	if count == 0 or last_kind ~= "MATCH" then
		return false, "missing_match"
	end
	return true
end

local function sync_geo_bypass_rule(uci)
	local enabled = uci:get("candy", "client", "bypass_china_ip") == "1"
	local keep_geo
	local remove_geo = {}

	uci:foreach("candy", "rule", function(section)
		if is_geo_cn_rule(section.value) then
			if enabled and not keep_geo then
				keep_geo = section[".name"]
			else
				remove_geo[#remove_geo + 1] = section[".name"]
			end
		end
	end)

	for _, section in ipairs(remove_geo) do
		uci:delete("candy", section)
	end

	if enabled and not keep_geo then
		keep_geo = uci:add("candy", "rule")
		uci:set("candy", keep_geo, "value", GEO_CN_RULE)
	end

	if enabled and keep_geo then
		local geo_index
		local first_match_index

		uci:foreach("candy", "rule", function(section)
			local index = tonumber(section[".index"])
			if section[".name"] == keep_geo then
				geo_index = index
			elseif is_match_rule(section.value) and not first_match_index then
				first_match_index = index
			end
		end)

		if geo_index and first_match_index and geo_index > first_match_index then
			uci:reorder("candy", keep_geo, first_match_index)
		end
	end
end

function index()
	if not nixio.fs.access("/etc/config/candy") then
		return
	end

	local page

	page = entry({"admin", "services", "candy"}, firstchild(), _("Candy"), 60)
	page.dependent = false

	page = entry({"admin", "services", "candy", "overview"}, template("candy/status"), _("Overview"), 10)
	page.leaf = true

	page = entry({"admin", "services", "candy", "nodes"}, cbi("candy/nodes"), _("Nodes"), 20)
	page.leaf = true

	page = entry({"admin", "services", "candy", "traffic"}, template("candy/rules"), _("Policy"), 30)
	page.leaf = true

	page = entry({"admin", "services", "candy", "dns_geo"}, cbi("candy/dns"), _("DNS"), 40)
	page.leaf = true

	page = entry({"admin", "services", "candy", "sdwan"}, template("candy/sdwan"), _("SD-WAN"), 50)
	page.leaf = true

	page = entry({"admin", "services", "candy", "logs"}, template("candy/log"), _("Logs"), 60)
	page.leaf = true

	page = entry({"admin", "services", "candy", "updates"}, template("candy/lifecycle"), _("Software updates"), 70)
	page.leaf = true

	page = entry({"admin", "services", "candy", "advanced"}, cbi("candy/advanced"), _("Advanced settings"), 80)
	page.leaf = true

	page = entry({"admin", "services", "candy", "diagnostics"}, template("candy/diagnostics"), _("Diagnostics"), 90)
	page.leaf = true

	-- Keep old bookmarks working while routing Core and update pages to one lifecycle view.
	page = entry({"admin", "services", "candy", "settings"}, template("candy/settings"), nil)
	page.leaf = true

	page = entry({"admin", "services", "candy", "core"}, template("candy/lifecycle"), nil)
	page.leaf = true

	page = entry({"admin", "services", "candy", "update"}, template("candy/lifecycle"), nil)
	page.leaf = true

	entry({"admin", "services", "candy", "action"}, call("action_service")).leaf = true
	entry({"admin", "services", "candy", "runtime_mode"}, call("action_runtime_mode")).leaf = true
	entry({"admin", "services", "candy", "geo_update"}, call("action_geo_update")).leaf = true
	entry({"admin", "services", "candy", "gfwlist_update"}, call("action_gfwlist_update")).leaf = true
	entry({"admin", "services", "candy", "traffic_log_active"}, call("action_traffic_log_active")).leaf = true
	entry({"admin", "services", "candy", "logs_json"}, call("action_logs_json")).leaf = true
	entry({"admin", "services", "candy", "rules_import"}, call("action_rules_import")).leaf = true
	entry({"admin", "services", "candy", "rules_export"}, call("action_rules_export")).leaf = true
	entry({"admin", "services", "candy", "status_json"}, call("action_status_json")).leaf = true
	entry({"admin", "services", "candy", "sdwan_join"}, call("action_sdwan_join")).leaf = true
	entry({"admin", "services", "candy", "sdwan_reconnect"}, call("action_sdwan_reconnect")).leaf = true
	entry({"admin", "services", "candy", "sdwan_leave"}, call("action_sdwan_leave")).leaf = true
	entry({"admin", "services", "candy", "sdwan_start"}, call("action_sdwan_start")).leaf = true
	entry({"admin", "services", "candy", "sdwan_stop"}, call("action_sdwan_stop")).leaf = true
	entry({"admin", "services", "candy", "congestion_test"}, call("action_congestion_test")).leaf = true
	entry({"admin", "services", "candy", "congestion_test_status"}, call("action_congestion_test_status")).leaf = true
	entry({"admin", "services", "candy", "core_status"}, call("action_core_status")).leaf = true
	entry({"admin", "services", "candy", "core_activate"}, call("action_core_activate")).leaf = true
	entry({"admin", "services", "candy", "core_rollback"}, call("action_core_rollback")).leaf = true
	entry({"admin", "services", "candy", "core_remove"}, call("action_core_remove")).leaf = true
	entry({"admin", "services", "candy", "core_install"}, call("action_core_install")).leaf = true
end

local function require_post()
	if luci.http.getenv("REQUEST_METHOD") ~= "POST" then
		luci.http.status(405, "Method Not Allowed")
		return false
	end
	local expected = luci.dispatcher.context.authsession
	if not expected or expected == "" or luci.http.formvalue("token") ~= expected then
		luci.http.status(403, "Forbidden")
		return false
	end
	return true
end

local function start_core_operation(argv)
	local fs = require "nixio.fs"
	if not fs.access(CORE_MANAGER, "x") then
		luci.http.status(503, "Service Unavailable")
		return false
	end
	if not process.run(argv, { background = true, output = "/tmp/candy-core-manager.log" }) then
		luci.http.status(500, "Internal Server Error")
		return false
	end
	if luci.http.getenv("HTTP_X_REQUESTED_WITH") == "XMLHttpRequest" then
		luci.http.status(202, "Accepted")
		luci.http.prepare_content("application/json")
		luci.http.write('{"accepted":true}\n')
		return true
	end
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "candy", "core"))
	return true
end

function action_core_status()
	local jsonc = require "luci.jsonc"
	luci.http.header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	luci.http.prepare_content("application/json")
	luci.http.write(jsonc.stringify(read_core_update_status()))
end

function action_core_install()
	if not require_post() then return end
	local version_key = trim(luci.http.formvalue("version_key") or "")
	if not version_key:match("^v[%w_]+$") or #version_key > 96 then
		luci.http.status(400, "Bad Request")
		return
	end
	local fs = require "nixio.fs"
	if not fs.access(CORE_UPDATE_MANAGER, "x") then
		luci.http.status(503, "Service Unavailable")
		return
	end
	if not process.run({ CORE_UPDATE_MANAGER, "install-core", version_key }, { background = true, output = "/tmp/candy-update-manager.log", append = true }) then
		luci.http.status(500, "Internal Server Error")
		return
	end
	if luci.http.getenv("HTTP_X_REQUESTED_WITH") == "XMLHttpRequest" then
		luci.http.status(202, "Accepted")
		luci.http.prepare_content("application/json")
		luci.http.write('{"accepted":true}\n')
		return
	end
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "candy", "core"))
end

function action_core_activate()
	if not require_post() then return end
	local version = trim(luci.http.formvalue("version") or "")
	if version == "" then
		luci.http.status(400, "Bad Request")
		return
	end
	start_core_operation({ CORE_MANAGER, "activate", version })
end

function action_core_rollback()
	if not require_post() then return end
	start_core_operation({ CORE_MANAGER, "rollback" })
end

function action_core_remove()
	if not require_post() then return end
	local version = trim(luci.http.formvalue("version") or "")
	if version == "" then
		luci.http.status(400, "Bad Request")
		return
	end
	start_core_operation({ CORE_MANAGER, "remove", version })
end

function action_congestion_test()
	if not require_post() then return end
	local fs = require "nixio.fs"
	local jsonc = require "luci.jsonc"
	local uci = require "luci.model.uci".cursor()
	local section = trim(luci.http.formvalue("node") or "")
	local node = section ~= "" and (uci:get("candy", section, "name") or section) or ""
	if section == "" or uci:get("candy", section) ~= "node" or uci:get("candy", section, "enabled") == "0" or node == "" then
		luci.http.status(400, "Bad Request")
		luci.http.prepare_content("application/json")
		luci.http.write(jsonc.stringify({ accepted = false, message = "invalid node" }))
		return
	end
	local live = jsonc.parse(fs.readfile("/var/run/candy/passive-status.json") or "") or {}
	local live_node = type(live.nodes) == "table" and live.nodes[node] or nil
	local major, minor, patch = tostring(live_node and live_node.server_version or ""):match("^(%d+)%.(%d+)%.(%d+)")
	major, minor, patch = tonumber(major), tonumber(minor), tonumber(patch)
	local features = live_node and type(live_node.passive) == "table" and live_node.passive.features or {}
	local probe = type(features) == "table" and features.congestion_probe or {}
	local supported = live_node and live_node.state == "ready" and major and
		(major > 0 or (major == 0 and (minor > 3 or (minor == 3 and patch >= 9)))) and
		probe.supported == true and probe.authorized == true
	if not supported then
		luci.http.status(409, "Conflict")
		luci.http.prepare_content("application/json")
		luci.http.write(jsonc.stringify({ accepted = false, message = "selected node is not ready for congestion comparison or its server test object is unavailable" }))
		return
	end
	remove_stale_congestion_test_lock()
	if fs.stat(CONGESTION_TEST_LOCK_DIR) then
		luci.http.status(409, "Conflict")
		luci.http.prepare_content("application/json")
		luci.http.write(jsonc.stringify({ accepted = false, message = "comparison already running" }))
		return
	else
		fs.unlink(CONGESTION_TEST_RESULT_FILE)
		fs.unlink(CONGESTION_TEST_LOG_FILE)
		if not process.run({ "/etc/init.d/candy", "congestion_test", node }, { background = true, timeout = 600 }) then
			luci.http.status(500, "Internal Server Error")
			luci.http.prepare_content("application/json")
			luci.http.write(jsonc.stringify({ accepted = false, message = "could not start comparison" }))
			return
		end
	end
	luci.http.prepare_content("application/json")
	luci.http.write(jsonc.stringify({ accepted = true, node = node }))
end

function action_congestion_test_status()
	local fs = require "nixio.fs"
	local jsonc = require "luci.jsonc"
	local stat = fs.stat(CONGESTION_TEST_RESULT_FILE)
	local result, state, message
	remove_stale_congestion_test_lock()
	if fs.stat(CONGESTION_TEST_LOCK_DIR) then
		state = "running"
	elseif stat and stat.type == "reg" and tonumber(stat.size or 0) <= MAX_CONGESTION_TEST_BYTES then
		result = jsonc.parse(fs.readfile(CONGESTION_TEST_RESULT_FILE) or "")
		state = type(result) == "table" and "completed" or "error"
	else
		message = trim(fs.readfile(CONGESTION_TEST_LOG_FILE) or "")
		state = message ~= "" and "error" or "idle"
	end
	luci.http.header("Cache-Control", "no-store")
	luci.http.prepare_content("application/json")
	luci.http.write(jsonc.stringify({ state = state, result = result, message = message }))
end

function action_service(action)
	if not require_post() then return end
	local allowed = {
		start = true,
		stop = true,
		restart = true
	}

	if not allowed[action] then
		luci.http.status(400, "Bad Request")
		return
	end

	mark_service_transition(action)
	candy_service_async(action)
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "candy", "overview"))
end

local function redirect_sdwan(result)
	local url = luci.dispatcher.build_url("admin", "services", "candy", "sdwan")
	if result and result ~= "" then url = url .. "?result=" .. result end
	luci.http.redirect(url)
end

local function run_sdwan_lifecycle(stage, argv, timeout)
	local ok, output = process.capture(argv, { timeout = timeout })
	local detail = trim(output or ""):gsub("[\r\n]+", " "):sub(1, 1024)
	local log = io.open(SERVICE_LOG_FILE, "a")
	if log then
		local level = ok and "info" or "error"
		log:write(os.date("%Y-%m-%d %H:%M:%S"), " level=", level,
			" event=sdwan_leave phase=", stage, " pid=luci result=", ok and "ok" or "failed")
		if detail ~= "" then log:write(" detail=", detail) end
		log:write("\n")
		log:close()
	end
	return ok
end

local function allocate_sdwan_bootstrap_path(fs)
	local nixio = require "nixio"
	local prefix = string.format("%s/bootstrap-%d-%d", SDWAN_BOOTSTRAP_ROOT, nixio.getpid(), os.time())
	for suffix = 0, 99 do
		local path = string.format("%s-%d.json", prefix, suffix)
		if not fs.lstat(path) then return path end
	end
	return nil
end

function action_sdwan_join()
	local fs = require "nixio.fs"
	local content_length = tonumber(luci.http.getenv("CONTENT_LENGTH") or "")
	if content_length and content_length > MAX_SDWAN_BOOTSTRAP_BYTES + 64 * 1024 then
		luci.http.status(413, "Payload Too Large")
		return
	end
	local root_stat = fs.lstat(SDWAN_BOOTSTRAP_ROOT)
	if root_stat then
		if root_stat.type ~= "dir" or tonumber(root_stat.uid) ~= 0 then
			luci.http.status(500, "Internal Server Error")
			return
		end
	elseif not fs.mkdirr(SDWAN_BOOTSTRAP_ROOT) then
		luci.http.status(500, "Internal Server Error")
		return
	end
	if not fs.chmod(SDWAN_BOOTSTRAP_ROOT, "0700") then
		luci.http.status(500, "Internal Server Error")
		return
	end

	local temporary
	local upload
	local uploaded = 0
	local complete = false
	local failure
	luci.http.setfilehandler(function(meta, chunk, eof)
		if failure then return end
		if complete then
			failure = "only one bootstrap file is allowed"
			return
		end
		if not upload then
			if not meta or meta.name ~= "bootstrap_file" then
				failure = "unexpected upload field"
				return
			end
			temporary = allocate_sdwan_bootstrap_path(fs)
			if not temporary then
				failure = "could not allocate bootstrap upload"
				return
			end
			upload = io.open(temporary, "wb")
			if not upload or not fs.chmod(temporary, "0600") then
				failure = "could not create bootstrap upload"
				return
			end
		end
		if chunk and #chunk > 0 then
			if uploaded + #chunk > MAX_SDWAN_BOOTSTRAP_BYTES then
				failure = "bootstrap file is too large"
				return
			end
			if not upload:write(chunk) then
				failure = "could not write bootstrap upload"
				return
			end
			uploaded = uploaded + #chunk
		end
		if eof then
			if not upload:flush() then
				failure = "could not flush bootstrap upload"
				return
			end
			upload:close()
			upload = nil
			complete = true
		end
	end)

	local parsed, authorized = pcall(require_post)
	if not parsed then failure = "malformed multipart upload" end
	if not authorized then
		if upload then pcall(function() upload:close() end) end
		if temporary then fs.unlink(temporary) end
		return
	end
	if failure or not complete or not temporary or uploaded == 0 then
		if upload then pcall(function() upload:close() end) end
		if temporary then fs.unlink(temporary) end
		local detail = failure or "empty bootstrap upload"
		local log = io.open(SERVICE_LOG_FILE, "a")
		if log then
			log:write(os.date("%Y-%m-%d %H:%M:%S"), " level=warn event=sdwan_bootstrap pid=luci result=upload-rejected detail=", detail, "\n")
			log:close()
		end
		redirect_sdwan(detail == "bootstrap file is too large" and "file-too-large" or "invalid-file")
		return
	end
	local ok, output = process.capture({ SDWAN_RUNTIME, "bootstrap", temporary }, { timeout = 90 })
	fs.unlink(temporary)
	local detail = trim(output or ""):gsub("[\r\n]+", " "):sub(1, 1024)
	local log = io.open(SERVICE_LOG_FILE, "a")
	if log then
		log:write(os.date("%Y-%m-%d %H:%M:%S"), ok and " level=info event=sdwan_bootstrap pid=luci result=registered" or " level=error event=sdwan_bootstrap pid=luci result=failed detail=", detail, "\n")
		log:close()
	end
	if not ok then
		redirect_sdwan("error")
		return
	end
	redirect_sdwan("joined")
end

function action_sdwan_reconnect()
	if not require_post() then return end
	local status = read_sdwan_status(require "luci.model.uci".cursor())
	if not status.registration or status.registration.state ~= "registered" then
		luci.http.status(409, "Conflict")
		return
	end
	process.run({ "/etc/init.d/candy-cloud-sync", "restart" }, { background = true, timeout = 10 })
	if not process.run({ "/etc/init.d/candy", "sdwan_reconnect" }, { background = true, timeout = 30 }) then
		redirect_sdwan("error")
		return
	end
	redirect_sdwan("reconnecting")
end

function action_sdwan_leave()
	if not require_post() then return end
	if not run_sdwan_lifecycle("stop", { "/etc/init.d/candy", "sdwan_stop", "user_leave" }, 30) then
		redirect_sdwan("leave-stop-failed")
		return
	end
	if not run_sdwan_lifecycle("runtime", { SDWAN_RUNTIME, "leave" }, 20) then
		redirect_sdwan("leave-runtime-failed")
		return
	end
	local log = io.open(SERVICE_LOG_FILE, "a")
	if log then
		log:write(os.date("%Y-%m-%d %H:%M:%S"), " level=info event=sdwan_leave result=completed ordinary_client=preserved\n")
		log:close()
	end
	redirect_sdwan("left")
end

function action_sdwan_start()
	if not require_post() then return end
	local status = read_sdwan_status(require "luci.model.uci".cursor())
	if not status.registration or status.registration.state ~= "registered" then
		luci.http.status(409, "Conflict")
		return
	end
	process.run({ "/etc/init.d/candy-cloud-sync", "restart" }, { background = true, timeout = 10 })
	if not process.run({ "/etc/init.d/candy", "sdwan_start" }, { background = true, timeout = 30 }) then
		redirect_sdwan("error")
		return
	end
	redirect_sdwan("starting")
end

function action_sdwan_stop()
	if not require_post() then return end
	if not run_sdwan_lifecycle("stop", { "/etc/init.d/candy", "sdwan_stop" }, 30) then
		redirect_sdwan("error")
		return
	end
	redirect_sdwan("stopped")
end

function action_runtime_mode()
	if not require_post() then return end
	local uci = require "luci.model.uci".cursor()
	local mode = luci.http.formvalue("runtime_mode") or "fallback"

	if mode ~= "fallback" and mode ~= "stable" and mode ~= "performance" then
		luci.http.status(400, "Bad Request")
		return
	end

	uci:set("candy", "client", "runtime_mode", mode)
	uci:set("candy", "client", "auto_firewall", "1")
	uci:set("candy", "client", "redirect_tcp", "1")
	uci:set("candy", "client", "transparent_tcp_port", "12345")
	uci:set("candy", "client", "dns_capture_lan", "1")
	uci:set("candy", "client", "filter_aaaa", "1")
	uci:set("candy", "client", "dns_remote", "0")

	if mode == "performance" then
		uci:set("candy", "client", "block_quic", "0")
		uci:set("candy", "client", "redirect_udp", "1")
		-- Performance mode is the explicit high-throughput profile. Start with
		-- bounded x2 redundancy; the Core adaptive policy may raise it to x3
		-- after sustained loss evidence and its own capacity budget check.
		uci:set("candy", "client", "udp_client_multiplier", "2")
		uci:set("candy", "client", "udp_server_multiplier", "2")
		uci:set("candy", "client", "transparent_udp_port", "12346")
		uci:set("candy", "client", "tproxy_mark", "100")
	else
		uci:set("candy", "client", "block_quic", "1")
		uci:set("candy", "client", "redirect_udp", "0")
		uci:set("candy", "client", "udp_client_multiplier", "1")
		uci:set("candy", "client", "udp_server_multiplier", "1")
		uci:set("candy", "client", "transparent_udp_port", "12346")
		uci:set("candy", "client", "tproxy_mark", "100")
	end

	uci:commit("candy")
	if candy_service_running() then
		candy_service_async("reload")
	end
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "candy", "overview"))
end

function action_traffic_log_active()
	if not require_post() then return end
	local fs = require "nixio.fs"
	local text = fs.readfile("/tmp/candy-traffic.log") or ""
	local lines = {}
	for line in text:gmatch("[^\r\n]+") do
		local protocol = line:match("^%d%d%d%d%-%d%d%-%d%d %d%d:%d%d:%d%dZ %[(%u+)%] ")
		if protocol == "TCP" or protocol == "UDP" then
			lines[#lines + 1] = line
		end
	end
	local out = {}
	for i = #lines, 1, -1 do
		out[#out + 1] = lines[i]
	end
	luci.http.header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	luci.http.header("Pragma", "no-cache")
	luci.http.prepare_content("text/plain")
	luci.http.write(table.concat(out, "\n"))
end

local function read_log_tail(path)
	local handle = io.open(path, "r")
	if not handle then return "" end
	local size = handle:seek("end") or 0
	local offset = math.max(0, size - LOG_READ_LIMIT)
	handle:seek("set", offset)
	local text = handle:read("*a") or ""
	handle:close()
	if offset > 0 then
		local newline = text:find("\n", 1, true)
		text = newline and text:sub(newline + 1) or ""
	end
	return text
end

local function read_log_history(base)
	local parts = {}
	for generation = LOG_HISTORY_GENERATIONS, 1, -1 do
		local text = read_log_tail(base .. "." .. generation)
		if text ~= "" then parts[#parts + 1] = text end
	end
	local current = read_log_tail(base)
	if current ~= "" then parts[#parts + 1] = current end
	return table.concat(parts, "\n")
end

local function log_level(line)
	local lower = line:lower()
	local explicit = lower:match("level[=:]%s*([a-z]+)") or lower:match("%[([a-z]+)%]")
	if explicit == "err" then explicit = "error" end
	if explicit == "warning" then explicit = "warn" end
	if explicit == "error" or explicit == "warn" or explicit == "info" or explicit == "debug" then return explicit end
	if lower:find("failed", 1, true) or lower:find("error", 1, true) or lower:find("fatal", 1, true) then return "error" end
	if lower:find("warning", 1, true) or lower:find("warn", 1, true) then return "warn" end
	return "info"
end

local function log_timestamp(line)
	return line:match("^(%d%d%d%d%-%d%d%-%d%d[T ]%d%d:%d%d:%d%dZ?)")
		or line:match("^(%a%a%a%s+%d+%s+%d%d:%d%d:%d%d)")
		or ""
end

local function log_field(line, key)
	return line:match("[%s,]" .. key .. "=([^%s,]+)") or line:match("^" .. key .. "=([^%s,]+)")
end

local function append_log_entries(entries, source, text, system_only)
	for line in (text or ""):gmatch("[^\r\n]+") do
		if not system_only or line:lower():find("candy", 1, true) then
			local protocol = source == "traffic" and line:match("^%d%d%d%d%-%d%d%-%d%d %d%d:%d%d:%d%dZ %[(%u+)%]") or nil
			if source ~= "traffic" or protocol == "TCP" or protocol == "UDP" then
				local level = log_level(line)
				local event = protocol or log_field(line, "event") or log_field(line, "operation") or source
				local result = log_field(line, "result") or log_field(line, "status")
				if not result then result = level == "error" and "failed" or (source == "traffic" and "routed" or "recorded") end
				entries[#entries + 1] = {
					timestamp = log_timestamp(line),
					source = source,
					level = level,
					event = event,
					result = result,
					detail = line
				}
			end
		end
	end
end

function action_logs_json()
	local jsonc = require "luci.jsonc"
	local entries = {}
	append_log_entries(entries, "runtime", read_log_history(SERVICE_LOG_FILE))
	local fault = read_fault_status()
	if fault and fault.state == "active" then
		local detail = {}
		if fault.reason and fault.reason ~= "" then detail[#detail + 1] = "reason=" .. fault.reason end
		if fault.cleanup and fault.cleanup ~= "" then detail[#detail + 1] = "cleanup=" .. fault.cleanup end
		if fault.detail and fault.detail ~= "" then detail[#detail + 1] = fault.detail end
		entries[#entries + 1] = {
			timestamp = fault.updated_at and os.date("!%Y-%m-%dT%H:%M:%SZ", fault.updated_at) or "",
			source = "runtime",
			level = "error",
			event = "runtime_fault",
			result = "active",
			detail = table.concat(detail, "; ")
		}
	end
	append_log_entries(entries, "core", read_log_tail("/tmp/candy-core-manager.log"))
	append_log_entries(entries, "update", read_log_tail("/tmp/candy-update-manager.log"))
	append_log_entries(entries, "sdwan", read_log_tail("/etc/candy/sdwan/events-v1.log"))
	append_log_entries(entries, "traffic", read_log_history(TRAFFIC_LOG_FILE))
	local _, system_log = process.capture({ "/sbin/logread", "-l", "250" }, { timeout = 3 })
	append_log_entries(entries, "system", system_log or "", true)
	for index, entry in ipairs(entries) do entry.sequence = index end
	table.sort(entries, function(a, b)
		if a.timestamp ~= b.timestamp then return a.timestamp > b.timestamp end
		return a.sequence > b.sequence
	end)
	while #entries > LOG_ENTRY_LIMIT do table.remove(entries) end
	for _, entry in ipairs(entries) do entry.sequence = nil end
	luci.http.header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	luci.http.header("Pragma", "no-cache")
	luci.http.prepare_content("application/json")
	luci.http.write(jsonc.stringify({ schema_version = 1, entries = entries }))
end

function action_status_json()
	local uci = require "luci.model.uci".cursor()
	local jsonc = require "luci.jsonc"
	local status = read_node_status()
	local runtime = status.runtime or {}
	local transition = read_service_transition()
	merge_multi_node_status(status)
	local service = apply_service_transition(candy_service_status(status), transition)
	sync_node_states_with_service(status, service)

	status.service = {
		status = service,
		running = service == "running",
		starting = service == "starting",
		stopping = service == "stopping",
		transition = transition,
		enabled = luci.sys.init.enabled("candy")
	}
	runtime.mode = runtime.mode or uci:get("candy", "client", "runtime_mode") or "fallback"
	runtime.multi_node = nil
	status.runtime = runtime
	status.sdwan = read_sdwan_status(uci)
	status.fault = read_fault_status()
	status.core = read_core_status()
	status.version = status.version or "0.4.0"
	status.release = status.release or "1"
	status.nodes = status.nodes or {}
	status.diagnostics = status.diagnostics or {}
	local node_count, group_count, rule_count = 0, 0, 0
	uci:foreach("candy", "node", function() node_count = node_count + 1 end)
	uci:foreach("candy", "group", function() group_count = group_count + 1 end)
	uci:foreach("candy", "rule", function() rule_count = rule_count + 1 end)
	status.overview = {
		configured_nodes = node_count,
		groups = group_count,
		rules = rule_count,
		dns_capture = uci:get("candy", "client", "dns_capture_lan") == "1",
		tcp_redirect = uci:get("candy", "client", "redirect_tcp") ~= "0"
	}

	luci.http.header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	luci.http.header("Pragma", "no-cache")
	luci.http.prepare_content("application/json")
	luci.http.write(jsonc.stringify(status))
end

function action_rules_export()
	luci.http.header("Content-Disposition", "attachment; filename=candy-rules.txt")
	luci.http.prepare_content("text/plain")
	luci.http.write(current_rules_text() .. "\n")
end

function action_rules_import()
	if not require_post() then return end
	local uci = require "luci.model.uci".cursor()
	local text = luci.http.formvalue("rules") or ""
	local normalized = normalized_rules_text(text)
	local valid, validation_error = validate_rules_text(uci, normalized)

	if not valid then
		luci.http.redirect(luci.dispatcher.build_url("admin", "services", "candy", "traffic") .. "?rules_error=" .. validation_error)
		return
	end

	if normalized == current_rules_text() then
		luci.http.redirect(luci.dispatcher.build_url("admin", "services", "candy", "traffic") .. "?rules_unchanged=1")
		return
	end

	uci:delete_all("candy", "rule")

	for line in normalized:gmatch("[^\r\n]+") do
		line = line:gsub("^%s+", ""):gsub("%s+$", "")
		if line ~= "" and not line:match("^#") then
			local section = uci:add("candy", "rule")
			uci:set("candy", section, "value", line)
		end
	end

	sync_geo_bypass_rule(uci)
	uci:commit("candy")
	candy_service_async("reload")
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "candy", "traffic"))
end

local function normalize_geo_update_url(value)
	local url = trim(value)
	if url == "" then
		return GEO_DEFAULT_URL
	end
	if url:find("%s") then
		return nil, "invalid"
	end
	if not url:match("^[A-Za-z][A-Za-z0-9+.-]*://") then
		url = "https://" .. url
	end
	if not url:match("^https://[^%s]+$") then
		return nil, "invalid"
	end
	return url
end

local function normalize_gfwlist_update_url(value)
	local url = trim(value)
	if url == "" then
		return GFWLIST_DEFAULT_URL
	end
	if url:find("%s") then
		return nil, "invalid"
	end
	if not url:match("^[A-Za-z][A-Za-z0-9+.-]*://") then
		url = "https://" .. url
	end
	if not url:match("^https://[^%s]+$") then
		return nil, "invalid"
	end
	return url
end

local function redirect_geo(status)
	local url = luci.dispatcher.build_url("admin", "services", "candy", "dns_geo")
	if status and status ~= "" then
		url = url .. "?geo_update_status=" .. status
	end
	luci.http.redirect(url)
end

local function redirect_gfwlist(status)
	local url = luci.dispatcher.build_url("admin", "services", "candy", "dns_geo")
	if status and status ~= "" then
		url = url .. "?gfwlist_update_status=" .. status
	end
	luci.http.redirect(url)
end

function action_geo_update()
	if not require_post() then return end
	local uci = require "luci.model.uci".cursor()
	local url, err = normalize_geo_update_url(luci.http.formvalue("url") or uci:get("candy", "client", "geo_update_url") or GEO_DEFAULT_URL)

	if not url then
		redirect_geo(err)
		return
	end

	uci:set("candy", "client", "geo_update_url", url)
	uci:commit("candy")

	local argv = { "/usr/bin/candy-client", "geo", "update", "cn-ip", "--url", url, "--output", "/etc/candy/rulesets/cn-ip.cidr" }
	if run_argv(argv, { output = "/tmp/candy-geo-update.log", append = true }) then
		candy_service_async("reload")
		redirect_geo("ok")
	else
		redirect_geo("failed")
	end
end

function action_gfwlist_update()
	if not require_post() then return end
	local uci = require "luci.model.uci".cursor()
	local url, err = normalize_gfwlist_update_url(luci.http.formvalue("url") or uci:get("candy", "client", "gfwlist_update_url") or GFWLIST_DEFAULT_URL)

	if not url then
		redirect_gfwlist(err)
		return
	end

	uci:set("candy", "client", "gfwlist_update_url", url)
	uci:commit("candy")

	local argv = { "/usr/bin/candy-client", "dns", "update", "gfwlist", "--url", url, "--output", "/etc/candy/rulesets/gfwlist.domains" }
	if run_argv(argv, { output = "/tmp/candy-gfwlist-update.log", append = true }) then
		candy_service_async("reload")
		redirect_gfwlist("ok")
	else
		redirect_gfwlist("failed")
	end
end
