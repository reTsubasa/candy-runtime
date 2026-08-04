local jsonc = require "luci.jsonc"
local fs = require "nixio.fs"
local process = require "luci.candy.process"

local m, s, o
local GEO_CN_RULE = "GEOIP,CN,DIRECT,no-resolve"
local DOMESTIC_RESOLVERS_DEFAULT = "system,223.5.5.5:53,119.29.29.29:53"
local FOREIGN_RESOLVER_DEFAULT = "8.8.8.8:53"
local PASSIVE_STATUS_FILE = "/var/run/candy/passive-status.json"
local MAX_PASSIVE_STATUS_BYTES = 262144

local function trim(value)
	return (value or ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function normalize_rule(value)
	return trim(value):gsub("%s*,%s*", ","):upper()
end

local function is_geo_cn_rule(value)
	return normalize_rule(value) == "GEOIP,CN,DIRECT,NO-RESOLVE"
end

local function is_match_rule(value)
	return normalize_rule(value):match("^MATCH,") ~= nil
end

local function sync_geo_bypass_rule()
	local uci = require "luci.model.uci".cursor()
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

	uci:commit("candy")
end

local function is_resolver_token(token)
	if token == "system" then
		return true
	end
	if token:match("^[%w._-]+:%d+$") then
		return true
	end
	return token:match("^%[[%x:]+%]:%d+$") ~= nil
end

local function normalize_resolver_list(value)
	local text = trim(value)
	local resolvers = {}
	if text == "" then
		return ""
	end
	for token in text:gmatch("([^,]+)") do
		token = trim(token)
		if token == "" or token:find("%s") or not is_resolver_token(token) then
			return nil
		end
		resolvers[#resolvers + 1] = token
	end
	if #resolvers == 0 or text:match(",$") then
		return nil
	end
	return table.concat(resolvers, ",")
end

local function read_dns_tunnel_status()
	local status = {}
	local rows = {}
	local stat = fs.stat(PASSIVE_STATUS_FILE)
	if stat and stat.type == "reg" and tonumber(stat.size or 0) <= MAX_PASSIVE_STATUS_BYTES then
		status = jsonc.parse(fs.readfile(PASSIVE_STATUS_FILE) or "") or {}
	end
	local nodes = status.nodes
	if type(nodes) ~= "table" or tonumber(status.schema_version) ~= 2 then
		status = jsonc.parse(fs.readfile("/tmp/candy.nodes") or "") or {}
		nodes = ((status.runtime or {}).multi_node or {}).nodes or {}
	end
	for node_name, node in pairs(nodes) do
		for _, tunnel in ipairs(node.dns_tunnels or {}) do
			rows[#rows + 1] = {
				node = tostring(node_name),
				connected = tunnel.connected == true,
				resolver = tostring(tunnel.resolver or "-")
			}
		end
	end
	table.sort(rows, function(left, right) return left.node < right.node end)
	return rows
end

m = Map("candy", translate("DNS & GEO"), translate("Enable Candy DNS and China routing with sensible defaults. Custom DNS servers are optional."))

s = m:section(NamedSection, "client", "candy", translate("DNS & GEO"))
s.addremove = false
s.anonymous = true

o = s:option(Flag, "dns_remote", translate("Use Candy DNS"))
o.description = translate("Send router DNS through Candy. Leave disabled to keep using the router's current DNS path.")
o.default = "0"
o.rmempty = false

o = s:option(Flag, "dns_capture_lan", translate("Capture LAN DNS"))
o.description = translate("Keep LAN DNS requests on the router policy even when devices specify another DNS server.")
o.default = "1"
o.rmempty = false

o = s:option(Flag, "dns_split", translate("GFWList split DNS"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "bypass_china_ip", translate("China direct routing"))
o.default = "1"
o.rmempty = false

o = s:option(Value, "dns_domestic_resolvers", translate("Custom domestic DNS servers"))
o.placeholder = DOMESTIC_RESOLVERS_DEFAULT
o.description = translate("Optional. Separate multiple servers with commas; leave empty to use Candy defaults.")
o.rmempty = true
o.validate = function(self, value)
	local resolvers = normalize_resolver_list(value)
	if resolvers == nil then
		return nil, translate("Invalid input")
	end
	return resolvers
end

o = s:option(Value, "dns_egress_resolver", translate("Custom foreign DNS server"))
o.placeholder = FOREIGN_RESOLVER_DEFAULT
o.description = translate("Optional. This resolver is reached through the selected Candy node; leave empty to use Candy defaults.")
o.rmempty = true
o.validate = function(self, value)
	local resolver = trim(value)
	if resolver ~= "" and (resolver == "system" or not is_resolver_token(resolver)) then
		return nil, translate("Invalid input")
	end
	return resolver
end

s = m:section(NamedSection, "client", "candy", translate("DNS tunnel status"))
s.addremove = false
s.anonymous = true

o = s:option(DummyValue, "_dns_tunnel_status")
o.template = "candy/dns_tunnel_status"
o.rows = read_dns_tunnel_status()

function m.on_after_commit(self)
	sync_geo_bypass_rule()
	if process.run({ "/etc/init.d/candy", "status" }) then
		process.run({ "/etc/init.d/candy", "reload_runtime" }, { background = true })
	end
end

return m
