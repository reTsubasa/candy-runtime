local m, s, o
local uci = require "luci.model.uci".cursor()
local process = require "luci.candy.process"
local node_options = {}

local function unique_section_id(prefix)
	local suffix = os.time()
	local id = prefix .. tostring(suffix)
	while uci:get("candy", id) do
		suffix = suffix + 1
		id = prefix .. tostring(suffix)
	end
	return id
end

local function option_label(section, display)
	if display and display ~= "" and display ~= section then
		return display .. " (" .. section .. ")"
	end
	return section
end

local function node_is_group_member(node_id)
	local referenced = false
	uci:foreach("candy", "group", function(group)
		local members = uci:get_list("candy", group[".name"], "node") or {}
		for _, member in ipairs(members) do
			if member == node_id then
				referenced = true
				return false
			end
		end
	end)
	return referenced
end

local function group_is_rule_target(group_name)
	local referenced = false
	uci:foreach("candy", "rule", function(rule)
		local fields = {}
		for field in ((rule.value or "") .. ","):gmatch("(.-),") do
			fields[#fields + 1] = field:gsub("^%s+", ""):gsub("%s+$", "")
		end
		local kind = (fields[1] or ""):upper()
		local target = kind == "MATCH" and fields[2] or fields[3]
		if target == group_name then
			referenced = true
			return false
		end
	end)
	return referenced
end

uci:foreach("candy", "node", function(section)
	if section[".name"] and section[".name"] ~= "" then
		node_options[#node_options + 1] = {
			section = section[".name"],
			label = option_label(section[".name"], section.name)
		}
	end
end)

m = Map("candy", translate("Nodes"), translate("Configure the node pool and node groups used by traffic policy rules."))

s = m:section(TypedSection, "node", translate("Node pool"))
s.description = translate("A node is one Candy server endpoint. Node groups reference these nodes, and traffic policy rules select a node group as their outbound.")
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"

function s.create(self, section)
	local id = unique_section_id("node")
	self.map:set(id, nil, self.sectiontype)
	self.map:set(id, "enabled", "1")
	self.map.proceed = true
	return id
end

function s.remove(self, section)
	if node_is_group_member(section) then
		self.map.message = translate("Remove this node from all node groups before deleting it.")
		return
	end
	TypedSection.remove(self, section)
end

o = s:option(Flag, "enabled", translate("Enable"))
o.default = "1"
o.rmempty = false
function o.validate(self, value, section)
	if value == "0" and node_is_group_member(section) then
		return nil, translate("Remove this node from all node groups before disabling it.")
	end
	return value
end

o = s:option(Value, "name", translate("Name"))
o.placeholder = "hk-1"
function o.validate(self, value, section)
	value = (value or ""):gsub("^%s+", ""):gsub("%s+$", "")
	if value == "" then
		return value
	end
	local duplicate = false
	uci:foreach("candy", "node", function(other)
		local other_name = other.name or other[".name"]
		if other[".name"] ~= section and other_name == value then
			duplicate = true
		end
	end)
	if duplicate then
		return nil, translate("Node name must be unique")
	end
	return value
end

o = s:option(Value, "key_id", translate("Key ID"))
o.placeholder = "router-1"

o = s:option(Value, "server", translate("Server address"))
o.datatype = "ipaddrport"
o.placeholder = "203.0.113.10:18443"
o.rmempty = false

o = s:option(Value, "server_name", translate("TLS server name"))
o.datatype = "hostname"
o.placeholder = "example.com"
o.rmempty = false

o = s:option(Value, "server_pin", translate("Server certificate pin"))
o.password = true
o.rmempty = false

o = s:option(Value, "auth", translate("Auth secret"))
o.password = true
o.rmempty = false

o = s:option(DynamicList, "port_hopping_port", translate("Port hopping ports"))
o.description = translate("Add the extra UDP ports configured on the server; leave empty to disable port hopping.")
o.datatype = "port"
o.placeholder = "10443"

o = s:option(Value, "port_hopping_interval_seconds", translate("Port hopping interval"))
o.description = translate("Rotation period in seconds.")
o.datatype = "range(30,86400)"
o.default = 300
o.rmempty = false

s = m:section(TypedSection, "group", translate("Node groups"))
s.description = translate("A node group can carry traffic across multiple nodes. Each new flow is assigned according to the selected algorithm.")
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"
s.sectionhead = translate("Group name")

function s.create(self, section)
	local id = unique_section_id("group")
	self.map:set(id, nil, self.sectiontype)
	self.map:set(id, "type", "round-robin")
	self.map.proceed = true
	return id
end

function s.remove(self, section)
	local group_name = uci:get("candy", section, "name") or section
	if group_is_rule_target(group_name) then
		self.map.message = translate("Update traffic policy rules before deleting this node group.")
		return
	end
	TypedSection.remove(self, section)
end

o = s:option(Value, "name", translate("Group name"))
o.placeholder = "Proxy"
o.rmempty = false
function o.cfgvalue(self, section)
	local value = Value.cfgvalue(self, section)
	if value and value ~= "" then
		return value
	end
	if section:match("^group%d+$") then
		return nil
	end
	return section
end
function o.validate(self, value, section)
	value = (value or ""):gsub("^%s+", ""):gsub("%s+$", "")
	if value == "" then
		return nil, translate("Group name is required")
	end
	if value:upper() == "DIRECT" or value:upper() == "REJECT" then
		return nil, translate("This group name is reserved")
	end
	if value:find(",", 1, true) or value:find("%c") then
		return nil, translate("Group name cannot contain commas or control characters")
	end
	local current_name = uci:get("candy", section, "name") or section
	if value ~= current_name and group_is_rule_target(current_name) then
		return nil, translate("Update traffic policy rules before renaming this node group.")
	end
	local duplicate = false
	uci:foreach("candy", "group", function(other)
		local other_name = other.name or other[".name"]
		if other[".name"] ~= section and other_name == value then
			duplicate = true
		end
	end)
	if duplicate then
		return nil, translate("Group name must be unique")
	end
	return value
end

o = s:option(DynamicList, "node", translate("Nodes"))
for _, node in ipairs(node_options) do
	o:value(node.section, node.label)
end
o.placeholder = "hk-1"
o.rmempty = false
function o.validate(self, value, section)
	local values = type(value) == "table" and value or { value }
	local validated = {}
	for _, node_id in ipairs(values) do
		if node_id and node_id ~= "" then
			if self.map.uci:get(self.config, node_id) ~= "node" then
				return nil, translate("Unknown node")
			end
			if self.map.uci:get(self.config, node_id, "enabled") == "0" then
				return nil, translate("Disabled nodes cannot be added to a group")
			end
			validated[#validated + 1] = node_id
		end
	end
	if #validated == 0 then
		return nil, translate("At least one node is required")
	end
	return type(value) == "table" and validated or validated[1]
end

o = s:option(ListValue, "type", translate("Algorithm"))
o:value("round-robin", translate("Round robin"))
o:value("consistent-hash", translate("Consistent hash"))
o:value("url-test", translate("Lowest latency"))
o:value("fallback", translate("Fallback order"))
o.default = "round-robin"
o.rmempty = false
function o.cfgvalue(self, section)
	local value = ListValue.cfgvalue(self, section)
	if value == "select" then
		return "fallback"
	end
	if value == "load-balance" then
		return "round-robin"
	end
	return value
end

function m.on_after_commit(self)
	if process.run({ "/etc/init.d/candy", "status" }) then
		process.run({ "/etc/init.d/candy", "reload_runtime" }, { background = true })
	end
end

return m
