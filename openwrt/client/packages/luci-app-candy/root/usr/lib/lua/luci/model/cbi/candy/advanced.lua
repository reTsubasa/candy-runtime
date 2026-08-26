local m, s, o
local process = require "luci.candy.process"
local dispatcher = require "luci.dispatcher"

local BOOTSTRAP_RESOLVERS_DEFAULT = "system,223.5.5.5:53"
local GFWLIST_DEFAULT_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
local GEO_DEFAULT_URL = "https://gaoyifan.github.io/china-operator-ip/china46.txt"

m = Map("candy", translate("Advanced"), translate("Expert DNS, provider, congestion-control, and transparent proxy controls.") ..
	' <a href="' .. dispatcher.build_url("admin", "services", "candy", "settings") .. '">' .. translate("Back to System") .. '</a>')

s = m:section(NamedSection, "client", "candy", translate("DNS expert settings"))
s.addremove = false
s.anonymous = true

o = s:option(ListValue, "dns_mode", translate("Smart DNS mode"))
o:value("smart", translate("Smart DNS"))
o:value("local", translate("System DNS"))
o:value("remote", translate("Remote DNS"))
o.default = "smart"
o.rmempty = false

o = s:option(ListValue, "dns_unknown_strategy", translate("Unknown-domain strategy"))
o:value("parallel-validate", translate("Parallel with GEO validation"))
o:value("prefer-direct", translate("Domestic first"))
o:value("prefer-proxy", translate("Matched node group first"))
o.default = "parallel-validate"
o.rmempty = false

o = s:option(Flag, "dns_answer_geo_validate", translate("Answer GEO validation"))
o.default = "1"
o.rmempty = false

o = s:option(Value, "dns_bootstrap_resolvers", translate("Bootstrap resolvers"))
o.placeholder = BOOTSTRAP_RESOLVERS_DEFAULT
o.default = BOOTSTRAP_RESOLVERS_DEFAULT
o.rmempty = false

o = s:option(Flag, "dns_cache", translate("DNS cache"))
o.default = "1"
o.rmempty = false

o = s:option(Value, "dns_cache_max_entries", translate("Maximum cache entries"))
o.datatype = "range(1,4096)"
o.default = "4096"
o.rmempty = false

o = s:option(Flag, "dns_bind_answers_to_route", translate("Bind answers to routes"))
o.default = "1"
o.rmempty = false

o = s:option(Value, "dns_ttl_cap_seconds", translate("Positive TTL cap (seconds)"))
o.datatype = "range(1,86400)"
o.default = "300"
o.rmempty = false

o = s:option(Value, "dns_negative_ttl_seconds", translate("Negative TTL (seconds)"))
o.datatype = "range(1,3600)"
o.default = "60"
o.rmempty = false

o = s:option(Flag, "filter_aaaa", translate("Filter AAAA records"))
o.default = "1"
o.rmempty = false

s = m:section(NamedSection, "client", "candy", translate("Provider updates"))
s.addremove = false
s.anonymous = true

o = s:option(Value, "gfwlist_update_url", translate("GFWList update URL"))
o.default = GFWLIST_DEFAULT_URL
o.rmempty = false

o = s:option(Flag, "gfwlist_auto_update", translate("Auto update GFWList"))
o.default = "1"
o.rmempty = false

o = s:option(Value, "gfwlist_update_interval_hours", translate("GFWList update interval (hours)"))
o.datatype = "range(1,168)"
o.default = "24"
o.rmempty = false

o = s:option(Value, "geo_update_url", translate("China IP provider URL"))
o.default = GEO_DEFAULT_URL
o.rmempty = false

o = s:option(Flag, "geo_auto_update", translate("Auto update China IP provider"))
o.default = "1"
o.rmempty = false

o = s:option(Value, "geo_update_interval_hours", translate("China IP update interval (hours)"))
o.datatype = "range(1,168)"
o.default = "24"
o.rmempty = false

s = m:section(NamedSection, "client", "candy", translate("Transport and TProxy"))
s.description = translate("Choose one of three Candy BBR profiles. Saving a change restarts Candy so new QUIC connections use the selected parameters.")
s.addremove = false
s.anonymous = true

o = s:option(ListValue, "congestion_profile", translate("Congestion profile"))
o:value("current", translate("Candy BBR - current (1.50 / 0.90, default)"))
o:value("bbr-v1", translate("Candy BBR - BBR v1 (1.25 / 0.75)"))
o:value("aggressive", translate("Candy BBR - aggressive (2.00 / 0.75)"))
o.default = "current"
o.rmempty = false
function o.cfgvalue(self, section)
	local preset = self.map.uci:get("candy", section, "candy_bbr_preset") or "current"
	if preset == "bbr-v1" or preset == "aggressive" then return preset end
	return "current"
end
function o.write(self, section, value)
	self.map.uci:set("candy", section, "congestion", "candy-bbr")
	self.map.uci:set("candy", section, "candy_bbr_preset", value)
end

o = s:option(Flag, "redirect_udp", translate("Proxy LAN UDP/443 with TProxy"))
o.default = "0"
o.rmempty = false
o.readonly = true
o.description = translate("Controlled by Runtime mode. Performance mode enables UDP TProxy; Stable and Fallback modes keep compatibility first.")

o = s:option(Value, "transparent_udp_port", translate("Transparent UDP listen port"))
o.datatype = "port"
o.default = "12346"
o.rmempty = false

o = s:option(Flag, "block_quic", translate("Block LAN UDP/443"))
o.default = "1"
o.rmempty = false
o.readonly = true
o.description = translate("Controlled by Runtime mode. This prevents unstable browser QUIC traffic from making the network appear unavailable.")

o = s:option(Value, "tproxy_mark", translate("TProxy routing mark"))
o.datatype = "uinteger"
o.default = "100"
o.rmempty = false

function m.on_after_commit(self)
	if process.run({ "/etc/init.d/candy", "status" }) then
		process.run({ "/etc/init.d/candy", "restart_queued" }, { background = true })
	end
end

return m
