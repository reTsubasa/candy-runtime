local controller = assert(arg[1])
local forms, method, response, calls, downloaded, activated, running, equal, committed, capture_code
local saved = {}
function module() end
package.preload["luci.candy.process"] = function()
	return {
		capture = function(argv, options)
			calls[#calls + 1] = { argv = argv, options = options }
			if argv[1] == "/usr/bin/candy-client" then
				return downloaded, downloaded and "updated cn-ip: 100 IPv4 entries -> target\n" or "Error: invalid CIDR at line 3\n", capture_code
			end
			assert(argv[2] == "reload_runtime", "only a hot reload may activate rules")
			return activated, "reload detail", capture_code
		end,
		run = function(argv, options)
			calls[#calls + 1] = { argv = argv, options = options }
			if argv[2] == "running" then return running end
			assert(argv[1] == "/usr/bin/cmp")
			return equal
		end
	}
end
package.preload["nixio.fs"] = function() return { writefile = function() return true end } end
package.preload["luci.jsonc"] = function() return { stringify = function(value) response = value; return "json" end } end
package.preload["luci.model.uci"] = function()
	return { cursor = function() return {
		get = function() return "https://rules.example/cn.txt" end,
		set = function(_, _, _, option, value) saved[option] = value end,
		commit = function() return committed end
	} end }
end
luci = {
	dispatcher = { context = { authsession = "test-token" } },
	http = {
		getenv = function(name) if name == "REQUEST_METHOD" then return method end end,
		formvalue = function(name) return forms[name] end,
		status = function(code) response = { http_status = code } end,
		header = function() end, prepare_content = function() end, write = function() end
	}
}
dofile(controller)
local function reset()
	forms = { token = "test-token", format = "json", url = "https://rules.example/cn.txt" }
	method, response, calls = "POST", nil, {}
	downloaded, activated, running, equal, committed, capture_code = true, true, true, true, true, nil
	saved = {}
end
reset(); action_geo_update()
assert(response.ok and response.activated and response.code == "provider_updated")
assert(calls[1].argv[2] == "geo" and calls[1].argv[4] == "cn-ip")
assert(calls[1].options.timeout == 60 and calls[3].options.timeout == 90)
assert(saved.geo_update_url == forms.url)
reset(); action_gfwlist_update()
assert(response.ok and calls[1].argv[2] == "dns" and calls[1].argv[4] == "gfwlist")
reset(); downloaded = false; action_geo_update()
assert(not response.ok and response.code == "provider_update_failed" and response.detail == "invalid CIDR at line 3")
assert(#calls == 1 and next(saved) == nil, "rejected downloads must not reload or change the source")
reset(); downloaded = false; capture_code = "process_timeout"; action_geo_update()
assert(response.code == "process_timeout")
reset(); activated = false; action_geo_update()
assert(not response.ok and response.code == "provider_activation_failed" and not response.activated)
reset(); running = false; action_geo_update()
assert(response.ok and not response.activated and response.code == "saved_service_stopped" and #calls == 2)
reset(); equal = false; action_geo_update()
assert(response.ok and not response.activated and response.code == "saved_not_active")
reset(); committed = false; action_geo_update()
assert(not response.ok and response.code == "source_save_failed" and #calls == 1)
reset(); forms.url = "http://rules.example/cn.txt"; action_geo_update()
assert(response.code == "invalid_url" and #calls == 0)
reset(); forms.token = "wrong"; action_geo_update()
assert(response.http_status == 403 and #calls == 0)
reset(); method = "GET"; action_geo_update()
assert(response.http_status == 405 and #calls == 0)
print("Provider manual update success, activation, failures, deadlines and CSRF tests passed")
