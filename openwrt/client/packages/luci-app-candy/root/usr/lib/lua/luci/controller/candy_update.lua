module("luci.controller.candy_update", package.seeall)

local UPDATE_MANAGER = "/usr/libexec/candy-update-manager"
local MAX_STATUS_BYTES = 1024 * 1024
local process = require "luci.candy.process"

function index()
	if not nixio.fs.access("/etc/config/candy") then
		return
	end

	local page = entry({"admin", "services", "candy", "update"}, template("candy/update"), _("Updates"), 75)
	page.leaf = true
	entry({"admin", "services", "candy", "update_status"}, call("action_status")).leaf = true
	entry({"admin", "services", "candy", "update_check"}, call("action_check")).leaf = true
	entry({"admin", "services", "candy", "update_install_core"}, call("action_install_core")).leaf = true
	entry({"admin", "services", "candy", "update_install_runtime"}, call("action_install_runtime")).leaf = true
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

local function valid_version_key(value)
	return type(value) == "string" and value:match("^v[%w_]+$") ~= nil and #value <= 96
end

local function manager_available()
	local fs = require "nixio.fs"
	if not fs.access(UPDATE_MANAGER, "x") then
		luci.http.status(503, "Service Unavailable")
		return false
	end
	return true
end

local function start_operation(arguments)
	if not manager_available() then return end
	if not process.run(arguments, { background = true, output = "/tmp/candy-update-manager.log" }) then
		luci.http.status(500, "Internal Server Error")
		return
	end
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "candy", "update"))
end

function action_status()
	local jsonc = require "luci.jsonc"
	local ok, output
	luci.http.header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	luci.http.prepare_content("application/json")
	if not manager_available() then
		luci.http.write(jsonc.stringify({ schema_version = 1, error = "Update manager is unavailable" }))
		return
	end
	ok, output = process.capture({ UPDATE_MANAGER, "status" }, { timeout = 5 })
	if not ok or not output or #output > MAX_STATUS_BYTES then
		luci.http.status(503, "Service Unavailable")
		luci.http.write(jsonc.stringify({ schema_version = 1, error = "Update manager status is unavailable" }))
		return
	end
	local status = jsonc.parse(output)
	if type(status) ~= "table" or tonumber(status.schema_version) ~= 1 then
		luci.http.status(502, "Bad Gateway")
		luci.http.write(jsonc.stringify({ schema_version = 1, error = "Update manager returned invalid status" }))
		return
	end
	luci.http.write(jsonc.stringify(status))
end

function action_check()
	if not require_post() then return end
	start_operation({ UPDATE_MANAGER, "check" })
end

function action_install_core()
	if not require_post() then return end
	local version_key = luci.http.formvalue("version_key") or ""
	if not valid_version_key(version_key) then
		luci.http.status(400, "Bad Request")
		return
	end
	start_operation({ UPDATE_MANAGER, "install-core", version_key })
end

function action_install_runtime()
	if not require_post() then return end
	local version_key = luci.http.formvalue("version_key") or ""
	if not valid_version_key(version_key) then
		luci.http.status(400, "Bad Request")
		return
	end
	start_operation({ UPDATE_MANAGER, "install-runtime", version_key })
end
