module("luci.controller.candy_update", package.seeall)

local UPDATE_MANAGER = "/usr/libexec/candy-update-manager"
local MAX_STATUS_BYTES = 1024 * 1024
local MAX_CORE_UPLOAD_BYTES = 128 * 1024 * 1024
local CORE_UPLOAD_ROOT = os.getenv("CANDY_UPDATE_UPLOAD_ROOT") or "/tmp/candy-core-upload"
local process = require "luci.candy.process"

function index()
	if not nixio.fs.access("/etc/config/candy") then
		return
	end

	local page = entry({"admin", "services", "candy", "update"}, template("candy/lifecycle"), nil)
	page.leaf = true
	entry({"admin", "services", "candy", "update_status"}, call("action_status")).leaf = true
	entry({"admin", "services", "candy", "update_check"}, call("action_check")).leaf = true
	entry({"admin", "services", "candy", "update_install_core"}, call("action_install_core")).leaf = true
	entry({"admin", "services", "candy", "update_install_core_upload"}, call("action_install_core_upload")).leaf = true
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

local function start_operation(arguments, json_response)
	if not manager_available() then return end
	if not process.run(arguments, { background = true, output = "/tmp/candy-update-manager.log", append = true }) then
		luci.http.status(500, "Internal Server Error")
		return false
	end
	if json_response then
		luci.http.status(202, "Accepted")
		luci.http.prepare_content("application/json")
		luci.http.write('{"accepted":true}\n')
		return true
	end
	luci.http.redirect(luci.dispatcher.build_url("admin", "services", "candy", "update"))
	return true
end

local function prepare_upload_root()
	local fs = require "nixio.fs"
	local stat = fs.lstat(CORE_UPLOAD_ROOT)
	if stat then
		if stat.type ~= "dir" or tonumber(stat.uid) ~= 0 then return false end
	elseif not fs.mkdirr(CORE_UPLOAD_ROOT) then
		return false
	end
	return fs.chmod(CORE_UPLOAD_ROOT, "0700") and true or false
end

local function allocate_upload_path()
	local fs = require "nixio.fs"
	local nixio = require "nixio"
	local prefix = string.format("%s/core-%d-%d", CORE_UPLOAD_ROOT, nixio.getpid(), os.time())
	for suffix = 0, 99 do
		local path = string.format("%s-%d.tar.gz", prefix, suffix)
		if not fs.lstat(path) then return path end
	end
	return nil
end

local function upload_error(status, message, path, file)
	local fs = require "nixio.fs"
	if file then pcall(function() file:close() end) end
	if path then fs.unlink(path) end
	luci.http.status(status, message)
	luci.http.prepare_content("text/plain")
	luci.http.write(message .. "\n")
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

function action_install_core_upload()
	if luci.http.getenv("REQUEST_METHOD") ~= "POST" then
		luci.http.status(405, "Method Not Allowed")
		return
	end
	if not manager_available() then return end
	local content_length = tonumber(luci.http.getenv("CONTENT_LENGTH") or "")
	if content_length and content_length > MAX_CORE_UPLOAD_BYTES + 1024 * 1024 then
		upload_error(413, "Core bundle exceeds the 128 MiB upload limit")
		return
	end
	if not prepare_upload_root() then
		upload_error(500, "Core upload staging directory is unavailable")
		return
	end

	local fs = require "nixio.fs"
	local upload_path
	local upload_file
	local upload_bytes = 0
	local upload_complete = false
	local upload_failure

	luci.http.setfilehandler(function(meta, chunk, eof)
		if upload_failure then return end
		if not meta or meta.name ~= "core_bundle" then
			upload_failure = "Unexpected upload field"
			return
		end
		if upload_complete then
			upload_failure = "Only one Core bundle may be uploaded"
			return
		end
		if not upload_file then
			upload_path = allocate_upload_path()
			if not upload_path then
				upload_failure = "Cannot allocate Core upload staging file"
				return
			end
			upload_file = io.open(upload_path, "wb")
			if not upload_file or not fs.chmod(upload_path, "0600") then
				upload_failure = "Cannot create Core upload staging file"
				return
			end
		end
		if chunk and #chunk > 0 then
			if upload_bytes + #chunk > MAX_CORE_UPLOAD_BYTES then
				upload_failure = "Core bundle exceeds the 128 MiB upload limit"
				return
			end
			if not upload_file:write(chunk) then
				upload_failure = "Cannot write Core upload staging file"
				return
			end
			upload_bytes = upload_bytes + #chunk
		end
		if eof then
			if not upload_file:flush() then
				upload_failure = "Cannot flush Core upload staging file"
				return
			end
			upload_file:close()
			upload_file = nil
			upload_complete = true
		end
	end)

	local parsed, authorized = pcall(require_post)
	if not parsed then
		upload_error(400, "Invalid multipart Core upload", upload_path, upload_file)
		return
	end
	if not authorized then
		upload_error(403, "Forbidden", upload_path, upload_file)
		return
	end
	if upload_failure then
		local status = upload_failure:find("128 MiB", 1, true) and 413 or 400
		upload_error(status, upload_failure, upload_path, upload_file)
		return
	end
	if not upload_complete or not upload_path or upload_bytes == 0 then
		upload_error(400, "A Core bundle is required", upload_path, upload_file)
		return
	end
	local async_upload = luci.http.getenv("HTTP_X_REQUESTED_WITH") == "XMLHttpRequest"
	if not start_operation({ UPDATE_MANAGER, "install-core-upload", upload_path }, async_upload) then
		fs.unlink(upload_path)
	end
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
