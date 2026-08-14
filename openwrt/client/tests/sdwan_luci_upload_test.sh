#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../packages" && pwd)
controller="$root/luci-app-candy/root/usr/lib/lua/luci/controller/candy.lua"
stage=$(mktemp -d "${TMPDIR:-/tmp}/candy-sdwan-luci-upload.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM

CANDY_SDWAN_BOOTSTRAP_ROOT="$stage/uploads" \
CANDY_SERVICE_LOG_FILE="$stage/candy.log" \
lua5.4 - "$controller" "$stage" <<'LUA'
local controller, stage = arg[1], arg[2]
local upload_root = stage .. "/uploads"
assert(os.execute("mkdir -p " .. string.format("%q", upload_root)))

function module() end
local handler
local parsed = false
local status_code
local redirected
local runtime_called = false

local fs = {}
function fs.lstat(path)
	if path == upload_root then return { type = "dir", uid = 0 } end
	return nil
end
function fs.mkdirr() return true end
function fs.chmod() return true end
function fs.unlink(path) return os.remove(path) end
package.preload["nixio.fs"] = function() return fs end
package.preload["nixio"] = function() return { getpid = function() return 4242 end } end
package.preload["luci.candy.process"] = function()
	return {
		run = function() return true end,
		capture = function(arguments)
			if arguments[1] == "/usr/libexec/candy-sdwan-runtime" then
				runtime_called = true
				return false, "invalid bootstrap fixture"
			end
			return false, ""
		end
	}
end

luci = {
	dispatcher = {
		context = { authsession = "csrf-token" },
		build_url = function() return "/sdwan" end
	},
	http = {
		getenv = function(name)
			if name == "REQUEST_METHOD" then return "POST" end
			if name == "CONTENT_LENGTH" then return "512" end
		end,
		setfilehandler = function(callback) handler = callback end,
		formvalue = function(name)
			if not parsed then
				parsed = true
				handler({ name = "bootstrap_file", file = "candy-node-bootstrap.json" }, '{"schema_version":1,', false)
				handler({ name = "bootstrap_file", file = "candy-node-bootstrap.json" }, '"cloud_address":"https://cloud.example.test"}', true)
			end
			if name == "token" then return "csrf-token" end
		end,
		status = function(code) status_code = code end,
		redirect = function(url) redirected = url end
	}
}

assert(loadfile(controller))()
action_sdwan_join()
assert(runtime_called, "a continuation chunk without metadata must reach Runtime")
assert(status_code == nil, "valid multipart streaming must not return a raw HTTP error")
assert(redirected == "/sdwan?result=error", "Runtime rejection must return to the SD-WAN page")

print("OpenWrt Candy SD-WAN multipart upload test passed")
LUA
