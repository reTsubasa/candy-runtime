local nixio = require "nixio"
local unpack_args = unpack or table.unpack

local M = {}
local CAPTURE_MAX_BYTES = 1024 * 1024

local function exec_with_timeout(argv, timeout_seconds)
	local timeout = tonumber(timeout_seconds)
	if timeout and timeout > 0 then
		local fs = require "nixio.fs"
		local timeout_bin
		if fs.access("/usr/bin/timeout", "x") then
			timeout_bin = "/usr/bin/timeout"
		elseif fs.access("/bin/timeout", "x") then
			timeout_bin = "/bin/timeout"
		end
		if timeout_bin then
			local args = { timeout_bin, "-s", "KILL", tostring(math.ceil(timeout)) }
			for _, value in ipairs(argv) do
				args[#args + 1] = value
			end
			nixio.exec(unpack_args(args))
			return
		end
	end
	nixio.exec(unpack_args(argv))
end

function M.run(argv, options)
	assert(type(argv) == "table" and #argv > 0, "argv must contain a program")
	options = options or {}
	local pid = nixio.fork()
	if pid == 0 then
		local output = nixio.open(options.output or "/dev/null", "w", "rw-------")
		if output then
			nixio.dup(output, nixio.stdout)
			nixio.dup(output, nixio.stderr)
		end
		for name, value in pairs(options.env or {}) do
			nixio.setenv(name, value, true)
		end
		exec_with_timeout(argv, options.timeout)
		os.exit(127)
	end
	if not pid then
		return false
	end
	if options.background then
		return true
	end
	local _, status, code = nixio.waitpid(pid)
	return status == "exited" and code == 0
end

function M.capture(argv, options)
	assert(type(argv) == "table" and #argv > 0, "argv must contain a program")
	options = options or {}
	local reader, writer = nixio.pipe()
	if not reader or not writer then
		return false, ""
	end
	local pid = nixio.fork()
	if pid == 0 then
		reader:close()
		nixio.dup(writer, nixio.stdout)
		nixio.dup(writer, nixio.stderr)
		writer:close()
		for name, value in pairs(options.env or {}) do
			nixio.setenv(name, value, true)
		end
		exec_with_timeout(argv, options.timeout)
		os.exit(127)
	end
	writer:close()
	if not pid then
		reader:close()
		return false, ""
	end

	local chunks = {}
	local captured = 0
	while true do
		local chunk = reader:read(4096)
		if not chunk or chunk == "" then
			break
		end
		if captured < CAPTURE_MAX_BYTES then
			local keep = math.min(#chunk, CAPTURE_MAX_BYTES - captured)
			chunks[#chunks + 1] = chunk:sub(1, keep)
			captured = captured + keep
		end
	end
	reader:close()
	local _, status, code = nixio.waitpid(pid)
	return status == "exited" and code == 0, table.concat(chunks)
end

return M
