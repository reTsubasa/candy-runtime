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
		-- Minimal OpenWrt images may omit the timeout applet. Supervise a
		-- separate process group so the deadline also stops its descendants.
		local pid = nixio.fork()
		if pid == 0 then
			nixio.setsid()
			nixio.exec(unpack_args(argv))
			os.exit(127)
		end
		if not pid then os.exit(127) end
		local deadline = nixio.sysinfo().uptime + math.ceil(timeout)
		while true do
			local finished, status, code = nixio.waitpid(pid, "nohang")
			if finished and finished > 0 then
				os.exit(status == "exited" and code or 1)
			end
			if nixio.sysinfo().uptime >= deadline then
				nixio.kill(-pid, 9)
				nixio.kill(pid, 9)
				nixio.waitpid(pid)
				os.exit(124)
			end
			nixio.nanosleep(0, 100000000)
		end
	end
	nixio.exec(unpack_args(argv))
end

function M.run(argv, options)
	assert(type(argv) == "table" and #argv > 0, "argv must contain a program")
	options = options or {}
	local pid = nixio.fork()
	if pid == 0 then
		local output_mode = options.append and "a" or "w"
		local output = nixio.open(options.output or "/dev/null", output_mode, "rw-------")
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
	local oversized = false
	while true do
		local chunk = reader:read(4096)
		if not chunk or chunk == "" then
			break
		end
		if captured + #chunk > CAPTURE_MAX_BYTES then oversized = true end
		if captured < CAPTURE_MAX_BYTES then
			local keep = math.min(#chunk, CAPTURE_MAX_BYTES - captured)
			chunks[#chunks + 1] = chunk:sub(1, keep)
			captured = captured + keep
		end
	end
	reader:close()
	local _, status, code = nixio.waitpid(pid)
	if oversized then return false, "Process output exceeds the capture limit", "output_limit_exceeded" end
	if status == "exited" and code == 124 then return false, "Process deadline exceeded", "process_timeout" end
	return status == "exited" and code == 0, table.concat(chunks)
end

return M
