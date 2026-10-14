local helper = assert(arg[1])
local uptime, killed, waited = 0, {}, false
local original_exit = os.exit
package.preload["nixio.fs"] = function() return { access = function() return false end } end
local forks = 0
package.preload["nixio"] = function()
    return {
        fork = function() forks = forks + 1; return forks == 1 and 0 or 4242 end,
        open = function() return nil end,
        exec = function() error("hung child must remain supervised") end,
        sysinfo = function() return { uptime = uptime } end,
        nanosleep = function() uptime = uptime + 1 end,
        kill = function(pid, signal) killed[pid] = signal end,
        waitpid = function(_, option)
            if option == "nohang" then return 0 end
            waited = true
            return 4242, "signaled", 9
        end
    }
end
os.exit = function(code) error({ exit_code = code }) end
local process = dofile(helper)
local ok, failure = pcall(process.run, { "/bin/hung-worker" }, { timeout = 2 })
os.exit = original_exit
assert(not ok and failure.exit_code == 124, "missing timeout executable must not disable deadlines")
assert(killed[-4242] == 9 and killed[4242] == 9, "deadline must stop child process group")
assert(waited, "terminated child must be reaped")
print("LuCI native timeout fallback test passed")
