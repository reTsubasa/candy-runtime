# Linux server Runtime

`serverd-linux` is a public Runtime launcher. It contains no Candy protocol or
transport implementation and never links private Core source.

## Core process API v1

The active private Core artifact is a native `candy-core` executable. Runtime
uses two stable commands:

```text
candy-core runtime-api-version
candy-core server [server arguments...]
```

`runtime-api-version` must write exactly `1` to standard output and have no
side effects. After that check, the launcher replaces itself with
`candy-core server` using `exec`. The Core process therefore retains the
Runtime PID and receives the original arguments, signals and exit-code
contract without a proxy process.

The default active binary is:

```text
/opt/candy/cores/current/candy-core
```

`CANDY_CORE_BINARY` selects an exact executable. `CANDY_CORE_ROOT` or
`CANDY_CORE_CURRENT_LINK` may change the managed Core location. The launcher
resolves the active symlink before checking compatibility so one invocation
cannot switch Core releases between inspection and execution.

The Linux Runtime package contains only the launcher, systemd unit, installer,
and example configuration. Core artifacts are installed and activated by the
independent Core manager.
