# Candy Core Process API v1

Core is delivered as a signed, platform-specific executable. Linux and OpenWrt
Runtime launchers execute the same Core artifact through this versioned process
API. Runtime never fetches or compiles Core source and Core bundles never contain
Runtime executables.

## Artifact

Each gzip-compressed Core bundle contains exactly these root-level regular files:

```text
manifest.json
manifest.sig
candy-core
```

`manifest.sig` signs `manifest.json` with a Runtime-trusted release key. The
manifest contains `schema_version`, `process_api_version`, Core version/API/wire
metadata, target OS/architecture/libc, `executable: "candy-core"`,
`executable_sha256`, and the Core feature catalog. The outer archive SHA-256 is
an additional transport-integrity check; it does not replace the signature.

OpenWrt accepts only Linux/musl artifacts matching the router architecture.

## Commands

Process API v1 defines these entry points:

```text
candy-core runtime-api-version
candy-core core-info
candy-core client [client arguments...]
candy-core client sdwan [SD-WAN arguments...]
candy-core server [server arguments...]
```

`runtime-api-version` writes exactly `1` followed by a newline and exits zero. It
has no side effects. Runtime launchers use this parser-free bootstrap before
executing a role command.

`core-info` writes one bounded JSON object to stdout and performs no network or
filesystem mutation. It reports at least `schema_version`,
`process_api_version`, `core_api_version`, `core_version`, `protocol_version`,
and `features`.

Role commands retain the existing role-specific CLI contract. Runtime launchers
only select a role and forward arguments without interpreting protocol options.
Core reports readiness, passive status, reload acknowledgements, and diagnostics
through paths and sockets explicitly supplied by Runtime.

Runtime owns UCI/systemd/procd integration, process supervision, netd, firewall,
DNS policy installation, update verification, and rollback. Core owns protocol,
transport, authentication, FEC, congestion control, and protocol feature state.

## Activation

Runtime verifies the signed manifest, executable SHA-256, platform tuple, process
API, Core API, and `core-info` response before installation. Activation switches
the version pointer atomically, restarts the affected role, and runs the Runtime
health check. A failed health check restores both current and previous pointers
and restarts the previous Core.
