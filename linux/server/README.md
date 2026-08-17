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

## Candy Cloud and the public SD-WAN endpoint

A Linux server can run its ordinary Candy service and participate in SD-WAN at
the same time. Cloud enrollment alone does not advertise a guessed address.
The inbound QUIC/UDP endpoint must be supplied explicitly as a numeric IP and
the port already configured on a Core listener:

```text
install/install-candy-server.sh \
  --artifact-file /path/to/candy-server-x86_64 \
  --listen 0.0.0.0:18443 \
  --public-endpoint 203.0.113.10:18443
```

IPv6 uses the canonical bracketed form, for example
`[2001:db8::10]:18443`. The installer writes only this value to
`/etc/candy/cloud-sync.env`, owned by `root:candy` with mode `0640`. An upgrade
without `--public-endpoint` preserves the existing file; an explicit value
updates it atomically. Installer rollback restores the previous value.

`candy-cloud-sync.service` reads that environment file. When an enrolled
server has no endpoint, synchronization exits successfully without reading an
identity, publishing transport data, or activating an SD-WAN configuration.
It records the actionable state below instead of silently skipping work:

```json
{
  "state": "waiting_for_public_endpoint",
  "error_code": "public_endpoint_required"
}
```

This waiting state does not stop or modify the ordinary Candy service. After a
valid endpoint is installed, start `candy-cloud-sync.service` or wait for its
timer; Cloud then validates the endpoint port against Core's real listeners
before accepting the transport identity.

For an operator-driven join over SSH, use the repository helper. It supports
both x86-64 and ARM64 servers and never accepts an SSH password:

```text
scripts/join-linux-server-node.sh \
  --bootstrap-file ./candy-node-bootstrap.json \
  --node 203.0.113.10 \
  --user operator \
  --public-endpoint 203.0.113.10:18443
```

## Installing a Core bundle

The packaged `candy-core-manager` consumes the same signed bundle format as
OpenWrt. It does not download or build Core source:

```text
candy-core-manager install CORE_VERSION /path/to/core.tar.gz BUNDLE_SHA256
candy-core-manager activate CORE_VERSION
candy-core-manager status
candy-core-manager rollback
```

Installation verifies the outer SHA-256, the three-file archive layout, the
publisher signature, manifest and executable SHA-256, target OS/architecture/
libc, Process API, Core API, and the executable's `core-info` result.

Activation stops a running server before switching `current` and `previous`,
runs the new Core's server config check and preflight through the Runtime
launcher, then starts the service. The packaged health check additionally
requires systemd to report the service active and the configured UDP listen
port to appear. A validation, startup, or listener-health failure restores both
pointers and restarts the previous Core.

By default signatures are checked with `usign` and
`/etc/candy/core-signing-key.pub`. A deployment can provide an equivalent
executable verifier through `CANDY_CORE_SIGNATURE_VERIFIER`; it receives the
manifest path followed by the signature path.

The manager requires `jq`, `tar`, `readlink`, and either `sha256sum` or
`shasum`. Signature verification additionally requires `usign` and the trusted
public key unless an external verifier is configured.

For a new host, install the Runtime package without enabling the service, use
the packaged manager to install and activate a Core bundle, then install or
enable `candy-server.service`. Subsequent Core activation is online-safe: the
manager coordinates service stop, validation, pointer rollback, and restart.

## Real Core integration gate

The Runtime verification suite includes an optional Linux/amd64 Docker E2E.
When a real private Core executable is supplied, it starts both Runtime
launchers, authenticates a client connection, and verifies TCP forwarding:

```text
CANDY_CORE_BINARY=/absolute/path/to/candy-core scripts/verify.sh
```

The test skips when no Core or Docker daemon is available. CI release jobs can
make either condition fatal with `CANDY_CORE_DOCKER_E2E_REQUIRED=1`. The Core
artifact is copied only into a temporary test directory and is never packaged
or committed by Runtime.
