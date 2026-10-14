# Public PacketPort Source Package

PacketPort contains packet descriptors, bounded output, authenticated local
framing and infrastructure owner changes. It must not depend on QUIC, Cloud
authentication, Proxy sessions or the SD-WAN route engine.

## Ownership

The development source is `candy-core/crates/candy-packet-port`. Runtime consumes
the fixed public package in `shared/vendor/candy-packet-port`. Runtime does not
need a sibling Core checkout to resolve or build TUNIO. The vendored files are a
materialized source release, not a second implementation: do not edit them.

`provenance.json` records the origin, base commit, exact source file hashes and
canonical package content hash. A dirty development export is explicitly marked;
the base commit alone does not identify its source. Release provenance must use
the final committed source and preserve these content checks.

The package manifest resolves workspace metadata and dependencies to literal
values. Only libc, nix, serde, tokio, tracing and test-only tempfile are allowed.
No private Core, sibling path or Git dependency is accepted.

## Refresh And Verification

After changing the authoritative public crate, refresh explicitly:

```sh
python3 scripts/packet_port_package.py --core-dir ../candy-core
```

Normal verification uses only the Runtime checkout:

```sh
python3 scripts/packet_port_package.py
scripts/runtime_layout_test.sh
```

Verification rejects added, missing or changed files, symlinks, digest mismatch
and disallowed dependencies. Refresh never runs as part of normal CI or a
deployment. The public package is source input, not an executable, so release
signing still covers the final Runtime binaries and manifest.

## Actual-State Receipt

The managed bridge accepts Attach, Renew, Revoke and Probe on its authenticated
control channel. An optional receipt reports its actual active binding,
monotonic deadline and highest consumed owner/policy epochs after the operation.
A lost ACK is reconciled through a fresh Probe. The controller cannot infer
success from a durable request or restore its old cached state after an operation
that may already have taken effect.

Receipt work is confined to control requests; no per-packet serialization or
state publication is introduced. No receipt alone verifies a business Grant:
Agent and Core retain their signed authorization checks.
