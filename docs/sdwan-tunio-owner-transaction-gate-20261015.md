# TUNIO owner transaction control

Date: 2026-10-15

## Protocol and Compatibility

Owner transactions are opt-in authority control schema 3. Schema 2 retains
StageAuthority, AttachAuthorized, ProbeTransaction, RevokeExact and
DiscardAuthority behavior. Schema 2 responses omit all newly introduced fields,
including when rejecting a schema 3-only operation. Existing controllers using
strict response decoding continue to work. A controller must not fall back from
an unsupported owner transaction to an immediate Attach.

Schema 3 adds these operations using the existing request envelope and capability:

| Operation | FD | Additional operation payload | Result |
| --- | --- | --- | --- |
| PrepareOwner | One connected AF_UNIX datagram FD | Expected actual active epoch and monotonic preparation deadline | Exact manager Prepared receipt |
| CommitOwner | None | Exact previously staged envelope | Exact manager Committed or rejection receipt |
| AbortOwner | None | Optional exact staged envelope | Exact manager Aborted/Expired or committed rejection receipt |
| ProbeTransaction | None | Transaction ID | Exact retained manager transaction and current actual owner |

All operations authenticate the peer process, current controller, controller
epoch, capability hash and TUNIO registration. A takeover preserves pending state;
the old controller fails before mutation. The new authenticated controller may
abort an inherited candidate. It cannot commit using an envelope verified for
the former controller epoch; it must explicitly resolve that candidate first.

## State and Failure Boundaries

StageAuthority validates a file authority. It is never evidence that a PacketPort
owner was prepared. Prepare additionally validates the exact staged envelope and
real FD type, connection, address family and creator credentials, then invokes
the public PacketPort Prepare API. The expected active epoch is checked against
the manager's actual binding. The preparation deadline must be live, at most 30
seconds away and within the verified authorization cap.

TUNIO retains the original immutable manager transaction, including its resolved
Instant deadlines, expected active epoch, binding, revision and transaction ID.
A duplicate must use that same envelope and requested preparation deadline. It
reuses the original transaction rather than recalculating and extending the cap.
Legacy Attach and file Discard cannot bypass a prepared owner transaction.

Manager receipts, including rejection receipts, reconcile actual TUNIO state.
A request whose ACK is lost retains its tentative local identity until the next
manager Probe confirms Prepared/Committed, a terminal result, or no application.
Probe distinguishes historical Committed from a currently active owner. A
duplicate Commit after revocation never reinstalls the old owner. Only one
terminal result is retained, consistent with the manager; an evicted result is
unknown. Controllers can use `exchange_authority_outcome` to inspect exact
rejection receipts. The existing `exchange_authority` helper preserves its error
behavior for old callers.

Authority and deadline rejection before Commit leaves the old owner available.
PacketPort enforces expiry independently of the control socket; candidate expiry
does not close the TUN infrastructure. Controller takeover does not grant a fresh
authorization cap. The new protocol does not make manager history durable across
a TUNIO process restart.

## Verification

Linux tests ran offline in `candy-core-diag-builder:rust-1.88.0`, with 2 CPUs,
4 GiB container limit and one Cargo build job. Commands used the existing TUNIO
lock and `--target-dir /workspace/candy-runtime/target-linux-tunio`:

```sh
cargo test --locked --offline --manifest-path /workspace/candy-runtime/linux/common/apps/candy-tunio/Cargo.toml --lib authority_control
cargo test --locked --offline --manifest-path /workspace/candy-runtime/linux/common/apps/candy-tunio/Cargo.toml --lib
cargo test --locked --offline --manifest-path /workspace/candy-runtime/linux/common/apps/candy-tunio/Cargo.toml --lib authority_control::tests::owner_schema3_active_and_pending_authorities_fit_bounded_response
cargo clippy --locked --offline --manifest-path /workspace/candy-runtime/linux/common/apps/candy-tunio/Cargo.toml --all-targets -- -D warnings
```

The first authorization run passed 8/8 tests; the complete library run passed
19/19 tests. An additional response-size regression then passed 1/1 test with 19
filtered tests: a signed active authority, signed pending authority and exact
owner Prepared receipt together fit the existing 4096-byte control bound.
Strict all-targets Clippy passed. No lock file was changed.

New tests exercised real connected Unix datagram FDs in both directions before
and after commit, loss of the control response followed by exact Probe recovery,
immutable duplicate preparation, schema 2 field omission, early Commit rejection,
legacy bypass rejection, stale active epoch, wrong FD, changed payload, old
controller rejection, authenticated takeover Abort, repeated terminal operations,
preparation expiry and historical Commit after revocation without reactivation.

The default Agent transaction flow has not been switched by this change.
End-to-end remote commit, Agent adoption and performance acceptance are separate
gates and cannot be inferred from this local control API.
