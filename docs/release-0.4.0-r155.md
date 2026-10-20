# Candy Runtime 0.4.0-r155

This release integrates the tested shared-listener renewal work with Candy Core 0.3.64.

## Changes

- Start and authenticate the successor before admitting new work, then negotiate retirement of the exact predecessor. Preserve TUN infrastructure independently of worker recovery.
- Reconcile the original forwarding and PacketPort transactions after lost replies. Preserve live owners when process or peer proof is uncertain; retry recoverable control failures without publishing stale ownership.
- Add shared-domain task evidence and strict tests for scaling, bilateral renewal, successor restart, mixed-role isolation and negotiated Proxy drain.
- Build the agent with negotiated renewal support and ship the independent candy-tunio executable on OpenWrt and Linux. Include this executable in the Linux upgrade backup, installation and rollback transaction.
- Initialize absent passive telemetry state under strict shell execution and keep the Rust 1.88 lint gates clean.
- Refresh the independently verified public PacketPort package from Core 0.3.64.

## Source history

The implementation was developed in local commits through `9e00cdd96a9e842359a4339388152736671197f1`, based on remote `f814dea415939311d06c6d2f7c7de5ff80a178dd`. A local history also contained oversized test snapshot executables that GitHub rejected. The source and technical documents are integrated on top of the current remote main; generated binary snapshots and frozen worktree copies are intentionally excluded. No remote history is overwritten.

## Release verification

Run `scripts/verify.sh`, the two Rust 1.88 Linux infrastructure Clippy commands from CI, and agent/TUN unit tests. Check actual OpenWrt x86_64 and IPQ40xx package extraction and Linux x86_64/ARM64 bundles before central finalization. The release packaging contract requires both negotiated renewal compilation and candy-tunio presence. Linux upgrade tests cover installation and rollback of the new managed file.

Core remains a separately signed artifact. Only the central candy-release workflow signs production manifests and the stable catalog. Remove unsigned candidate drafts only after the matching signed formal release is published and verified.

This publication does not claim hardware throughput acceptance or the postponed two-hour soak, and does not deploy to live nodes.
