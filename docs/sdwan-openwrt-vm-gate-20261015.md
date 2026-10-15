# OpenWrt VM Platform Evidence, 2026-10-15

## Scope

This gate adds a disposable, actual OpenWrt/procd environment. It does not
substitute a lifecycle probe for the production Agent/Core implementation.
The worker in the procd case is a shell lifecycle probe. The infrastructure
process is the current static x86_64 musl `candy-netd`.

The kernel case executes the real ignored Rust test
`real_linux_tun_survives_forward_revoke_and_netd_restart` from
`candy-netd/tests/infrastructure_v2.rs`. It exercises actual TUN and Linux
network state, with the service reconstructed from its journal in the test
process. This is distinct from production signed configuration, Cloud
renewal, a complete Agent/Core packet path, or TUN recovery under procd.

## Trusted Environment

- Checked the official release directory: both 25.12.4 and 25.12.5 exist;
  25.12.5 is the latest stable 25.12.x listed at verification time.
- Image: `openwrt-25.12.5-x86-64-generic-ext4-combined.img.gz`.
- SHA256: `23e2538e8ab0eb52dfed1c65d608ecdb71ffd432dd54885da138ae67cd9e4461`.
- Official `sha256sums` verified using usign key `b5043e70f9a75cde`.
  The public key is pinned in the runner, independently obtained from the
  official `openwrt/keyring` repository, Git blob
  `82d7677e2370c7abf87e70abd2e77c4daf660331`.
- QEMU 9.0.0, x86_64 TCG, one vCPU, 512 MiB, snapshot disk.
- User networking has `restrict=on`; the only host forward binds 127.0.0.1.
  No production addresses, credentials, routing, or TUN devices are used.
- A fresh SSH key and known_hosts are created per VM and removed afterward.
  Child process groups are stopped and reaped on completion or timeout.

## Build Evidence

`scripts/build_openwrt_netd_gate.py` copies source into a private temporary
directory and limits Cargo to one job. It keeps the source workspace lock
unchanged. The initial locked build correctly rejected the pending logging
dependency changes. The isolated offline build resolved those dependencies
and saved both locks and a full source-file SHA256 map.

- Compiler: Rust 1.93.1, LLVM 21.1.8, native macOS rust-lld.
- Target: `x86_64-unknown-linux-musl`; no ELF interpreter, static PIE.
- Source HEAD at capture: `8eb0b5f0cbf67849db50bea890901dffc6fc23a3` plus
  the source-file hashes in the build report.
- netd SHA256: `8830f85acbe8226886f97fb0cca97605a77ac4f0e52dd655668e8f69b449bddf`.
- Kernel test SHA256: `f76de1e9272107c977c05a61b2d9b66db21a063e006f80b269404409bd081949`.
- The test lock adds ten packages required by tracing-subscriber. This is
  a platform test build, not a signed release or Rust 1.88 compatibility gate.

## Results

| Case | Result | Boundary |
| --- | --- | --- |
| Runner manifest/ELF input checks | 4/4 PASS | Missing/duplicate checksum, wrong arch, dynamic interpreter rejected |
| Official image checksum/signature | PASS | Actual official image, not a fixture |
| Real procd lifecycle, v3 and v7 | PASS | Current real netd; lifecycle probe worker |
| Real Linux TUN/journal case, v7 | PASS | 1 actual kernel test passed in 6.31 seconds |
| Official offline APK repository trust, v7 | PASS | ip-full/libbpf1/libelf1/kmod-tun; no trust bypass |
| Production candy.init plus real Agent/Core | NOT RUN | Requires signed product activation and complete x86 artifacts |
| Upgrade, rollback and config retention on real OpenWrt | NOT RUN | Existing mocks alone do not close this gate |
| IPQ40xx hardware | NOT RUN | Generic QEMU ARM is not an IPQ40xx replacement |
| Android Rust integration and upgrade signer | NOT RUN / signer conflict | See offline audit |

The procd case checks repeated start does not duplicate/replace instances,
worker SIGKILL recovery, netd SIGKILL recovery, no cascading restart,
bounded persistent-fault retries, and explicit recovery after removing the
fault. The kernel case checks actual interface/address/route continuity and
an already connected UDP socket through forwarding guard and journal recovery.

## Retained Failed Attempts

- v1: image download and signature PASS; console bootstrap was interrupted.
  The initial report is a download-only report, not a VM execution verdict.
- v2: console activation succeeded, but bootstrap ran before br-lan existed;
  interrupted and VM reaped. The runner now waits for the interface.
- v4: an early SSH handshake exceeded five seconds; VM reaped. The runner
  now retries individual handshakes within the overall deadline.
- v5: local package installation failed with `UNTRUSTED signature`.
  OpenWrt package trust is carried by signed repository indexes; no
  `--allow-untrusted` bypass was used. The runner now includes the official
  base/kmods indexes and performs offline repository installation.
- v6: the harness recorded an old PID after asynchronous stop/start, causing
  an incorrect infrastructure-restart assertion. The harness now waits for
  both old processes to exit and clears readiness before a fresh start.
  The original failure and logs remain retained; v7 passed the corrected gate.

The v7 report records two persistent-fault attempts before procd's configured
crash bound stopped the probe, successful explicit recovery, and a reaped VM.
All downloaded package/index hashes are recorded in the report. The static
build source map, resolved lock SHA256 and lock diff are retained under
`docs/artifacts/sdwan-20261015/openwrt-musl-build-v1/`; the official image
checksum manifest, signature and key are retained in `openwrt-official-image-v1/`.

The v7 netd still uses the old connection-only health probe. The subsequent
protocol probe correction below has separate unit/integration evidence;
the v7 result must not be attributed to its newer source or binary.

All raw attempts remain under `docs/artifacts/sdwan-20261015/openwrt-vm-v*/`.

## Reproduce

```sh
python3 scripts/openwrt_vm_gate_test.py
python3 scripts/build_openwrt_netd_gate.py \
  --out /tmp/candy-openwrt-netd-build --kernel-test
python3 scripts/openwrt_vm_gate.py \
  --out /tmp/candy-openwrt-platform-gate --timeout 360 \
  --netd /tmp/candy-openwrt-netd-build/candy-netd \
  --kernel-test /tmp/candy-openwrt-netd-build/kernel-test
```

The runner downloads only bounded official artifacts. Repository signatures
must be accepted by the trust keys already present in the authenticated
OpenWrt image. The result always keeps `whole_platform=NOT_RUN` until the
remaining production integration cases have separate evidence.

## Protocol Health Probe Correction

`--probe-socket` now sends a read-only request, with explicit
`--probe-protocol v1|v2` selection (default v1 for legacy callers).
It verifies framing, response request ID, expected response body, absence of
descriptors, and for v2, ABI version 2 and independent infrastructure support.
The framed request/response has a shared 750 ms deadline. OpenWrt retains its
outer process timeout, including connection establishment.

- Production `candy.init` currently starts v1 netd and now explicitly probes v1.
  This correction does not claim to migrate production Agent/Core to v2.
- The isolated VM explicitly probes its v2 infrastructure service with v2.
- Legacy Status checks from the configured UID/GID use a read-only service
  path. They cannot claim ownership, change a lease, or invalidate an active
  owner's next transaction. PID/UID/GID authentication remains enforced.
- V2 Capabilities returns after authentication and before expiry recovery.
  Expiry remains the maintenance loop's responsibility. A health check does
  not mutate forwarding, TUN, authorization, or journal state.
- Stop completion uses the existing daemon PID query, avoiding an incorrect
  readiness failure when the stop caller is root and the permitted IPC client
  is the unprivileged SD-WAN account.

Focused results before the exclusive performance window:

| Check | Result |
| --- | --- |
| Probe framing, response validation, and stalled peer | 3/3 PASS |
| CLI probe/server argument compatibility | 1/1 PASS |
| Netd service and infrastructure integration | 24/24 PASS |
| OpenWrt init config/lifecycle shell suite | PASS |

The infrastructure test snapshots the real journal bytes and backend events
before a Capabilities request made after lease expiry, then confirms both
remain unchanged and the same TUN ifindex/firewall remain present. The legacy
test probes using a distinct instance/generation between Prepare and Commit,
then verifies the original owner can still commit without creating another TUN.

On macOS, changing `SO_RCVTIMEO` after the peer closes can return `EINVAL`.
The protocol unit tests synchronize endpoint lifetime explicitly; this is
separate from the Linux/OpenWrt daemon target and is not evidence of Linux
CLI behavior. A fresh Linux/OpenWrt probe gate is required after the performance
window before claiming that target's new binary has passed.

### Fresh Target Verification

After the exclusive performance window, the new probe code was rebuilt for
`x86_64-unknown-linux-musl` with `cargo build --locked --offline -j 1`.
The builder now always requires the lock on its initial build. Build evidence
records `test_lock_changed=false`, root lock SHA256
`78f4fda42127ce097042086c6ccb5fb826ecded4719151dd915b76de35b49a34`,
and netd SHA256
`55d37fa4ea6ebff5bf9c0cb9a3873c33702d0fd9792991eaf75b961db79f82c0`.
The source snapshot HEAD is `46d8e3a3d50fd6ae4ea7cb91e5c2ed23db766266`,
which includes probe correction `ebc9d06`; the full copied source file map is
in the build report. Unrelated working Agent changes were not compiled by
this netd-only package build.

The authenticated OpenWrt 25.12.5 VM rerun completed
`PASS_NARROW_PROCD`, including `protocol_v2_health_probe=PASS` and an explicit
assertion that health checks produced no `code=netd_v2_request_failed` warnings.
Repeated startup, worker/netd SIGKILL recovery, fault containment, bounded
persistent retries (three attempts), and manual recovery all passed again.
QEMU exited and was reaped. This run intentionally did not repeat the kernel
TUN case, whose separate v7 evidence remains above.

Evidence:

- `docs/artifacts/sdwan-20261015/openwrt-musl-probe-v2/build-report.json`
- `docs/artifacts/sdwan-20261015/openwrt-musl-probe-v2/build.log`
- `docs/artifacts/sdwan-20261015/openwrt-vm-probe-v8/report.json`
- `docs/artifacts/sdwan-20261015/openwrt-vm-probe-v8/guest-evidence.tar.gz`

The netd probe target gate is now verified on real OpenWrt; the full production
Agent/Core platform, IPQ40xx, Android, and update/rollback statuses remain as
listed above.
