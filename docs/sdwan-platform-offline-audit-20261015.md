# SD-WAN Offline Platform Audit, 2026-10-15

## Decision

G0/G5 remain incomplete. This audit did not build, sign, publish, install, boot
a VM, run Linux load tests, or change production. Existing artifact metadata
cannot attest the current frozen source or its SD-WAN implementation.

Runtime at check time: `5f9138d409d27185513482ca866af7932097e104`.
Android source at check time: `ed9f66a30d48ed8d02103ac2fcd40fd69186a8f4`.
The report records dirty worktrees because parallel work and local evidence
were present; it is not a release provenance statement.

## Executed Checks

| Check | Result | Evidence |
| --- | --- | --- |
| ELF parser regression | PASS, 5 tests | `python3 scripts/platform_release_gate_test.py`, 0.006 seconds |
| Existing stable catalog signature and modified catalog rejection | PASS | `artifacts/sdwan-20261015/platform-offline-recheck-v4/report.json` |
| Four existing x86 Runtime executables | PASS, static ELF64 x86-64, no interpreter | Same report; artifacts are the old `dist/runtime/openwrt-client/x86_64/` stage |
| Existing Android 0.3.5 and 0.3.6 signatures, package, version, ABIs and alignment | Individual identities obtained | `apk-identities.json` and both `*-apk.log` files in the same directory |
| 0.3.5 to 0.3.6 upgrade compatibility | FAIL, signer differs | `report.json`, process exit 1 |
| Current 0.3.6 candidate matches required release signer | FAIL | Same report |
| OpenWrt cold boot/procd/install/rollback | NOT RUN | No confirmed boot image or SDK cache; no VM started |
| IPQ40xx kernel/TUN/hardware | NOT RUN | No offline hardware fixture; QEMU does not implement IPQ40xx |
| Android install/VPN/TUN/recovery | NOT RUN | No AVD, system image or connected device |

No contract suites or long-running tests were repeated during the concurrent
build/performance work. The gate command used the four old x86 executables,
the 0.3.5 universal APK in `candy-android/build/release-verify-035/`, the 0.3.6
universal APK in `candy-android/app/build/outputs/apk/meta/release/`, Android
build-tools 35.0.0, and the required certificate below. It did not use
`--contracts`. Full input paths, SHA256 values and individual results are in
the machine-readable report.

## Android Signing Finding

Both APKs declare `com.github.metacubex.clash.meta`, retain all four native
ABIs (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`), and pass 16 KiB zip alignment.
Their versionCode increases from 300005 to 300006. Both cryptographic APK
signature checks pass individually. Their certificates differ:

| APK | Certificate SHA256 | APK SHA256 |
| --- | --- | --- |
| Existing 0.3.5 universal | `28e56315d42d3960958d7d5f550596209c37db75fa51e6fb53f25687f8a8bc7f` | `1a63b68b7e07bc0bc3bc0de053082107a3522f22ac239f3353a8d6fce79a0ee6` |
| Existing 0.3.6 universal | `2f3578febd2c24c835e00b3e44aa7b2fabe6c217eb72f03ea7b10f23494d0a15` | `de837490166e444c677f33629f0de013340518e189d4d6ad9a3ce1ee9dd6870c` |

The 0.3.5 certificate is `CN=Candy Android`; 0.3.6 is `CN=Android Debug`.
The Android `sign-local-apks.yaml` workflow requires the 0.3.5 certificate.
The historical 0.3.4 universal evidence records the Debug certificate, but the
original Downloads file is no longer available in this audit, so it was not
reverified here. Installed Debug and release certificate cohorts must be
handled explicitly. Re-signing a candidate with the release certificate alone
does not prove compatibility with the Debug cohort. No APK is assumed to have
a verified signing lineage: apksigner reports v3/v3.1 false for these two files.

Required resolution before installation: identify the supported installed
certificate cohort, use its compatible certificate or a separately verified
signing migration, and verify the final candidate against the exact previous
APK. Test on an explicit isolated serial and preserve a validated configuration
export. A normal uninstall or unsupported APK downgrade is not a safe fallback.

These APKs contain the existing `libclash.so` Go application and ancillary JNI
libraries. This audit does not establish integration of the new Rust SD-WAN
worker architecture or treat them as new SD-WAN candidates.

## Observed Environment

| Resource | Observation |
| --- | --- |
| QEMU | `/usr/local/bin/qemu-system-x86_64`, version 9.0.0; `qemu-system-arm -machine help` lists generic `virt` and other boards, no IPQ40xx |
| OpenWrt SDK | Runtime `.openwrt-sdk-cache/` absent; `dist/openwrt/` absent |
| OpenWrt boot image | None found in the workspace file inventory, Downloads, `/tmp` shallow search, or selected shallow local cache search |
| Docker images | Existing Rust Core builders, Linux perf runner and systemd fixture present; no `candy-openwrt-sdk-gate:*` image in the actual image list |
| Android SDK | build-tools 34.0.0, 35.0.0, 36.0.0, 36.1.0, 37.0.0; adb and emulator executable present |
| Android system images | `/Users/hyc/Library/Android/sdk/system-images/` absent |
| Android AVD | `/Users/hyc/.android/avd/` exists and is empty; `emulator -list-avds` exits 0 with no entries |
| Android devices | Explicit SDK `adb devices -l` lists no devices; only the local adb server was started |
| User-mode emulation | `qemu-arm` and `qemu-x86_64` absent from PATH |
| Host platform services | Native `procd` and `apk` absent from PATH; `usign` available |

The inventory is bounded to these locations. It does not claim that no image
could exist on another disk or external host. QEMU machine-list and version
commands only queried tool capabilities and did not instantiate guests.

## Concrete Isolation Setup

| Platform | Obtain and validate | Gate it can close |
| --- | --- | --- |
| OpenWrt x86-64 | From `https://downloads.openwrt.org/releases/25.12.4/targets/x86/64/`, obtain the release SHA256SUMS/signature, the generic combined disk image, and matching SDK. Verify checksum/signature against the trusted OpenWrt key. The repository currently specifies GCC 14.3.0 for 25.12.4. | Boot a disposable QEMU guest with snapshot storage, serial console and `-nic none`. Validate real procd startup/unique instance/backoff, package install-over-old, rejected activation rollback, config checksums and TUN infrastructure survival. A later deliberately isolated network is required for guest tunnel traffic tests. |
| OpenWrt IPQ40xx | Same release's `targets/ipq40xx/generic/` SDK and trusted hashes; package architecture `arm_cortex-a7_neon-vfpv4`, Runtime target `armv7-unknown-linux-musleabihf`. Use an isolated spare IPQ40xx device and its matching vendor firmware/board recovery path. | SDK packaging and static ARM EABI5 hard-float checks first; real device must still prove CPU features, kernel/TUN ABI, procd, upgrade/rollback and persistent config. A QEMU ARM `virt` guest cannot close the hardware gate. |
| Android | Use the installed SDK manager to obtain an Android ARM64 emulator system image compatible with the host, then create a dedicated AVD. Use `emulator -list-avds` and explicit `adb -s SERIAL`; start with no bridge to production. Obtain final APK plus the exact previous signed APK and known config fixture. | Signature/package/version/ABI static checks, real install-over-old, config persistence, VpnService permission and TUN packets, worker/underlay recovery and validated export/restore. Emulator results do not replace ARMv7 hardware coverage. |

For each platform freeze the tested Core/Runtime/APK commits and lockfiles,
record tool versions and artifact hashes, and use a fresh evidence directory.
Acquire and prepare tools outside the exclusive performance window. No download,
SDK setup, image creation, device flashing, candidate re-signing or installation
was performed by this audit.
