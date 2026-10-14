# SD-WAN 平台与发布门禁（2026-10-14）

## 范围与判定

`scripts/platform_release_gate.py` 提供不构建、不安装、不签名和不发布的离线门禁。每次必须使用新的证据目录；目录已存在时拒绝运行，保留失败证据。退出码 1 表示至少一个实测失败，退出码 2 表示所执行检查通过但完整平台门禁尚未完成。该脚本不会返回完整发布 PASS。

检查分为三种证据：OpenWrt/中央 Release 的 mock fixture 契约、真实已有 catalog 的密码学验签与篡改拒绝、指定 ELF/APK 的真实制品元数据。fixture 中的签名通过不能作为新制品已经签名的证明；旧制品也不能证明当前源码已经完成构建。

## 可重复执行

在 Runtime 仓库执行：

```sh
python3 scripts/platform_release_gate_test.py
python3 scripts/platform_release_gate.py \
  --out docs/artifacts/sdwan-20261014/platform-release-gate-next \
  --contracts
```

`--elf x86_64=/absolute/path/candy-core` 或 `--elf ipq40xx=/absolute/path/candy-core` 可重复传入 Core 和 Runtime 的所有 ELF。检查 ELF class、machine、可执行类型、program header、IPQ40xx EABI5 hard-float 及无动态 interpreter。这个检查不会运行 foreign binary，也不证明 ARMv7 CPU 指令集、NEON/VFPv4、TUN ioctl 或实际 kernel ABI 已通过。

APK 覆盖安装的静态条件单独验证：

```sh
python3 scripts/platform_release_gate.py \
  --out docs/artifacts/sdwan-20261014/platform-apk-next \
  --apk /absolute/path/new.apk \
  --previous-apk /absolute/path/installed-version.apk \
  --android-tools /Users/hyc/Library/Android/sdk/build-tools/35.0.0 \
  --expected-apk-cert REQUIRED_CERTIFICATE_SHA256
```

APK 必须通过真实 apksigner 验签、aapt 包名/版本检查、候选 zipalign 16 KiB 对齐；新旧 package 与 certificate 相同，versionCode 增加，保留旧包的 native ABI。旧 APK 的对齐状态仅记录，因为历史可用安装包不必符合新目标的对齐标准。单 ABI 新包覆盖 universal 旧包需要另行提供真实设备 ABI 证据，不能用这个 universal 比较自动放行。

## 当前发现的安卓兼容问题

用户提供的 `cmfa-0.3.4-meta-universal-release.apk` 包名为 `com.github.metacubex.clash.meta`，versionCode 300004。现有本地 0.3.6 universal APK 使用相同包名和同一证书，但这只是既有 Go Android 客户端制品，不能证明本轮 Rust SD-WAN 功能已经集成。

| 对象 | SHA-256 certificate |
|---|---|
| 用户历史 0.3.4 APK 和现有本地 0.3.6 APK（Android Debug） | `2f3578febd2c24c835e00b3e44aa7b2fabe6c217eb72f03ea7b10f23494d0a15` |
| Android `sign-local-apks.yaml` 的 EXPECTED_CERT | `28e56315d42d3960958d7d5f550596209c37db75fa51e6fb53f25687f8a8bc7f` |

中央工作流要求的签名与历史安装证书不同。直接重签同 package 会导致覆盖安装失败；不得因为新旧本地包同为 Debug 证书就将发布门禁标记 PASS。正式发布需要明确选择保留已安装证书的兼容升级路径，或实施显式迁移（先导出并验证配置备份，再另行安装；普通卸载会清除应用数据）。此次只记录问题，没有更改签名配置、泄露私钥或卸载设备应用。

## 完整平台验收流程

1. 先冻结最终 Core 与 Runtime commit、lockfile、工具链和 PacketPort vendor provenance。构建与性能测量不得重叠；现有 `dist/` 或旧 Android APK 不能冒充该冻结版本。
2. 在隔离 Linux 构建机使用现有 `packaging/openwrt/build/build_runtime.sh` 分别构建 `x86_64-unknown-linux-musl` 和 `armv7-unknown-linux-musleabihf`。ARM stage 为 `arm_cortex-a7_neon-vfpv4`。逐一验证四个 Runtime 可执行文件及匹配 Core，记录二进制 SHA256 与源码 commit。
3. 使用 `CANDY_RUNTIME_BIN_DIR=<x86 stage> packaging/openwrt/build/sdk_container_gate.sh apk x86_64` 和 ARM stage 的 `... apk ipq40xx-generic` 构建软件包。默认 OpenWrt 25.12.4/GCC14.3.0；本项目接受 25.12.x。OpenWrt package architecture 必须匹配设备 `arm_cortex-a7_neon-vfpv4`，不能仅根据 `uname -m=armv7l` 选择 generic Runtime。
4. 在发布侧校验真实候选 bundle 的全部 extracted payload、metadata/provenance、SHA256 和签名；先通过候选验收再推进 catalog。现有已签名 stable catalog 验签不等于本轮候选已经发布。
5. 在一次性 OpenWrt x86_64 VM 验证 procd 的 cold boot、唯一实例、启动顺序、退避、Core/Runtime install-over-old、失败激活回滚和配置保留；阻断业务线路时 TUN/netd 必须保持。必须保存控制台、logread、pid/epoch、route/nft 与配置校验和证据。
6. 在 IPQ40xx 真机复核相同流程及 ARM hard-float/指令兼容和真实 TUN。QEMU system-arm 不模拟原 IPQ40xx 硬件，不能据此关闭真机门禁。不能在承载用户流量的路由器实施故障注入。
7. 在指定隔离 Android emulator/设备执行覆盖安装、VPN 授权、TUN 流量、续期/线路恢复、配置持久化和故障隔离。不得用默认 `adb -d` 或未知设备安装；必须显式 serial，并保存旧包和配置。正常生产 APK 不保证可降级，`adb -r -d` 也不应作为普遍回退能力的证明。

Docker 适合隔离 Linux QUIC/TUN 与性能矩阵；它不提供 OpenWrt procd、IPQ40xx 硬件或 Android VPN framework 的验收证据。本机有 Docker、qemu-system-x86_64、qemu-system-arm、usign 与 Android SDK 工具，但没有已确认的可启动隔离 OpenWrt 镜像或指定 Android 测试设备；工具存在不等于对应平台通过。

## 本轮结果

| 检查 | 结果 | 证据目录 |
|---|---|---|
| ELF 架构校验 regression | 5/5 PASS | `scripts/platform_release_gate_test.py` |
| OpenWrt/中央发布 fixture | 13/13 PASS（合并 v1 与 v2 复测） | `platform-release-gate-v1/`、`platform-release-gate-v2/` |
| 现有 stable catalog 真实验签、篡改拒绝 | PASS | 同上 |
| 历史 APK → 现有本地 APK 静态覆盖兼容条件 | PASS | `platform-release-gate-v1/apk-identities.json` |
| APK required release signer | FAIL | `platform-release-gate-v1/report.json` |
| 现有 x86 Runtime 四个 ELF | PASS（旧制品身份） | `platform-artifact-gate-v3/report.json` |
| selector malformed、x86 误标 IPQ40xx | 正确拒绝 | `platform-release-gate-negative-v1/report.json` |
| 最终源码多平台构建、真实候选签名、设备 install/upgrade/rollback | NOT RUN | 各 report 的 `not_run` |

以上目录均在 `docs/artifacts/sdwan-20261014/`。v1 的 update-manager 在 runner 180 秒上限失败，v2 将单 suite 上限提高为 600 秒后真实执行通过，原超时结果保留。其余 12 个 fixture 无需重跑。runner 现在提供 `--contract-timeout` 和 `--contract-only`，超时会清理该 fixture 的独立 process group，避免残留后台负载。各 report 的具体源码/脚本 SHA256 是对应轮次的证据；工作树曾有并行改动，不能宣称这是最终整洁 commit 的全平台构建。

全部 fixture 结果、签名策略发现和 NOT RUN 项须逐项保留，不能汇总成 G0/G5 已关闭。

本轮没有执行新的平台构建、SDK 下载、真实安装、线上更新、中央签名发布或性能测试。完整 G0/G5 仍需最终冻结源码的真实制品与上述平台实测。
