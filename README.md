# candy-runtime

`candy-runtime` 是 Candy 的平台运行、系统集成和交付仓库。Linux 与 OpenWrt 的
client/server 都在这里，以平台和角色分目录；私有线路协议、传输、认证、
FEC、BBR 和 DNS/路由决策实现只存在于 `candy-core`。

```text
linux/
  client/      Linux client 入口、配置和 systemd 交付
  server/      Linux server 入口、安装器和容器交付
  common/      Linux/OpenWrt 可复用的 netd 等平台适配
openwrt/
  client/      client 的 UCI、procd、LuCI 和包测试
  server/      server 的 UCI、procd 和包测试
shared/
  contracts/   Runtime/Core 的公开稳定合同
packaging/     跨目录的构建与发布编排
```

## 依赖方向

```text
platform role -> runtime adapters -> stable Core process API -> private Core
```

Core 不得依赖本仓库。Runtime 不复制 feature bit、FEC 激活条件、协议状态机
或拥塞控制参数。LuCI 只读 Runtime 发布的原子状态文件，不直接扫描 Core 目录。

## 版本

Runtime 使用根目录 `VERSION`；Linux/OpenWrt client/server 共用 Runtime SemVer。
OpenWrt `PKG_RELEASE` 及其他平台 revision 是独立的包管理元数据。Core 版本、
wire 版本和 Core API 版本与 Runtime 版本不要求相等。

Runtime 发布必须记录 Runtime 版本/revision、Core commit/版本/API、wire 版本、
目标平台/架构和产物 SHA-256。Core 独立更新使用
[Core Process API v1](shared/contracts/core-process-api-v1.md)，Runtime 不加载 Rust dylib，
也不获取或编译 Core 源码。

OpenWrt client 的集中发布由 `release-openwrt-client` 手动 workflow 执行。
它固定从 `main` 构建、校验 Runtime 版本与包 revision，然后将两个
APK、`BUILD-INFO`、`SHA256SUMS` 和 `runtime-release-metadata.json`
上传到 `reTsubasa/candy-release` 的 `runtime-v<version>-r<revision>`
draft Release，然后发送 `candy-artifact-ready` 事件。中央发布 Action 负责验证、
发布 Release 并更新签名稳定版目录；Runtime 源仓库不直接修改目录。

## 当前迁移状态

- OpenWrt client 已迁入 `openwrt/client`。
- Linux/OpenWrt role 入口均为 Process API v1 薄启动器；协议实现不在本仓库。
- `candy-netd` 和 `candy-cloud-enroll` 是 Runtime 原生 Rust 边界，均与 Core crate 完全解耦。
- Linux `candy join` 已实现 Cloud activation/challenge/complete：设备 Ed25519 密钥、证书和稳定重试状态保存在 `/var/lib/candy/sdwan/identity`，激活凭据不会落盘。私有 CA 可通过 `CANDY_CLOUD_CA_CERTIFICATE` 指定。
- OpenWrt server 目录已保留，不伪装成已实现；它将复用同一 Core process API。
- Core 作为独立签名制品安装和更新；Runtime 构建不检出、链接或复制 Core 源码。
