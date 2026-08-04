# Candy Core ABI v1

Core 以签名的平台 `cdylib` 制品交付。Linux/OpenWrt 的 client/server 都是 Runtime
可执行入口，通过稳定 C ABI 加载同一 Core；不依赖 Rust dylib ABI，不把 Runtime
可执行文件包装成 Core。

## 制品

```text
manifest.json
manifest.sig
libcandy_core.so
```

`manifest.sig` 使用 Runtime 内置信任根验证 `manifest.json`。Manifest 至少包含：

- `schema_version`
- `core_api_version`
- `core_version`
- `wire_version`
- `target_os`、`target_arch`、`libc`
- `library`、`library_sha256`
- Core 编译能力目录

URL 和用户同时输入的 SHA-256 不是发布者身份证明；正式激活必须先通过签名和
library SHA-256 两层校验。

## ABI 规则

ABI v1 必须以 C 兼容类型定义下列能力：

1. 查询 ABI/Core/wire 版本与能力 manifest。
2. 以角色、平台回调表和已验证配置创建 client/server engine。
3. 启动、请求停止、等待停止和释放 engine。
4. 原子读取状态快照，并订阅有界状态事件。
5. 验证并应用运行配置，明确返回“热更新”或“需重启”。
6. 所有跨 ABI 内存由分配方释放；Runtime 不直接 `free` Core 内存。
7. Core panic 不得跨越 ABI；错误使用稳定错误码和有界 UTF-8 详情。
8. 回调不得在 Core 内部锁持有期间调用；线程所有权与重入规则由 ABI 头文件定义。

Runtime 只通过回调提供文件、时钟、随机数、socket/TUN、DNS 查询、netd 和状态
发布等平台能力。Core 不读取 `/etc`、`/proc`、UCI/procd/systemd，不直接写运行状态文件。

## 激活与回滚

Runtime 管理器安装 Core 后先在独立进程中加载并校验 ABI，不在 LuCI worker 内
`dlopen`。激活后必须同时验证：

- Runtime 进程与 Core engine 均进入 ready；
- client 的 DNS、监听端口、控制 socket 和有界出口诊断成功；
- server 的监听端口、证书/ECH 和 preflight 成功；
- 状态 schema 和 Core API 仍在 Runtime 支持范围。

任一检查失败时同时恢复 `current` 与 `previous` 指针，重启旧 Core 并保留失败
证据。仅“procd/systemd 进程存活”不构成健康。
