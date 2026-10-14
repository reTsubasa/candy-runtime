# SD-WAN 实施与门禁状态（2026-10-14）

## 已完成并推送

| 项目 | 结果 | 证据/提交 |
|---|---|---|
| WorkerPool 角色配额、credit 回收、连续扩缩 | PASS（API级） | candy-core `319e2b2`；transport all-targets 163 passed |
| ownership prepare/commit/abort、单调 fencing、drain deadline、迟到 release | PASS（API级） | candy-core `319e2b2`；`sdwan-worker-pool-handoff-gate-20261014.md` |
| fixture 两小时静态 Grant TTL 支持 | PASS（仅测试 fixture） | candy-core `b81a509`；生产 Grant 上限/协议未改变 |
| systemd netd 独立重启 | PASS（隔离 Docker/fake payload） | `systemd-supervisor-gate-20261014.json`：netd PID 118→151，Agent PID 保持 121 |
| systemd Agent SIGKILL 恢复 | PASS（隔离 Docker/fake payload） | NRestarts 0→1，Agent PID 121→210 |
| Linux Runtime 打包与缓存行为 | PASS | `packaging/linux/server_package_test.sh`、`linux/client/tests/candy_sdwan_runtime_test.sh` |
| Core 格式与 transport 回归 | PASS | `cargo fmt --all -- --check`；163 passed / 0 failed |

## 尚未关闭的门禁

以下项目不能由上述 API/fixture 结果推定通过：

- **F08 完整进程池**：真实 OS worker manager、ready/exit 注册绑定、Proxy/SD-WAN 进程扩缩、live session/domain migration、跨进程 prepare/commit/abort、真实 drain deadline 和 IPC/packet late handling。
- **混合 listener**：Transport master 尚未接管生产公共 listener；Proxy 与 SD-WAN 的真实混合 session/packet/FD/全池配额路径未端到端验收。
- **TUN/Cloud/WAN 组合链**：生产 mTLS Cloud、真实 WAN、续期跨授权周期、多候选 QUIC failover 未在隔离环境组合验证。
- **平台门禁**：OpenWrt x86_64、IPQ40xx ARMv7、Android 真机的构建、安装、升级、回退和签名覆盖安装尚未形成本轮证据。
- **正式性能门禁**：1 Gbps 物理链路 B0、800 Mbps 上传/下载、UDP 64/512/1200 矩阵、CPU/GiB、小事务 p99、Proxy/SD-WAN mixed、多 worker 和 2 小时稳定性尚未通过。最新提交的独占 soak 正在构建后启动；在证据生成前状态为 NOT RUN。
- **procd**：systemd fixture 不代表 OpenWrt procd 的启动顺序、退避和重复实例锁验收。

## 发布结论

Core 和 Runtime 的局部修复已推送到各自 `main`，但完整发布门禁未关闭。当前不执行中央签名发布、线上节点更新或生产 listener 切换。后续必须先补齐上述隔离实现和门禁，再按 G0-G6 顺序发布。
