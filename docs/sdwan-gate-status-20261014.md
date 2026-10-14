# SD-WAN 实施与门禁状态（2026-10-14）

## 最新集成结论（v16）

本节优先于下文历史失败记录。完整 G0–G6 **仍未通过**，不得据此签名发布或更新生产。

| 专项 | 结果 | 范围与限制 |
| --- | --- | --- |
| 连续双向负载下的 worker slot rotation | PASS，1 项实际执行 | 原 TUN/TUNIO、授权 hash/expiry 保持；7 个阶段可用。下载切换窗口丢 80/73/69 包，并非无损；仅 one-domain-per-exclusive-slot，不是共享多域池验收 |
| 真实 mTLS Cloud 授权过期、恢复与续期 | PASS，1 项实际执行 | 独立隔离签发；不代表生产 Cloud 或两小时稳定性 |
| 两个签名候选的真实 QUIC 路径故障与恢复 | PASS，1 项实际执行 | 三秒收敛断言、双向有效 UDP、原 Core/TUNIO/TUN、授权未延长；故障窗口允许有界丢包，恢复后的流量完整性要求保留 |
| 低 RTT 数据流黑洞，不停止域 actor | PASS | Core `cc06b1a`；SD-WAN lib 36/36、重连专项 1/1、Clippy PASS |

隔离原始证据：工作区 `docs/artifacts/sdwan-20261014/signed-handoff-gate-v16/`。
执行器逐项确认恰好一项测试通过；失败保留退出码，下一项使用重新启动的隔离容器，防止 veth/namespace 残留污染。

已修复的具体缺陷：

- `93fd6ec`：控制器接管 Active owner 前没有 Guard，产生本地 unreachable 路由。v13 监控确认 20.9 ms 路由窗口，导致应用收到同步 `EHOSTUNREACH`；v16 已无该路由事件。
- `c9bfa24`：stop/spawn 两侧使用不配对的墙上时钟和单调时钟，跨秒会使授权 duration 自相矛盾。修复保留成对样本及原期限上限；TUNIO 日志明确拒绝谓词。该缺陷有确定性复现，v14 的旧组合错误日志不能单独证明具体谓词。
- `cc06b1a`：数据路径探测被 1 秒指标循环和 5 秒周期拖延，候选恢复耗时过长。独立探测调度、RTT 自适应期限与已建立候选的重试退避修正。v15 实测 2448/2341 ms；正式专项加入 <=3000 ms 断言。
- `123fb58` / Runtime `13e62fc`：PacketOutput 有界 drain 和过期包处理已提交，release 队列对照尚待执行，不能声明完整性已修复。

尚须完成：共享多域进程池与完整 Proxy 认证/session IPC、混合总预算与故障隔离、正式性能/两小时续期、平台安装回退、正式 APK 证书覆盖安装。Docker aarch64 不替代物理 x86_64 1 Gbps 或真机证据。

## 已完成并推送

| 项目 | 结果 | 证据/提交 |
|---|---|---|
| WorkerPool 角色配额、credit 回收、连续扩缩 | PASS（API级） | candy-core `319e2b2`；后续 WorkerPool 25 passed |
| ownership prepare/commit/abort、单调 fencing、drain deadline、迟到 release | PASS（API级） | candy-core `94ffe43`、`a2b0fe9`；修正 failed source/target reservation，transport 167 passed |
| OS worker manager 启动、ready/exit、连续扩缩和有界退避 | PASS（实际子进程/隔离测试） | candy-core `7b7f08b`；6 passed，含 2 child helpers；未接入业务迁移 |
| fixture 独立策略/Grant TTL | PASS（仅测试 fixture） | candy-core `064dcab`；生产一小时独立 worker 上限保留 |
| systemd netd 独立重启 | PASS（隔离 Docker/fake payload） | `systemd-supervisor-gate-20261014.json`：netd PID 118→151，Agent PID 保持 121 |
| systemd Agent SIGKILL 恢复 | PASS（隔离 Docker/fake payload） | NRestarts 0→1，Agent PID 121→210 |
| systemd 持续失败有界重试、修复后恢复、停止隔离 | PASS（真实 PID1/fixture payload） | Runtime `b479e76`；5 次后停止，reset-failed 后恢复，netd 保持 |
| Cloud mTLS HTTP500 与真实 QUIC/TUN peer 恢复、拒绝重复 Agent | PASS（隔离组合） | Runtime `d9dc630`；126 次已验证客户端证书的 HTTP500；不是 Cloud 签发续期门禁 |
| Linux Runtime 打包与缓存行为 | PASS | `packaging/linux/server_package_test.sh`、`linux/client/tests/candy_sdwan_runtime_test.sh` |
| Core 格式与 transport 回归 | PASS | `cargo fmt --all -- --check`；163 passed / 0 failed |

## 尚未关闭的门禁

以下项目不能由上述 API/fixture 结果推定通过：

- **F08 完整进程池**：OS lifecycle manager 已单独实现并验证；Proxy/SD-WAN 业务接线、跨进程 domain placement、live session/domain migration、真实 drain 与混合业务尚未关闭。
- **混合 listener**：Transport master 尚未接管生产公共 listener；Proxy 与 SD-WAN 的真实混合 session/packet/FD/全池配额路径未端到端验收。
- **TUN/Cloud/WAN 组合链**：生产 mTLS Cloud、真实 WAN、续期跨授权周期、多候选 QUIC failover 未在隔离环境组合验证。
- **平台门禁**：OpenWrt x86_64、IPQ40xx ARMv7、Android 真机的构建、安装、升级、回退和签名覆盖安装尚未形成本轮证据。
- **正式性能门禁**：1 Gbps 物理链路 B0、800 Mbps 上传/下载、UDP 64/512/1200 矩阵、CPU/GiB、小事务 p99、Proxy/SD-WAN mixed、多 worker 和 2 小时稳定性尚未通过。最新 2 小时 soak 因授权到期在 58/120 个样本中止，且 9 个低速样本，结果 FAIL/INCOMPLETE，详见 `sdwan-perf-latest-soak-report-20261014.md`。
- **procd**：systemd fixture 不代表 OpenWrt procd 的启动顺序、退避和重复实例锁验收。

## 发布结论

Core 和 Runtime 的局部修复已推送到各自 `main`，但完整发布门禁未关闭。当前不执行中央签名发布、线上节点更新或生产 listener 切换。后续必须先补齐上述隔离实现和门禁，再按 G0-G6 顺序发布。

## 本轮有载续期诊断

- 一小时实际授权来自 fixture 的 Segment/Site 策略期限；`compile-control` 取 Segment、Projection、Grant 最小期限。延长 Grant 单独无效。
- `perf-renewal-smoke-v2` 复现旧 Core 在新候选连接建立后重连，服务端按同 attachment 替换 lane，随后候选失败、事务撤销、domain supervisor 等待新计划，不能算通过。
- Runtime 增加已验证/已持久化签名候选之后的认证 stop-old 屏障，保留 TUNIO/netd；Core `e6e6535` 对明确 authenticated lane supersession 停止抢回同一 policy。普通网络故障仍重试。
- `perf-renewal-smoke-v3` 使用含 Runtime stop-old 屏障的冻结产物，真实有载续期两次，epoch 1→2→3，同 IO/TUN，未永久停流。4 个 20 秒样本中 3 个约 750 Mbps，另一个上传 658.94 Mbps；短测仅提供交接功能证据，吞吐结果 FAIL，不能关闭稳定性。
- 12 分钟固定参数诊断 `perf-queue-diagnostic-v1` 已完成 12/12。r12 下载仅 590.74 Mbps，吞吐与丢包门禁 FAIL；实际 queue-full 为 25,881 次，slot 细分与其重叠不能累加，deadline 153 次，byte/channel 为零。下载队列峰值 256，上传没有输出拒绝。qdisc drops 为零；部分无 CPU throttling 的样本仍超时，不能只归因 CPU quota。前两样本可能受其他构建影响，后续为静默窗口。Core `fce58c5` 已修正诊断分类重复增加 drops 的缺陷，旧原始数据保留。
- IPC nonblocking fast path 直接尝试 fd，避免 Tokio readiness cache 尚未填充时虚假不可写；异步发送仍使用 reactor readiness 并在实际 EAGAIN 时清理。Core host PacketPort 24/24 与 clippy PASS；Linux 满缓冲等待/恢复专项待实跑。macOS 满队列返回 ENOBUFS，该 Linux EAGAIN 专项不用于推定 macOS 通过。

Docker aarch64 veth 结果不替代 x86_64 物理 WAN、OpenWrt 或 Android 真机验收。所有构建/运行原始证据保留于工作区 `docs/artifacts/sdwan-20261014/`。

## Cloud candidate → domain plan bridge（2026-10-14 v4）

- Runtime 将经签名验证并持久化的 Cloud activation 转换为 domain plan：模板保留本地 TUN/IO、基础设施和 worker placement；Cloud 仅提供签名策略，并与本地 underlay exclusions 合并。activation generation、descriptor、文件权限和路径均经过约束；Core `compile-control` 在 deadline 内验证 immutable snapshot。candidate 无效或编译失败时保留此前 published plan；Supervisor shutdown 会取消编译。
- 实现已提交：Runtime `ba747ca`；Cloud renewal 测试接线 `627da65`。
- 隔离证据 `docs/artifacts/sdwan-20261014/runtime-cloud-bridge-v4/renewal/run.log`：真实 mTLS Cloud 签发 2 次授权，318 个请求均验证客户端证书；首次授权过期时流量被拒绝，Cloud 恢复后第二个 activation 发布、新授权生效，原 TUN 上 ICMP 恢复；Agent PID、IO PID、TUN 身份保持不变。专项测试 1/1 PASS。Agent feature suite 103/103 PASS，Clippy 与 release build PASS。
- 有载 worker placement 目前 FAIL，证据在 `docs/artifacts/sdwan-20261014/runtime-cloud-bridge-v4/placement/run.log`。placement revision 1→2、worker 1→2 的切换中，旧 worker 对端 tunnel 在新 peer 全面可用前关闭；服务端记录 `route_has_no_active_peer=62`，持续 UDP upload socket 返回 `EHOSTUNREACH` 并退出。TUNIO/netd 基础设施仍存活、io_epoch 不变且自身队列 drop 为零，因此这是对端业务 owner handoff 的数据面窗口，不是 Cloud bridge 或 TUN teardown。该结果维持 F08/live placement 门禁 FAIL；须修复原子 peer/route handoff 并在连续双向负载下复测，不能弱化流量存活断言。
- v4 测试文件同时含另一并行任务新增的 CandidateFailover 草稿，以上 `627da65` 只提交 CloudRenewal 两个 hunk；未将并行改动混入提交。
- 本门禁在隔离 Docker `NetworkMode=none`、privileged 容器完成；没有访问或切换线上节点。性能门禁仍 FAIL，bridge 专项短测不构成 800 Mbps 验收，也不构成正式发布许可。
