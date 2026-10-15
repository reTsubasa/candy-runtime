# SD-WAN 实施与门禁状态（2026-10-14）

## 最新集成结论（2026-10-15，executor v9）

完整 G0–G6 仍未通过。Core `bb9228e`、Runtime `531a6d1` 的六产物冻结构建
及 SHA256 复核 PASS。默认四轮上传 750.00/750.00、下载 750.00/749.81 Mbps；
干净诊断四轮上传 737.76/749.99、下载 750.02/743.56 Mbps。
两种模式诊断吞吐 PASS，输出完整性均 FAIL：默认 Core deadline 183、
TUNIO→Core 919；诊断 Core 1025、TUNIO→Core 630。参数未扩大。

新增执行器证据确认长 poll 既包含高 CPU 工作，也包含低 CPU 的长停顿；
不能将所有超时归因 VM。首次诊断轮的构建扰动已记录并使用新目录完整复测。
细节、测试限制和下一步见 `sdwan-executor-comparison-20261015.md`。
该冻结不含后续 PacketPort/remote staging、混合 listener 与 exact ACK 草稿，
不能据此证明这些实现或 Nginx 式完整代际交接通过。未操作生产或签名发布。

## 最新集成结论（2026-10-15，release v8）

本节优先于历史记录。完整 G0–G6 **仍未通过**，不签名发布或更新生产。

- 六产物冻结构建 PASS：Core `4703269`、Runtime `9931110`；manifest
  `cea491dff7713eec7c792d940bc71ef7445813c9b07e1e278f488d1f9832f860`。
  六个二进制与 source manifest SHA256 逐项复核通过。首次 v8 因 Runtime 根锁遗漏
  TUNIO 日志传递依赖而失败，原目录保留；同步根锁后继续使用 `--locked --offline`。
- 独占 4 × 60 秒、4 TCP 流、750 Mbps offered load 完成：上传
  749.997 / 749.993 Mbps，下载 750.009 / 750.008 Mbps。诊断吞吐 PASS；
  **完整性 FAIL**：TUNIO→Core deadline 393（r1 193，r3 200）。Core 两端 drop、
  stream read/write error、全部 admission subtype、TUNIO→TUN drop 均为零。
  参数仍为 100 ms、256 packets / 512 KiB，不以扩大期限关闭故障。
- 两次 deadline 突发的证据不同：02:38:29Z 主要是 expired-before-write，
  queue 约 143.6 ms，同期独立 guest heartbeat 最大约 43 ms，host event loop
  最大 66 ms；02:40:44Z 同时有 pending-send 约 125.8 ms 和 expired-before-write，
  独立 client heartbeat 最大 117.3 ms。两个上传样本客户端 quota throttling 均为零。
  跨轮仅一次对照不足以证明 TX yield 解释全部改善，也不能认定剩余全是 VM 调度。
- Core `af95057` 已修复完整 TransportOwner 身份过滤与重复/拒绝 prepared candidate
  误关活动连接。SD-WAN 42/42、严格 runtime Clippy PASS；该提交晚于 v8 冻结，
  不将 v8 吞吐归属于它。
- Runtime `ebc9d06` 已修复真实只读 v1/v2 健康探测、总期限和响应校验。3 probe、
  1 CLI、24 service/infrastructure 及 OpenWrt init shell PASS；新版目标二进制
  OpenWrt 25.12.5 VM v8 复验 PASS_NARROW_PROCD，涵盖真实 v2 健康探测、恢复、
  隔离和三次持久化有界重试，无虚假 netd_v2_request_failed。此轮未重跑真实 TUN
  专项；v7 已通过受限真实 procd/TUN/journal。完整生产 Agent/Core、升级回退和
  IPQ 硬件仍 NOT RUN。
- v8 冻结 shared-host lifecycle 与四域扩缩/隔离各实际执行 1 项测试，均 PASS；
  这是隔离 release fixture 证据，不等价于混合公共 listener 或同域 1/2/4 worker。
- 已采用 Nginx 代际切换基线，见 `sdwan-nginx-master-worker-design-20261015.md`。
  mixed listener 注册、Runtime receipt、原子快照与 drain 接线仍在实施，尚未测试通过。
  入口精确激活 ACK、候选 attachment 不抢占、旧 QUIC 新 session fencing、
  Runtime 旧 PID reap 和同域横向扩展须分别闭环。当前 stop-old 续期存在业务
  切换窗口；master 重启会关闭 QUIC，均不能称为 Nginx 式无损交接。

证据位于工作区 `docs/artifacts/sdwan-20261015/`：
`fairness-release-v8-tx-yield/`（失败）、`fairness-release-v8-lock-fixed/`（构建通过）、
`perf-fairness-comparison-v8/{summary.json,scheduler-analysis.json}`。
容器已清理；未操作生产。800 Mbps 正式矩阵、p99、UDP、多 worker mixed、
两小时续期、当前平台安装及 Android 签名升级仍未关闭。

## 最新集成结论（2026-10-15，release v7）

本节优先于下文历史记录。完整 G0–G6 **仍未通过**，不签名发布或更新生产。

| 专项 | 实际结果 | 证据及范围 |
| --- | --- | --- |
| 冻结六产物构建 | BUILD_PASS | Core `8454593`、Runtime `b4459ce`；manifest `a75dee1f0b9a8dd73a2fe3035d2c5b788a0766010f1c01833aceeefdf524b4d9`；排除工作区未提交修改，不包含仍在实现的 mixed listener 接线 |
| shared host lifecycle | PASS，恰好 1 项实际执行 | 真实失败域返回 `exit_code=1` / `domain_failed`；host 存活，forget 回收 completed/live；冻结 release helper |
| shared host 四域扩缩与隔离 | PASS，恰好 1 项实际执行 | 四签名域、扩缩、域/host 故障与基础设施保持；冻结 release fixture，不等价于平台验收或混合公共 listener |
| v7 独占 4 × 60 秒吞吐 | 诊断阈值 PASS | 上传 750.00 / 749.99 Mbps，下载 747.93 / 750.01 Mbps；750 Mbps offered load，不能作为 800 Mbps 验收 |
| v7 稳态完整性 | FAIL | TUNIO→Core deadline 1462，Core→TUNIO deadline 593；全部 admission subtype 拒绝为零，TUNIO→TUN 和 server 无输出丢包；100 ms 期限与 256 packets / 512 KiB 参数保持 |
| 平台静态复查 | 部分 PASS，Android 签名 FAIL | 5 项 parser 回归、4 个旧 x86 ELF、catalog 验签通过；本地 0.3.5 正式证书与 0.3.6 Debug 证书不同，覆盖安装与 required signer 静态门禁失败；旧包不证明当前源码平台通过 |

v7 第一上传轮客户端无 cgroup throttling，仍有 726 次 TUNIO deadline；下载轮同时
出现 runnable wait 和部分 quota throttling。新增每秒每线程 `schedstat`、CPU PSI、
VM CPU 采样支持继续区分系统调度与执行器阻塞，不能据此断言代码已无缺陷。
Core 排队峰值 432.291 ms，TUNIO 排队峰值 313.987 ms；v6 的 477/324 次历史失败
保留，当前没有完整性改善或故障关闭的结论。

证据位于工作区 `docs/artifacts/sdwan-20261015/`：
`fairness-release-v7-source-fixed/`、`shared-host-v7-lifecycle/`、
`shared-host-v7-four-domains/`、`perf-fairness-comparison-v7/summary.json`。
平台审计见 `sdwan-platform-offline-audit-20261015.md`。Docker aarch64 不替代
物理链路、OpenWrt/procd、IPQ40xx 或 Android 真机证据。两小时稳定性、正式
800 Mbps / UDP / p99 / 多 worker mixed、当前平台安装与签名升级仍未关闭。

## 最新集成结论（2026-10-15，v18 / release v6）

本节优先于下文历史记录。完整 G0–G6 **仍未通过**，不得据此签名发布或更新生产。

- 最新提交冻结 release v6 已完成六个二进制构建；manifest SHA256 为 `b1e8400b4005abccaf957fc00e0565de8794ecefe2bf307283b976447136395a`。冻结 Core `df63994`、Runtime `42a9abd`，不包含后续接收拥塞隔离和完整 Proxy OS worker 的增量。
- signed handoff v18 实际执行 3/3 PASS：连续负载 worker slot rotation、真实 mTLS Cloud 过期/恢复/续期、两个签名候选的路径故障恢复。每个专项均恰好执行一个真实测试；这是 exclusive slot 功能证据，不是共享多域池、无损交接或完整稳定性验收。v17 在测试前因冻结目录缺少 Git 元数据失败，失败证据保留；执行器已支持校验签名源快照。
- release v6 独占窗口完成 4 × 60 秒：上传 750.00 / 749.98 Mbps，下载 738.70 / 750.00 Mbps。诊断吞吐阈值 PASS，但完整性 **FAIL**：TUNIO to_worker deadline 丢 477 包、Core tun_write_deadline 丢 324 包。slot/byte/channel admission 拒绝均为零，说明 direction-local backpressure 消除了该轮队列槽拒绝，尚未消除输出超时。第一上传轮客户端/服务端均无 cgroup throttling，不能将全部超时归因 CPU quota。队列等待峰值 217.780 ms（TUNIO）/271.311 ms（Core）。750 Mbps 是诊断限速，不构成 800 Mbps 指标通过。
- 最新源代码 `cargo fmt --all -- --check` 与 `cargo check --workspace` PASS。跨 worker 中心认证 Core `6167ec9`：server 74/74、authority 3/3 和严格 Clippy PASS；完整 Proxy OS worker、共享多域 fixture 的结果须按各专项最新证据单独列示。
- Core `382c608` 的真实 Proxy worker 门禁 2/2 PASS：使用 bounded first control stream classifier 和 exact primed bytes replay，覆盖 TCP/UDP、坏认证、1→2→4→2→1、SIGKILL 替换、健康 worker 保持及 credit 归零。Core transport 179/179、server 74/74、packet-port 36/36 均通过。
- Core `fb9d75e` 的 listener classifier 只做有界 traffic-kind 预分类并保留原始首帧；它不执行认证，也不代表 SD-WAN 已完成跨进程数据面接线。Proxy master CLI 的实际启动/停止测试 1/1 PASS；master 仍是 Proxy-only opt-in 入口。
- 共享多域 host fixture v2 已完成四签名域、1→2→4→2→1、TUN/IO 身份保持、单域故障隔离和 host SIGKILL 后受影响域迁移；完整现场见 `docs/artifacts/sdwan-20261015/shared-pool-v2/shared-pool.json`。该证据为隔离 fixture，仍不能替代 OpenWrt/procd 或物理链路门禁。
- Core `327146e` / Runtime `51efa1b` 修复持续可读 raw PacketPort 接收饿死 sibling task 的确定性缺陷，并增加 packet port、stage、queue residence、send elapsed 和 deadline overrun 日志。参数仍为 256 packets、512 KiB、100 ms；新的公平性回归 PASS，但 v6 有载性能结果仍保留为完整性 FAIL，需 v7 复测确认。

证据：工作区 `docs/artifacts/sdwan-20261014/signed-handoff-gate-v18/`、`perf-renewal-freeze-v6-committed/`、`perf-renewal-build-v6/`，以及 `docs/artifacts/sdwan-20261015/perf-queue-comparison-v6/summary.json`。输出丢包、共享多域/混合 listener、正式性能矩阵与两小时稳定性仍待关闭；平台真机门禁仍 NOT RUN。

## 历史集成结论（v16）

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
