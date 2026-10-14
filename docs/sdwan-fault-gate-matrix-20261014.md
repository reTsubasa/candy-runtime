# SD-WAN 故障门禁核对（2026-10-14）

本清单把现有实际证据与测试标准中的 F01/F02/F03/F04/F05/F06/F08/F11/F12/F13/F15/F16 分开记录。`PASS` 仅表示对应注入和证据完整；单元测试、模拟状态机或性能快照不能代替真实故障门禁。性能测试不在本清单中重复。

## 当前证据

| 门禁 | 当前结论 | 已有证据 | 缺口/限制 |
| --- | --- | --- | --- |
| F01 worker kill | PARTIAL | `final-signed-cli-unified-core-rebind.log`：真实 Core 两次替换、owner epoch 1/2/3、同 TUN/ICMP；`final-signed-cli-takeover-expiry.log`：Agent SIGKILL 后接管 | Proxy worker 与 SD-WAN 混合池隔离、旧 IPC 迟到请求尚未同一用例覆盖 |
| F02 慢消费者/满队列 | PASS（fixture 受限） | `worker-isolation-final-gates-diagnostics-v2/result.json`：真实 QUIC worker fixture slow worker 停止、健康 worker 30 个 latency 样本与 5 个吞吐样本、分段 QUIC/auth/Unix/data/payload p99、credit 回收；scaling 同目录 PASS | 仅为独立 Proxy fixture；生产 Proxy+SD-WAN 混合池、真实 TUN 和完整进程迁移仍未覆盖 |
| F03 Peer/前缀丢失 | PASS（受限） | `netd-v2-kernel-final.log`：真实前缀route/ifindex；`final-signed-cli-scoped-namespace.log`：真实签名Peer离线/恢复、同TUN | 多 peer 物理/真实 QUIC 候选 failover 未执行 |
| F04 过期/旧 epoch | PASS（受限） | v4 `signed-commit-restart.log`：实际expiry→fresh Grant、授权commit丢ACK恢复、netd重启后精确拒绝`stale_forward_owner`、`io_owner_alive`；同TUN/Core/IO继续ICMP | 完整混合业务迟到IPC仍需单独覆盖 |
| F05 Agent kill | PASS（受限） | `final-signed-cli-takeover-expiry.log`、fresh Grant evidence：有效期内 Agent 接管，过期后流量拒绝 | 同时存在 Cloud 同步失败和 Agent kill 的组合尚未执行 |
| F06 netd/TUNIO 退出 | PASS（普通IO/netd scoped）/FAIL（续期后IO） | v9普通IO两轮真实SIGKILL恢复PASS；F11链netd重启PASS；v9新Grant后IO失败日志完整 | 续期后IO恢复仍在epoch/fence及rollback处失败，最新修复需实际复验 |
| F07 netd+TUNIO 同时退出 | PASS（受限） | `signed-netd-io-gate-v10/`：两轮真实双SIGKILL，1993/2138ms恢复、sameifindex14/地址MTU、旧epoch/第二reader拒绝、真实ICMP | netd由harness重启，未覆盖systemd/procd自动拉起；故障期间carrier可下降但持久TUN身份不变 |
| F08 并发扩缩容 | NOT RUN（完整门禁） | `transport-worker-concurrent-pool-faults.log`：1/2/4 worker isolation、epoch rejection、credit 归还 | 没有 1→2→4→2→1 连续 migration barrier、sticky connection 和迟到释放的完整序列 |
| F11 commit 回包丢失 | PASS（真实链，受限） | v4 `signed-commit-restart.log`与`…evidence.json`：真实`ForwardCommitAuthorized`已成功后丢1次回复、相同owner恢复、netd重启和Agent接管继续真实ICMP | 重复rollback/prepare/失败候选和混合业务仍需独立覆盖 |
| F12 Cloud 错误/候选 | PASS（受限） | `cloud-mtls-http-faults.log`：生产sync_once_with_retry真实loopback mTLS，HTTP500/304、连接reset、恢复、过期304后unconditional fetch；unified Agent证据证明Cloud失败不停止域 | mTLS测试未与实际TUN/Agent跨WAN接成同一故障链；多Segment rollout未执行 |
| F13 renewal 周期/WAN | PASS（受限） | `signed-cli-fresh-grant-renewal-first.log`：过期、fresh Grant、Agent takeover、真实 ICMP、同 TUN | 完整 WAN 断开跨周期后恢复未执行；当前 fresh fixture 是本地签名服务 |
| F15 Transport kill/bind conflict | PASS（现有public server受限） | `signed-public-listener-gate-v8/`：实际第二Core public bind被拒、已有ICMP继续，实际server SIGKILL及人工重启后同client Core/IO/TUN恢复 | 当前是整Core server，并非独立master；未覆盖Proxy/SDWAN混合业务与自动server拉起 |
| F16 混合配额 | NOT RUN | `transport-worker-concurrent-pool-faults.log` 只有 SD-WAN worker pool；优化性能快照只有单 SD-WAN domain | Proxy+SD-WAN 同 listener、混合 session/replay/queue 配额和存量连接保护未执行 |

## 实际重跑结果

最新冻结目录为`docs/artifacts/sdwan-20261014/{core,runtime}-fault-v4`，逐文件SHA256、Git SHA和dirty状态保存在`signed-commit-restart-gate-v4/source-manifest.json`。Core基于`ef3e9f8`，Runtime基于`3c704b3`，存在清单记录的未提交测试/修复。所有测试在`--network none`隔离privileged容器执行，没有访问线上节点。

| 执行项 | 结果 | 证据 |
| --- | --- | --- |
| Linux Core、Runtime feature build | PASS | `build-core.log`、`build-runtime.log`；启用`candy-sdwan-agent/experimental-tunio-rebind` |
| Linux bootstrap cap | PASS，1 test | `tunio-bootstrap-cap.log`，原monotonic cap不能因wall time重算延长 |
| WorkerPool确定性慢消费者/配额隔离 | PASS，10 tests | `worker-pool-faults.log`；一个worker持满本身credit、另一个128次成功；按role隔离不等于跨role共享总预算 |
| 真实commit回包丢失+netd强杀重启 | PASS，1 test | `signed-commit-restart.log`、`signed-commit-restart-evidence.json`；fresh Grant、同TUN/Core/IO、Agent接管 |
| 真实TUNIO强杀/pair恢复 | FAIL | `signed-io-pair.log`；首次control socket地址冲突，重试epoch/fence不前进，45秒未恢复 |
| 新Grant后TUNIO强杀 | NOT RUN | runner在上一项FAIL后停止，不能写为PASS |

上述证据均位于`docs/artifacts/sdwan-20261014/signed-commit-restart-gate-v4/`。失败已交回实现修复；必须重新冻结源码并重跑，不能用上轮netd通过推算TUNIO恢复通过。

### v5 修复重跑

`signed-commit-restart-gate-v5/`冻结Runtime最新修复并继续使用Core v4：Linux feature build、bootstrap cap、10项WorkerPool测试及真实F11/netd链再次PASS。逐文件source manifest与`binary-sha256-early.log`保留实际构建版本。

TUNIO强杀仍为FAIL：消耗epoch/fence递增已生效（实测2→3→…23），但每次pair启动仍报`Address already in use (os error 98)`。新IO尚未记录`tunio_ready`，因此不能仅据Agent的`business_worker_exited`认定为Core故障；已要求给各个附属control/packet/authority socket bind加精确path/module上下文，并检查死亡IO留下的附属端点回收。45秒未恢复，TUN身份始终保持。newGrant之后强杀和newGrant与IO死亡同时到达两项因runner先前FAIL停止，仍NOT RUN。

### v6 修复重跑

`signed-commit-restart-gate-v6/`保留完整运行日志、逐文件source manifest和`binary-sha256-post-failure.log`。build、cap、10项WorkerPool和实际commit/netd链再次PASS。同一Grant下两次真实TUNIO SIGKILL恢复PASS，恢复时间分别2169ms、2090ms，ifindex/地址/MTU不变，旧Core和IO身份失效、epoch递增、旧owner与第二reader被精确拒绝。

新Grant成功续期后再杀IO仍FAIL：StageAuthority/AttachAuthorized/commit均成功，随后pair恢复报`live infrastructure status is not bound to actual IO process/epoch/capability`且不可重试，45秒未恢复。该结果不能被普通IO恢复通过覆盖。newGrant与IO死亡同时到达一项在runner中未执行。实现侧已补schema2 Probe确认与legacy status发布之间的就绪等待，需继续实际验证。

### v7 Linux 单测

`signed-commit-restart-gate-v7/`build PASS；Agent Linux lib为97/98，唯一FAIL是新Unix socket清理测试夹具未把替代socket设为0600。安全权限校验拒绝了夹具；fixture修正已提交`7082fd3`。本次signed故障用例在前置单测失败后没有执行。

### v8 实际扩展门禁

v8冻结Runtime `7082fd3`及当前signed harness。Linux Agent lib 98/98、cap1、WorkerPool10、实际F11/netd链、普通IO强杀两轮PASS。续期后IO强杀FAIL：先撤committed再撤candidate，前者已清除candidate，后者返回`stale_forward_owner`并停止域恢复。实现侧已将撤销顺序修正为candidate后committed，同时保留精确owner匹配。

F15独立执行PASS，证据位于`signed-public-listener-gate-v8/`：第二个实际Core server绑定相同public UDP端口失败，stderr精确包含`Address already in use`；原listener继续实际ICMP。随后原server SIGKILL，真实流量失败，人工重启server后原客户端Core/IO和TUN恢复ICMP。本用例覆盖现有整Core server，不代表已实现独立Transport master或Proxy/SDWAN混合业务。

F07独立执行在故障后身份断言提前停止，证据位于`signed-netd-io-gate-v8/`。原TUN ifindex14、地址、MTU保留，但全部FD关闭后Linux carrier变为DOWN/NO-CARRIER；harness原先比较完整JSON，将动态carrier误判成TUN身份变化。v9改为仅在双进程全FD故障期间严格比较ifindex、名称、MTU、地址、qdisc、txqlen和稳定flags，恢复后仍要求完整原JSON及真实ICMP；本次没有走到恢复断言，不能写成F07通过。

### v9 续期恢复和 F07

v9 Agent Linux lib98/98、cap1、WorkerPool10、F11/netd、普通IO两轮再次PASS。续期后IO仍FAIL：候选撤销顺序修复生效，新IO实际启动到owner_epoch3，但随后又进入signed renewal到owner_epoch4，netd以generation/fencing不前进拒绝；回滚还暴露`Revoke cannot supply an envelope`。完整日志在`signed-commit-restart-gate-v9/signed-renewed-io-pair.log`。该门禁仍阻断发布。

F07 v9独立测试实际首轮已恢复真实ICMP和新Core/IO，但最终完整JSON断言因`operstate UNKNOWN→UP`停止。两者都adminUP/LOWER_UP，ifindex/地址/MTU未变。最终harness要求故障期间基础设施身份和配置严格保持，恢复时额外要求adminUP、LOWER_UP、无NO-CARRIER，operstate允许Linux合法的UP/UNKNOWN；不再用展示状态字符串判定接口被替换。

F07独立v10 PASS两轮，证据在`signed-netd-io-gate-v10/signed-netd-io-pair-recovery-272-evidence.json`。每轮真实netd+IO SIGKILL，人工重启netd，Agent自动替换Core/IO，恢复1993ms、2138ms；ifindex始终14、地址/MTU保持，worker epoch递增2/3、旧owner精确拒绝、重复reader精确拒绝、实际ICMP恢复。这里的netd重启由harness执行，不能宣称已覆盖systemd/procd自动拉起。

## 初期构建记录

`candy-tunio/tests/signed_cli.rs` 新增 ignored test
`signed_cli_lost_commit_reply_and_netd_restart_preserve_original_tun`，它要求：

1. `signed_commit_reply_loss` 对真实 `ForwardCommitAuthorized` 执行后丢弃 ACK，并写入结构化证据；
2. Agent/Core 保持 committed owner，随后杀掉实际 netd；
3. 原 TUN 的 ifindex、地址、Core/TUNIO identity 和真实 ICMP 在 netd 停止期间保持；
4. 重启 netd 后查询恢复相同 owner；旧 worker epoch 必须返回 `stale_forward_owner`，重复 `InfraAcquireIoFd` 必须返回 `io_owner_alive`。

本轮尝试构建时，Agent 正在同时编辑 pair recovery，现有工作树缺少
`PairRecoveryRequired`、`NetdUnavailable`、`recover_pair` 和 `recovery_plan`，因此 Runtime
构建失败，测试没有执行。失败日志：
`docs/artifacts/sdwan-20261014/signed-commit-restart-gate/build-runtime.log`。
Core 构建成功，容器和 `/build` 已释放。之后v2因为测试镜像缺`ping`未进入故障注入，v3因cap test误用根workspace命令停下；这些失败记录保留。v4已修复harness并执行真实故障链，结果如上。

## 可执行缺口

- 修复pair恢复残留控制端点和消耗epoch持久化后，重新执行真实TUNIO与newGrant组合门禁。
- 在隔离 Linux namespace 使用相同 TUN 载体，分别执行 netd SIGKILL 和 TUNIO SIGKILL；保存基础设施与业务状态，确认没有第二 reader。
- 增加 1→2→4→2→1 worker 连续扩缩和迟到释放 runner；现有一次性 worker fault 证据不能替代。
- 建立 Proxy+SD-WAN 同 listener 的混合配额 runner；至少验证到达总 session/packet/byte 上限时只拒绝新对象，存量两类业务继续。
- 真实 public listener kill/bind conflict 与完整 Cloud WAN outage 跨续期周期仍需在隔离测试环境执行。

所有缺口均是测试环境事项，不访问线上节点，也不把性能矩阵或单元测试推算成故障门禁通过。

### v11 Linux 全门禁续期复验（2026-10-14）

证据目录：`docs/artifacts/sdwan-20261014/signed-commit-restart-gate-v11/`。所有用例在 `NetworkMode=none` 的隔离特权容器执行；没有访问生产节点。冻结清单记录 Runtime 基线 `cf7ea733`（冻结工作树另含 `experimental_tunio.rs` 与 `signed_cli.rs` 的未提交内容），Core 基线 `ef3e9f8`（含清单所列未提交 egress/server 修改）。因此本轮证明的是清单哈希对应的构建产物，不能把它表述为纯净提交构建。Runtime 当前另有提交 `1aa5c91`，未进入该冻结清单；针对 recovery cap 的最后提交需要后续独立重跑。

| v11 用例 | 结果 | 证据及边界 |
| --- | --- | --- |
| Runtime Linux Agent 单测 | PASS | `agent-lib-linux.log`：99 passed、0 failed。 |
| TUNIO bootstrap monotonic cap | PASS | `tunio-bootstrap-cap.log`：1 passed。 |
| worker 慢消费者/隔离测试 | PASS | `worker-pool-faults.log`：10 passed；只覆盖现有池故障语义，不覆盖完整水平扩缩迁移。 |
| 签名 commit 丢回复、netd SIGKILL/restart、Agent 接管 | PASS | `signed-commit-restart.log`：1 passed；结构化证据证明同 TUN/Core/IO、丢 ACK 后提交可确认、旧 epoch 与重复 reader 被拒、真实 ICMP 在前/故障期间/恢复后成功。 |
| TUNIO 双次 SIGKILL 并恢复 pair | PASS | `signed-io-pair.log`：2 次实际 IO SIGKILL，原 TUN 身份保持、epoch 前进、旧 owner/第二 reader 被拒、真实 ICMP 恢复。 |
| 新签名授权续期后再杀 TUNIO | PASS（v11 冻结哈希范围内） | `signed-renewed-io-pair.log`最终用例 exit 0：2 次 IO SIGKILL、pair 恢复、原 TUN 保持、tamper 被拒、Agent 接管与真实 ICMP 通过。日志前段保留了早先尝试的签名不匹配重试记录，最终测试通过不能抹去该历史；由于冻结源早于 Runtime `1aa5c91`，最后一次 cap 提交仍需在新冻结构建中复验。 |
| 新授权、WAN 跨期中断、Agent/Core/IO 故障并发 | PASS（恢复/安全断言） | `signed-concurrent-grant-io.log` 与 `signed-concurrent-grant-io-evidence.json`：WAN 在旧授权过期期间不可达；旧 IO 与候选 Core 在 Agent 启动前均退出；新 IO/Core 和有效本地签名授权被接管，原 TUN ifindex/地址/MTU 保持，权限证明哈希匹配、tamper 拒绝、真实 ICMP 成功。签名服务是本地 fixture，不是线上 Cloud。 |
| public UDP listener 冲突与 server Core 退出 | PASS（既有拓扑受限） | `signed-public-listener.log`：冲突被精确拒绝，原 listener 流量恢复；属于整 Core server，不等价于独立 Transport master 或 Proxy/SD-WAN 混合 worker。 |

v11 结束后仍不可宣称所有 SD-WAN 门禁关闭：完整 1→2→4→2→1 worker migration/sticky-flow/迟到释放、Proxy 与 SD-WAN 同 listener 的混合配额、生产 Cloud mTLS 与真实 TUN 跨 WAN 续期故障链、systemd/procd 自动恢复、真实多候选 QUIC failover 仍为缺口。性能门禁是独立结果，不可由这些恢复测试推定。`signed-commit-restart-gate-v11/container.json` 记录测试容器 `candy-signed-commit-restart-gate-20261014`；容器只以 sleep 保持挂载，实际用例均已结束，清理后才将共享 `/build` 视作空闲。

### 并发用例断言审查与新源码门禁

`candy-runtime/linux/common/apps/candy-tunio/tests/signed_cli.rs` 的并发授权/TUNIO 故障测试已按实际生命周期复核，并提交推送至 Runtime `bef990a`（基于 `1aa5c91`）。审查没有删减或放松任何既有通过条件：仍要求原 TUN 身份/地址/MTU不变、实际签名 authority hash 一致、authority revision 前进、授权期限与 IO 状态匹配、同域仅一个 TUN fd、tampered Grant 不激活流量、旧 owner/epoch 被拒绝、真实 ICMP 恢复及 Agent 接管。

测试时序证据额外收紧：SIGKILL 旧 TUNIO 后，最多等待 5 秒并以 PID/starttime process identity 确认其退出，然后才启动新 Agent；若未确认死亡即失败。证据字段描述的是“新 Grant 已准备”和“IO SIGKILL 已确认死亡”，不预设恢复成功。`cargo fmt --manifest-path linux/common/apps/candy-tunio/Cargo.toml -- --check` 通过。此前 v11 并发 PASS 发生在这项死亡确认断言加入前，因此必须在 `bef990a` 冻结源码后重跑并发场景；Renewed IO 专项的 `1aa5c91` 冻结重跑由独立 Linux 门禁执行中，不能与并发重跑共用或覆盖同一个 build 目录。

### 剩余门禁执行边界

**无需先改实现，可直接在隔离 Linux 补跑：**

- 用 Runtime `bef990a` 和匹配的 Core 冻结构建重跑：并发签名 Grant/WAN 跨旧期限中断/IO 与 Agent 同时故障；保留真实签名验证、确认旧 IO 已退出的断言、TUN 身份和 ICMP 证据。
- 在现有实现下补 systemd/procd 的真实 supervisor 自动拉起测试（使用专用 VM/测试路由器和独立 service unit，不操作生产）：区分 systemd 对 Agent/netd 的恢复兜底与 Agent 对 Core/IO/worker 的域级恢复；检查重复实例锁、启动顺序、退避和 shutdown 截止。
- 扩充 F12/F13 的隔离 Cloud 故障链：生产 mTLS 形态的 loopback fixture 与真实 TUN 同场，覆盖 HTTP 失败/断连、WAN 跨授权期限、Cloud 恢复后签名续期、不中断其他域/Proxy；只要现有 fixture 支持接口注入，可先做测试不改变线上流程。
- 真实多候选 QUIC failover、Peer/前缀丢失和恢复的 signed namespace 测试；已有单候选签名 runner 可作为隔离 harness 基础。
- 物理 1 Gbps 链路的现有单进程 B0 与当前实现交错基线：必须先验证直连基线至少 900 Mbps，然后执行上传/下载单流及多流、双向、稳定时延和资源采集；此结果只能作为当前实现基线，不代表未实现 worker 架构已通过。

**必须先实现或定义契约，再开始端到端验收：**

- 1→2→4→2→1 worker 的连续扩缩、rolling drain、sticky connection/session 迁移及迟到 IPC/重复释放：当前只有一次性 worker fault 测试，无 pool manager/完整迁移 runner。
- Proxy 与 SD-WAN 同 listener 的真实混合数据面、role/session/queue/byte/FD 共享总预算和配额耗尽隔离：当前没有混合 worker 路径，先定义全局预算与拒绝新对象语义，再实现运行时路径和专项 runner。
- 独立 Transport master 与 Proxy/SD-WAN worker 进程边界：当前 public listener 测试只是完整 Core server bind 冲突/退出，不能验收 QUIC 鉴权 handoff、stream/datagram 所有权交付、master 故障隔离或 worker 水平扩展。先完成生产 Proxy Session 抽取和传输 IPC 契约。
- 多域自动创建、迁移、清理及跨平台进程级 RSS/cgroup 预算：当前是静态域配置/线程预算原型，需先定义资源调度和生命周期，再做容量矩阵。
- 真实 Android/Go 混合 wire 兼容、OpenWrt x86_64/IPQ40xx 安装升级回退、签名包运行中版本验证，以及受控 canary：先形成对应构建产物和部署流程；不将开发机的 Linux namespace 证据替代平台验收。

### Runtime v12 续期恢复与并发用例（2026-10-14）

证据目录：`docs/artifacts/sdwan-20261014/runtime-renewed-io-v12/`。冻结源码 Runtime `bef990ab8d5cc36ae3bb203f9784030e7ab93e69`、Core `9e43d9405634586d19d7c597d0ba6109a1b954ee`；manifest SHA256 `a5874614ec8158a4609e29ed6e3663350e831450385b7a5e97dd3dba949f127d`。容器使用 `NetworkMode=none`，未访问线上节点。

| 用例 | 结果 | 证据及限制 |
| --- | --- | --- |
| 新签名授权续期后 TUNIO 两次 SIGKILL 并恢复 | PASS（隔离 Linux） | `report.json`、`gate-bef990a/signed-renewed-io-pair.log`、`signed-io-pair-recovery-5406-evidence.json`；恢复 2596ms/2395ms，原授权 cap 不延长、同 TUN、epoch 递增、旧 epoch/第二 reader 拒绝、真实 ICMP 恢复。 |
| 新 Grant 准备与旧授权到期期间 WAN/IO 并发故障 | PASS（隔离 Linux） | `report.json`、`gate-bef990a/signed-concurrent-grant-io.log`、`signed-concurrent-grant-io-evidence.json`；SIGKILL 确认旧 IO 退出后才启动 Agent；篡改 Grant 被拒、接管与真实 ICMP 恢复。 |

本门禁以本地签名 Grant fixture 代替生产 Cloud；不覆盖真实 WAN 硬件、Cloud 续期服务、OpenWrt、Android 或完整 Proxy/SD-WAN worker 架构。早期 signature-mismatch 文本是 tamper rejection probe；报告只将最终签名恢复断言标记通过，保留原始日志。

### WorkerPool 连续扩缩池级门禁（Core `a94f814`）

`candy-core/crates/candy-carrier-transport/src/worker_pool_shared_tests.rs` 新增连续 `1→2→4→2→1` 测试并已推送。`cargo fmt --all -- --check` 与该单项测试通过。测试验证新连接分布、存量 owner sticky、draining worker 不接新 owner、存量 lease/ByteCredit 阻止 retire、credit 释放后 retire、迟到重复 release 拒绝；结果打印 `remaining_connections=728`。

这是 WorkerPool API/lease 语义的**池级部分通过**，不关闭 F08：当前没有生产进程池生命周期、drain completion ACK 或 live connection/session 迁移；扩缩时连接会留在原 owner，完成 drain 依赖对应连接正常释放。必须实现并集成进程管理和 live ownership/drain 协议，再执行端到端 F08。该测试不能证明真实 Proxy Session、SD-WAN domain dispatch 或同 listener 混合业务已经迁移。
