# SD-WAN Master/Worker 生命周期设计

状态：设计基线，作为 mixed listener 默认启用前的实现与测试约束。

## 1. 参考原则

本设计采用 Nginx 的三个关键行为：

1. master 先校验配置并准备资源；校验或准备失败时保留旧代继续工作。
2. 新代 worker ready 后才原子发布；旧代停止接收新工作，但继续服务已有连接，直到排空或到期。
3. master 负责生命周期和控制消息，worker 负责数据面；单个 worker 的请求错误、退出或慢消费者不能退出 listener、TUN、其他 worker 或另一业务角色。

Nginx 的信号语义映射为本项目的事务语义：`reload` 对应 prepare/commit，`quit` 对应 drain，`term` 对应受控快速停止，`reopen` 对应日志重开。这里不复制 Nginx 的 socket 实现细节；QUIC 连接仍由 Transport master 持有。

## 2. 进程层级与边界

```text
procd/systemd
  +-- Runtime Agent (配置与发布协调者)
  |     | Cloud 同步、续期、prepare/commit、registry、drain/reap
  |     +-- Transport Listener Master (UDP/QUIC、TLS、identity、replay/admission、IPC)
  |     |     +-- Proxy worker pool (N 个，master 内 manager 唯一监督)
  |     |     +-- SD-WAN worker pool (M 个)
  |     +-- SD-WAN worker 的唯一监督、恢复和有界退避
  +-- netd/TUNIO infrastructure (独立常驻，不属于任一业务 worker)
```

这是职责与监督关系，不新增第三套 supervisor。Runtime Agent 协调配置发布，Transport master 接受已提交的路由与注册表。当前实现中，Proxy PID 的唯一本地监督者为 `ManagedProxyWorkerHost` manager，SD-WAN PID 的唯一本地监督者为 Runtime；registry 不启动或重启 worker。master 不另起 Cloud/续期循环，Agent 不竞争重启 Proxy PID。netd/TUNIO 的具体启动路径须与现有进程身份和 journal 一致，禁止由多个层级竞争监督同一个 PID。

### Runtime Agent

- 读取并验证 Cloud candidate、签名、版本、能力、资源预算和路由域。
- 生成 immutable `PlanSnapshot`，执行 `prepare -> ready receipt -> atomic publish`。
- 协调 domain/role/worker registry、owner epoch、drain deadline 和发布重试；监督 SD-WAN worker。
- 只发送控制消息，不逐包参与数据面；Proxy worker 生命周期委托 master 的已有 manager，procd/systemd 仅兜底 Agent/基础设施。

### procd/systemd

- 仅监督 Agent、netd/TUNIO 的启动、退出码和有界退避。
- 不读取 Cloud、不做业务 worker placement、不重复做 drain。
- Agent 失联时不删除 TUN；已有有效业务按授权继续，过期后仅撤销 forwarding。

### Transport Listener Master

- 独占公共 UDP listener、QUIC/TLS handshake、完整 `TransportOwner` 身份和全局 admission/replay。
- 根据已激活的内存 registry 选择 role/domain worker；域 hint 只能缩小候选，不能授权。
- 维护 IPC 通道、连接到 worker 的 sticky owner、旧 epoch 过滤、FD 传递和统计聚合。
- 使用已有 manager 唯一监督 Proxy worker 的 ready/退出/退避；SD-WAN worker 从 Runtime 注册表取得，不竞争其监督权。
- 不持有 Proxy session 或 SD-WAN peer/prefix 状态，不读取 TUN 数据。

### Proxy worker

- 只处理已认证连接上的 Proxy session、TCP/UDP relay、per-session backpressure 和 egress。
- 同一连接/session 保持 sticky；worker 扩容只接新连接，不能随机迁移已有 QUIC stream。
- 坏请求只关闭对应 session 或丢弃对应 datagram，并返回结构化 `code/module/reason/action`。

### SD-WAN worker

- 只处理已认证 routing-domain 的 Peer、prefix、barrier、stream/datagram 和 PacketPort。
- 不持有 TUN fd，不创建第二个 TUN reader，不修改基础路由。
- worker 故障只撤销其 forwarding receipt；TUNIO 保留 `ifindex/infra_id/generation/fd`。

### TUNIO/netd

- 持有唯一 TUN fd、接口地址、基础路由和基础设施 epoch。
- 负责 packet ingress/egress、PacketPort 绑定、旧 owner fencing 和基础设施健康检查。
- 业务 worker 的 bad packet、Grant 过期、QUIC 故障和 drain 不得让 TUN down 或删除路由。

## 3. 发布与重载状态机

每次配置或续期使用单调 `plan_generation`，每个 worker 使用单调 `worker_epoch`，每个连接使用完整 `(role, transport_id, connection_id, worker_id, owner_epoch)`。

1. **validate**：解析、签名、能力、域唯一性、资源预算、路径权限和版本兼容性检查；失败记录错误并保留 active snapshot。
2. **prepare**：启动或复用 worker，发送受限 plan，建立 IPC、认证和 PacketPort receipt。`PreparedIngress` 只允许经签名验证的候选进行认证和就绪握手，TUN/netd forwarding 继续 fencing；不得抢占仍有效的 committed owner，也不得承载未提交的用户流量。
3. **ready**：worker 返回包含 PID/start_ticks、role、domain、epoch、plan hash、auth deadline、能力和资源额度的 receipt；master 重新核对身份。
4. **commit**：master 在控制面原子发布 registry snapshot。新连接只读新 snapshot；旧连接仍使用旧 owner。
5. **drain**：旧 worker 标记 `draining`，关闭 accept/新 session，已有连接继续处理；数据和控制队列有界，超过 deadline 的对象按协议重试、reset 或丢弃。
6. **reap**：连接、FD、credit、task、receipt 全部归还后回收旧 worker。超时只终止该 worker，并保留其他 worker、listener、TUNIO/netd。

提交决定持久化之前，准备失败只撤销 candidate，保留旧的有效业务。已发布 snapshot
不回滚到半成品。重复 commit、迟到 receipt、旧 epoch 和重复 unregister 必须幂等。

这里的原子性只属于单一组件的 snapshot/CAS，不能推定 listener、TUNIO、netd
和远端 actor 跨进程、跨网络同时生效。协调者在首个可能生效的 Commit 前，必须
持久化完整事务身份、各参与者原状态、期限与 commit intent。Commit 发送失败、
超时或 ACK 丢失均属于结果未知，不能据此停止旧业务、盲目 Abort 已安装新代，
或递增 epoch 后重新开始。恢复先查询各参与者的实际 receipt，再按同一决定
幂等继续；在原授权范围内收敛，不能重新计算期限。授权到期只 fence 相应业务。
只有所有必要参与者确认实际提交，才写 committed；只有旧代数据面与进程回收
分别确认后，才删除其 journal。TUNIO 重启丢失的内存历史必须作为 unknown
处理，再核对基础设施 incarnation 和实际 owner，不能把缺失 receipt 当作 Abort。

### 3.1 候选入口与激活确认

inbound-only 域必须先能接收认证握手才能 ready。禁止形成 `等待 Ready -> 发布入口 -> 才能 Ready` 的环，也禁止通过跳过 Ready 消除该环。候选入口与业务 forwarding 分开授权：签名候选、受限 PacketPort 和完整进程身份准备完成后，可以发布 prepared receipt；数据转发仍受 netd commit fence 约束。

文件落盘只证明发布意图，不能证明 master 已激活。Runtime 须持久化 pending publication，master 完成校验和原子切换后返回匹配的 `(master incarnation, domain, plan generation/hash, worker id/epoch, PID/start_ticks, receipt hash)` ACK。迟到或不同候选的 ACK 不得提交 journal。master 重启后须重新验证和确认，不能复用上一 master 的 ACK。

### 3.2 续期、排空与回收

Nginx 的候选代准备规则要求：旧授权有效期间，candidate 失败不能停止旧业务。当前远端 attachment 在新连接建立时可能直接替换旧 lane；必须先建立不抢占的 prepared attachment，再提交接管。只把 `spawn` 移到 `stop` 前面会造成新旧端反复抢占，不满足该规则。所有等待仍受旧授权 deadline 限制，不延长过期授权。

drain 同时约束新连接和已有 QUIC 连接上的新 session。现有 session 的数据、FIN/reset、必要控制与探测继续处理；新 session 返回可重试错误。排空终态由 supervisor 可观察的 receipt/ACK 确认，超时后只回收匹配 PID/start_ticks/epoch 的旧 worker。registry 删除条目不是进程已经 reap 的证据。

session registry 为空、relay task join 或 FIN 已进入发送队列都不证明对端已经
收完尾部数据。当前 transport 没有可用于该证明的 FIN 送达 ACK，因此不得以
registry 为空为由提前关闭 QUIC。先保留既有连接直到对端关闭或原 drain deadline；
只有连接、保留任务、handoff reservation 与 credit 都归零，才报告 owner drained。
若后续引入 GOAWAY/确认式优雅关闭，必须作为明确协议能力及独立尾部完整性门禁。

## 4. 性能约束

- listener 的 accept、QUIC poll、连接路由和 IPC fast path 不读取磁盘、不扫描所有域、不解析完整 plan。
- Runtime Agent 在控制面 reconcile 时构造内存 registry；热路径只做 bounded map lookup、owner/epoch 校验和 credit 记账。
- `select()` 不得对每个新连接 `read_dir`、读取 worker JSON 或重新执行进程身份检查；文件和进程证明只在注册/续期/健康 reconcile 阶段验证。
- Proxy 与 SD-WAN 分离 role budget，同时受全局 admission ledger、worker byte/connection/task/FD/RSS 预算约束；空闲 worker 不预分配业务队列。
- 批处理必须有 cooperative yield；单次 poll、单次 IPC drain、单次 QUIC write 都有上限。不得通过扩大 deadline 或队列掩盖调度停顿。
- TUNIO 与 netd 不随 worker 数量线性复制；业务 worker 水平扩展共享 PacketPort/infra receipt。

## 5. 必须通过的回归

- 配置语法/签名错误：旧代继续服务，listener 和 TUN 不变。
- 新 worker ready 前崩溃：candidate 清理，无新连接误路由。
- reload 后旧 worker drain：旧连接完成，新连接只进入新代。
- worker SIGKILL、慢消费者、队列满、坏 datagram、Grant 过期：只影响所属 owner，另一 role/domain 保持双向流量。
- 迟到旧 epoch、相同数字 connection ID 但 owner epoch/transport 不同：旧事件必须被拒绝。
- Agent 重启、netd/TUNIO 重启：TUN 基础设施身份保持，业务 forwarding 按 receipt 恢复。
- 1/2/4 Proxy、1/2/4 SD-WAN 以及 mixed 矩阵：检查 goodput、CPU/GiB、RSS、FD、p99、credit 回收和 2 小时续期。

在上述门禁完成前，master/worker 代码保持 opt-in；不切换生产默认 listener，不进行线上重启或发布。

## 6. 参考与实现差异

- [Nginx control 文档](https://nginx.org/en/docs/control.html)：HUP 校验和失败回退、启动新 worker 后旧 worker 优雅退出、USR2 新旧 executable 并存。
- [Nginx process cycle](https://github.com/nginx/nginx/blob/master/src/os/unix/ngx_process_cycle.c)：master reconfigure/reap、channel command 和 worker event loop。

Nginx master 通常不承载应用连接数据；本项目当前 Transport master 仍执行 QUIC 加解密与物理收发，因此是额外的数据面瓶颈和故障域。业务 worker 数量增加不能消除该上限。须将其 CPU、延迟、队列与退出影响纳入测试；只有实测证明 Transport 饱和后才引入 CID-aware Transport shard。继承 UDP fd 或普通 `SO_REUSEPORT` 不能迁移 Quinn 的用户态连接状态，也不能据此承诺 master 热升级时 QUIC 连接无损。

## 7. 实施顺序与未关闭差距

以下是目标与实际实现的差距，不能由 API 或多域 fixture 通过推定完成。

| 顺序 | 需补齐的契约 | 当前差距 | 必须保留的验收证据 |
| --- | --- | --- | --- |
| 1 | PreparedIngress 与 committed forwarding 分离 | 混合入口接线进行中，严格 Ready 存在入站启动依赖环 | 从 Runtime 启动，经同一公共 listener 完成两个签名域真实双向流量；候选未提交时不能转发 |
| 2 | master 精确激活 ACK 与 durable pending | 写 registration 文件及日志不足以确认激活 | master 拒绝、重启、丢 ACK、重复 ACK、迟到 ACK；旧 committed generation 保留 |
| 3 | attachment prepare/commit/abort | 续期仍使用 ForwardGuard 后 stop-old，再 spawn candidate；保基础设施，但有业务切换窗口 | 候选启动失败、认证失败、远端拒绝时旧流继续；成功接管后旧事件不夺回 lane |
| 4 | session quiesce、drained receipt、精确 reap | registry drain 已撤销到期 lease，但尚不能证明拒绝已有 QUIC 上的新 session，或 Runtime 已回收旧 PID | 长连接持续流量；旧 QUIC 新 session 被拒绝；正常排空与超时回收后 FD/credit/PID 均无泄漏 |
| 5 | 同域 worker set 与 sticky placement | domain 到单 PID/epoch；四域分散不是同域横向扩展 | 同一 domain 1/2/4/2/1；只有一个 TUN reader，peer/prefix ownership 唯一，故障只影响所属 owner |
| 6 | 独立维护与有界退出 | Proxy spawn/reconcile 不得推迟其他域授权到期与 drain；独立维护任务正在实施 | Proxy ready 超时期间另一域 deadline 仍按时执行；退出可取消维护任务，无悬挂 |
| 7 | master 故障恢复 | master 仍持有 QUIC 状态，重启会断开现有连接 | 记录连接中断与重连收敛时间、其他基础设施保持；不将其称为无损热升级 |

先完成入口与确认，再完成远端 attachment 事务，然后验证会话排空/进程回收，最后实现同域扩展及 1/2/4 性能矩阵。维护任务隔离与诊断可并行推进。每一步都使用失败注入与连续双向业务检验；失败记录保留，使用新目录复测，不放宽原有流量存活、授权或完整性断言。

## 8. 本轮已取得的证据

- Core `fff6827`、Runtime `8f294b0`：本地 PacketPort 两阶段 owner 及 opt-in
  authority schema 3 已完成窄测。schema 2 保持兼容；Agent 默认调用顺序尚待接入。
- Core `72b08f2`、`9c4f64f`：远端 StageLane 与真实候选 packet-stream nonce
  探测基础已完成窄测。bit 18 尚未 advertise，应用层签名授权、候选选择及 barrier
  接线未完成；不能由 API 存在推定 Ready/CommitAck 已闭环。
- `runtime-mixed-listener-v5`：两个签名域经同一公共入口的实际 ICMP、Proxy HTTP、
  单 worker 故障恢复与 TUNIO PID 保持通过。这里只是 source-worktree/debug
  冷启动集成；不是同域新旧代并存或平台发布验收。
- master 重启追加测试暴露旧 driver socket 生命周期问题，正在改为每个 master
  incarnation 的私有目录并验证旧子进程退出。失败证据保留，未据 v5 宣称通过。
- owner v10 四轮稳态 750 Mbps 对照吞吐与输出完整性通过；未触发续期或候选事务。
  详细范围见 `sdwan-owner-performance-20261015.md`，完整 G0–G6 仍未关闭。

## 9. Nginx 方法的具体落地与恢复边界

| Nginx 的生命周期行为 | Candy 的执行与证据 | 失败时的处理 |
| --- | --- | --- |
| HUP 前验证配置并准备资源 | 验证签名和原期限，准备候选进程、入口、远端 lane、本地 owner 与 netd；以实际 receipt 和候选 packet proof 判定就绪 | commit intent 持久化前失败只清理候选，旧授权有效的业务继续 |
| 启动新代，再让旧代退出 | 所有必要参与者 Prepare 后持久化同一提交决定，核对实际 Commit receipt，再发布新连接路由 | 确认丢失按 UNKNOWN 查询并继续同一决定，不能把超时推定为撤销成功 |
| 旧 worker 停止接受新工作 | 既禁止新连接，也禁止旧 QUIC 上的新 session；客户端收到明确的排空通知后只把新请求转到新连接 | 普通配额不足不能触发整连接重置；现有 session 的数据和 FIN 继续 |
| QUIT 后处理已有连接 | 保留旧 transport 至对端关闭或原 drain deadline，汇总连接、reservation、credit 和 task 的实际状态 | deadline 到期只处理匹配的 owner，不停止另一 role/domain 或 TUN |
| CHLD 后 reap 并重建缺失 worker | 唯一 supervisor 核对 PID/start_ticks/epoch 后回收；有界退避只重建需要的 slot | registration 删除或进程发送退出 ACK 均不能代替实际 reap |

这里不能直接套用 Nginx 的 listener FD 继承来宣称无损升级：现有 master
仍持有 Quinn 连接状态。正常 reload、worker 排空和 master SIGKILL 必须分开
测试。SIGKILL 是无关闭通知的黑洞，恢复时间包含已配置的失效检测、重连退避、
握手和入口激活时间。Linux 默认 keepalive 15 秒、idle timeout 120 秒的测试，
不能在 10 秒后仅凭未重连就认定永久失效；缩短 fixture 的显式超时也不代表
生产默认值已经改善。须记录实际配置、检测时间与业务恢复时间。

### 9.1 客户端也是排空契约的参与者

目前服务端 quiesce 使用 `RESOURCE_EXHAUSTED` 拒绝新 session，只证明服务端
停止接收新工作。这个通用错误不能表达 owner 正在排空；客户端若继续复用旧
QUIC，新请求可能持续失败到原 drain deadline。完整交接还须明确的、经能力协商
的 drain/GOAWAY 通知，绑定连接 owner 与原期限，撤销该连接的新请求资格并
准备替代连接。不得将所有 `RESOURCE_EXHAUSTED` 都当作连接故障，也不能为了
重试而中断旧连接已有请求。此项在通知及客户端接线完成前保持未关闭。

master 重启回归还发现一次性 speculative TCP 任务与常驻 listener 任务使用
同一 critical JoinSet；重连后的单个请求结束会被监督器当成客户端服务退出。
修复须将有限请求放入 attempt 所有的独立 task set，结束时取消并 join，归还
permit；回归须证明请求正常结束、取消或失败都不终止 listener，后续请求仍可用。

### 9.2 每次变更的验证顺序

1. 先执行状态机、重复命令、旧 epoch、原期限和精确进程身份的窄测。
2. 在两个隔离端运行连续双向流量，分别注入候选失败、ACK 丢失、worker 退出
   与 master 重启；保留每次失败证据，核对旧业务和基础设施身份。
3. 提交确定源码后冻结并构建，复核 source manifest 与六个产物的 hash。
4. 在无并发构建或测试负载的窗口测量默认和诊断模式；吞吐、输出完整性与
   恢复时间分别报告，稳态 PASS 不能代替交接 PASS。
5. 完成同域 1/2/4、mixed、两小时续期及目标平台门禁后，才签名发布或更新生产。

### 9.3 对照 Nginx 官方流程的实施顺序

2026-10-15 已核对官方 control 文档。HUP 先检查配置和新资源，失败继续
旧配置；成功启动新 worker 后，旧 worker 关闭新工作入口并服务已有客户端。
本项目依此顺序实施：

1. 固定完整配置代际、签名证据和原授权期限，先完成校验与所有参与者 Prepare。
2. 用独立候选 namespace 和精确 selector 接入新代，取得真实 packet proof；
   同域 active owner 不得被候选握手抢占，候选失败只清理候选。
3. 持久化 commit intent，核对实际 Installed receipt，再发布新请求路由。
   丢失确认按 UNKNOWN 查询，沿用同一事务和原期限恢复。
4. 明确通知客户端旧连接排空，停止分配新 session，准备并验证替代连接；
   已有 session 保留原 transport，普通 quota 错误不触发连接级重置。
5. 分别取得 transport drained 与 OS exit/reap 证据。kill 请求、registry
   删除、FIN 排队均不能代替完成证明；失败保留精确 Child 所有权并有界退避。
6. 最后验证同域 sticky 1/2/4/2/1 扩缩容与全部性能、故障和平台门禁。

Nginx 官方同页也明确指出：QUIC reload/upgrade 保留连接需要 `quic_bpf`。
这不是 Candy 已具备连接迁移的证据。当前 Quinn 状态仍属于 Transport
master；worker reload 与 master 可执行文件升级必须分别验收。

### 9.4 本轮状态补充

- mixed-listener v10 已通过两个签名域、Proxy、单 worker 故障恢复与两次
  master 重启；TUNIO 保持。它是工作区 debug 集成证据，不是同域扩容验收。
- Core `788d3f6` 已完成服务端 session quiesce 并推送；通用 code 5 尚不足以
  通知客户端交接，端到端 graceful replacement 仍未完成。
- 候选 selector、paired-clock 原期限与精确 Child 回收正在补齐并验证；
  应用层 staged caller 与 Runtime durable orchestration 尚未完成。
- 冻结 v11 默认四轮约 750 Mbps，输出完整性 PASS；详细诊断模式干净复测
  上传 649.64/680.37 Mbps，吞吐 FAIL、输出完整性 PASS。详见
  `sdwan-owner-performance-v11-20261015.md`。详细诊断保持默认关闭。

以上补充不关闭完整 G0-G6，也不授权依据局部 PASS 进行生产切换。

### 9.5 激活确认不能跨 master 代际复用

注册发布采用非阻塞独占锁；竞争时返回 `listener_registration_busy`，保留
当前业务并交给下一轮 reconcile 重试，不能阻塞续期或其他域的维护循环。
激活 ACK 必须匹配当前 master instance、存活的 PID/start_ticks、UID、非零
transport id 及完整 registration。读取 ACK 前后再次核对 master 身份，
避免重启前残留的精确 ACK 被误当作新 master 已激活的证据。

重复 prepared 发布遇到同一代 committed registration 时，仅允许 phase
不同；其余字段必须完全相同，并仍须核验 committed activation ACK。
只比较 PID/epoch 然后返回成功会漏掉 master 重启、授权变化或路径变化。

Linux 默认构建和 `experimental-tunio-rebind` 模式的注册测试均已执行通过
（分别 1/1），实验模式严格 Clippy 通过。测试覆盖 ACK 缺失/字段不符、
master 更代、错误 start_ticks/PID/UID、零 transport id 和不安全文件权限。
这是本地控制面身份门禁，不代替端到端候选交接、ACK 丢失恢复或性能验收。
