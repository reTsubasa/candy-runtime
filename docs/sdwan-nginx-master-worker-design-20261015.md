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
  +-- Runtime Agent (唯一业务生命周期协调者)
  |     | Cloud 同步、续期、prepare/commit、registry、drain/reap
  |     +-- Transport Listener Master (UDP/QUIC、TLS、identity、replay/admission、IPC)
  |     |     +-- Proxy worker pool (N 个)
  |     |     +-- SD-WAN worker pool (M 个)
  |     +-- 业务 worker 的唯一监督、恢复和有界退避
  +-- netd/TUNIO infrastructure (独立常驻，不属于任一业务 worker)
```

这是职责与监督关系，不新增第三套 supervisor。Runtime Agent 管理业务生命周期，Transport master 接受其发布的路由与注册表，不再另起独立 Cloud/续期/worker 重启循环。netd/TUNIO 的具体启动路径须与现有进程身份和 journal 一致，禁止由多个层级竞争监督同一个 PID。

### Runtime Agent

- 读取并验证 Cloud candidate、签名、版本、能力、资源预算和路由域。
- 生成 immutable `PlanSnapshot`，执行 `prepare -> ready receipt -> atomic publish`。
- 维护 domain/role/worker registry、owner epoch、drain deadline、失败重试和有界退避。
- 只发送控制消息，不逐包参与数据面；业务 worker 的启动、重启和退避只在此处实现，procd/systemd 仅兜底 Agent/基础设施。

### procd/systemd

- 仅监督 Agent、netd/TUNIO 的启动、退出码和有界退避。
- 不读取 Cloud、不做业务 worker placement、不重复做 drain。
- Agent 失联时不删除 TUN；已有有效业务按授权继续，过期后仅撤销 forwarding。

### Transport Listener Master

- 独占公共 UDP listener、QUIC/TLS handshake、完整 `TransportOwner` 身份和全局 admission/replay。
- 根据已激活的内存 registry 选择 role/domain worker；域 hint 只能缩小候选，不能授权。
- 维护 IPC 通道、连接到 worker 的 sticky owner、旧 epoch 过滤、FD 传递和统计聚合。
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
2. **prepare**：启动或复用 worker，发送受限 plan，建立 IPC、认证和 PacketPort receipt；此阶段不能接收新业务。
3. **ready**：worker 返回包含 PID/start_ticks、role、domain、epoch、plan hash、auth deadline、能力和资源额度的 receipt；master 重新核对身份。
4. **commit**：master 在控制面原子发布 registry snapshot。新连接只读新 snapshot；旧连接仍使用旧 owner。
5. **drain**：旧 worker 标记 `draining`，关闭 accept/新 session，已有连接继续处理；数据和控制队列有界，超过 deadline 的对象按协议重试、reset 或丢弃。
6. **reap**：连接、FD、credit、task、receipt 全部归还后回收旧 worker。超时只终止该 worker，并保留其他 worker、listener、TUNIO/netd。

任何阶段失败都只撤销 candidate。已发布 snapshot 不回滚到半成品；下一次 reconcile 才重试。重复 commit、迟到 receipt、旧 epoch 和重复 unregister 必须幂等。

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
