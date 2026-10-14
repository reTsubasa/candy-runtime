# 最新 Core/Runtime SD-WAN soak 门禁报告（2026-10-14）

## 范围与源码

本次使用独立冻结构建：

- Core `b81a5099923e1c8a0e1477c3f9a208dc978fe71b`（包含仅测试 fixture 的长 soak TTL 校验扩展）
- Runtime `aee037925ced5e6bc8369e4ef4c46093ab001118`
- 构建证据：`docs/artifacts/sdwan-20261014/perf-latest-build-v2/`
- 原始运行证据：`docs/artifacts/sdwan-20261014/perf-latest-soak-v2/`

测试在 Docker Desktop LinuxKit **aarch64** 上运行，两个独立 privileged netns/cgroup，1 Gbps veth，2 GiB/3 CPU，真实签名 TLS/QUIC、真实 TUN、managed TUNIO。该环境不能替代 x86_64 物理 1 Gbps 链路，也不能作为 800 Mbps 绝对性能验收。

## 运行结果

Runner 使用四并行 iperf UDP/TCP 业务样本，目标 offered load 750 Mbps，每个样本 60 秒，交替上传/下载。计划 120 个样本（约 2 小时），但在第 58 个样本完成后授权到期，业务 worker 停止；因此本次 2 小时 soak **FAIL / INCOMPLETE**，不能写为通过。

- 已完成：58 个样本，累计 3480.25 秒（约 58 分钟）。
- 中位数 receiver goodput：749.99 Mbps。
- 最低样本：476.75 Mbps（`soak-p4-upload-r19.json`）。
- 低于稳定性门槛 712.5 Mbps 的样本：9/58（包括 476.75、593.32、592.32、542.64、627.18、675.96、587.61、611.67、621.76 Mbps）。
- 这些样本发生期间宿主还有其他 Go 全量/编译负载；该轮不满足独占宿主前提，不能把下降单独归因于协议代码。

## 失效原因

fixture 的 Grant TTL 已允许 10800 秒，但运行时 worker authorization 仍按 3600 秒有效期上限执行。Core status 在约启动后一小时报告：

- `code=worker_authorization_expired`
- `action=keep_tunio_revoke_owned_forwarding`
- `lifecycle=stopped`, `steering_suspended=true`
- TUNIO 继续存活，基础设施保持；业务 worker 被撤销。

随后 iperf 进程等待/无有效 peer，不能继续生成有效稳定性数据。该行为符合授权过期保护，不能通过把静态测试 TTL 改成长于 worker cap 来规避。

## 资源与丢包证据

最终 client status（原始快照同时保留）显示：

- `drops=61867`，其中 `tun_output_queue_full=61677`、`tun_write_deadline=190`。
- `stream_read_errors=0`、`stream_write_errors=0`、`reconnects=0`。
- 队列峰值：发送 476 packets/576,912 bytes，接收 764 packets/921,384 bytes。

`tun_output_queue_full` 与 `tun_write_deadline` 是实际数据面丢包/背压，不能因为进程未退出而忽略；需要后续门禁对队列预算、TUN 写入调度及过载恢复单独验收。

## 后续修复要求

1. 2 小时门禁必须每个授权周期使用已验证的 signed authority renewal 事务，至少在 30 分钟前签发 fresh Grant 并完成 commit/接管；不能使用静态 1 小时 worker authorization。
2. Runner 在启动前校验 `auth_deadline - now >= soak_duration + safety_margin`；若不满足应立即 `BLOCKED` 退出，不能运行至授权过期后把停流计入 soak。
3. 保留并单独统计 `tun_output_queue_full`、`tun_write_deadline`、`route_has_no_active_peer`、`stream_*_errors` 和 `reconnects`；任意稳定性样本低于 712.5 Mbps 或出现未允许丢弃都不能判 PASS。
4. 在无额外宿主编译/负载的专用 Linux x86_64 主机上重跑，才可评估 800 Mbps 绝对门禁；本 aarch64 Docker 结果只作为受限稳定性诊断。

结论：本轮生成了可审计原始证据并正确保留 FAIL，未部署或影响生产节点。
