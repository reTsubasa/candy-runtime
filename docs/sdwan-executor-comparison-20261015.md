# SD-WAN 执行器诊断对照（2026-10-15 v9）

## 结论

六产物冻结构建通过，默认/诊断模式四轮均达到本次诊断吞吐阈值，
但两种模式的输出完整性均失败。不能据此关闭 G0–G6、发布或更新生产。
本轮没有修改队列容量、100 ms 期限或生产节点。

执行器诊断记录了同步 poll 长时间占用线程 CPU，也记录了高墙钟、低 CPU
的停顿及独立 guest heartbeat 延迟。当前证据支持同时调查同步工作与系统调度，
不能断言剩余全是 VM，也不能将诊断模式的全部超时归因应用计算。

## 冻结与环境

- Core `bb9228e9abf6c0bf7acf19e9339ef1f93cdd8b55`。
- Runtime `531a6d1dd8b27b5bf3f04487c3a2adabd062c9c2`。
- source manifest `c8817d9b5a315e6fb1710df1224643e8a6b1f6fdf4d412fe28333988c2985b08`。
- 六个二进制和 source manifest SHA256 已独立复核。
- `--release --locked --offline`；只读取提交源，排除未提交的混合入口及事务实现。
- 两个隔离 aarch64 Docker/netns，真实 QUIC、TUN、Agent/netd/TUNIO；
  4 TCP 流、750 Mbps offered load、每轮 60 秒。
- 默认模式和诊断模式使用相同二进制，仅诊断环境变量不同。
  此次是诊断对照，不是物理 1 Gbps、800 Mbps、平台安装或两小时验收。

## 结果

| 模式 | 上传 r1/r3 Mbps | 下载 r2/r4 Mbps | Core 客户端 deadline | TUNIO→Core deadline | 结论 |
| --- | --- | --- | --- | --- | --- |
| 默认 | 749.9998 / 749.9973 | 749.9956 / 749.8082 | 183 | 919 | 吞吐 PASS，完整性 FAIL |
| 诊断，干净复测 | 737.7609 / 749.9916 | 750.0170 / 743.5636 | 1025 | 630 | 吞吐 PASS，完整性 FAIL |

两轮中 TUNIO→TUN deadline 和各 admission subtype 拒绝均为零。
不相加统计中的 aggregate 与 subtype，也不累加抽样日志中的累计 dropped_packets。
上述精确数量来自同进程、同代际状态计数差。

初次诊断目录保留：其 r1 与另一 agent 的短暂 cargo check 潜在区间
`03:06:40Z–03:07:10Z` 重叠。范围来自保守报告，命令准确 UTC 不可得；
该轮不能作为独占性能对照。默认测试已于约 `03:06:00Z` 结束，不重叠。
随后在新目录完成无构建的四轮复测。

## 执行器观察

以下均来自干净诊断复测；UTC 由 guest monotonic 和 scheduler clock sample
近似映射。单次 poll CPU 与 heartbeat 线程区间 CPU 分开解释，嵌套记录不相加。

| 观察 | 墙钟 ms | 线程 CPU ms | 范围 |
| --- | --- | --- | --- |
| TUNIO managed bridge poll，约 03:11:56.287Z | 228.779 | 228.724 | 此次 poll 内存在大量同步 CPU 工作；后续还发生低 CPU 停顿 |
| Core packet output writer poll，约 03:12:33.901Z | 669.704 | 370.475 | 同时包含 CPU 工作与未运行/等待时间，不能归为纯计算或纯调度 |
| TUNIO managed bridge poll，约 03:12:50.105Z | 545.191 | 339.802 | 与较长同执行器 heartbeat 延迟同时出现 |
| TUNIO packet output writer poll，约 03:14:22.580Z | 400.009 | 0.691 | 兼容调度延迟或同步阻塞，当前探针不能二选一 |
| Core stream receive poll 峰值 | 169.132 | 169.055 | 需要继续分解帧读取、队列和同步处理，不能只增加 worker |
| 唯一记录到的慢 malloc trim poll | 12.918 | 12.898 | 此轮已记录样本不能单独解释数百 ms 的主要停顿 |

Core queue wait 峰值 784794 µs，TUNIO→Core queue wait 峰值 522010 µs。
`03:12:33Z` 的独立客户端 heartbeat 迟到 606.639 ms，同秒有 3 次 quota
throttling；而 r3/r4 整轮客户端 quota throttling 为零仍有输出超时。
这些观测排除“只看 quota 即可解释全部问题”的推断，但不能据一秒 schedstat
累计 runnable wait 声称存在同长度的单次 deschedule。

每个进程的已导出 lost_events 最大值均为零。服务端 JSONL 有半条末行；
进程退出不等待 exporter，因此即使没有半行也可能丢尾部记录。
缺失诊断记录不能证明没有长 poll。10 ms heartbeat 和每 poll 时钟读取
会增加开销，本次只有一组默认与干净诊断对照，不用于精确估计开销百分比。

## 后续修复与验收

1. 进一步分解长 poll 的同步路径，保持探针默认关闭、packet task 不写文件。
   优先测实际授权检查、非阻塞 FD write/poll、帧处理和批次工作；仅依据实测
   增加 cooperative yield 或移出同步阻塞，不能以扩大 deadline 关闭故障。
2. Nginx 式 candidate/commit/drain 与当前输出故障分别验证。候选 Prepare
   不得 invalidate 整域输出，也不得通过停止旧 lane 获得候选 Ready。
3. 本地 PacketPort 两阶段 owner、远端 lane staging、listener 精确 ACK
   各自完成窄测后，组合运行连续双向流量、候选失败保旧、ACK 丢失和代际恢复。
4. 用新提交冻结构建后复测，完整性先通过，再继续正式 UDP/p99/mixed/1/2/4
   和两小时门禁；保留当前失败证据，不用 fixture 代替平台验收。

## 证据

工作区 `docs/artifacts/sdwan-20261015/`：

- `executor-release-v9/`：冻结源、构建日志、六产物 hashes。
- `perf-executor-default-v9/`：默认四轮、summary、scheduler analysis。
- `perf-executor-enabled-v9/`：受扰动轮、environment-interference、原始诊断。
- `perf-executor-enabled-v9-clean/`：干净复测、summary、scheduler analysis、
  每进程 JSONL、原始 sidecar/log/scheduler。

性能容器已清理；未操作生产节点、签名或发布。
