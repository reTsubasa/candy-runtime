# PacketPort owner 事务版本性能对照（2026-10-15 v10）

## 结论

冻结构建和四轮稳态诊断的吞吐、输出完整性均 PASS。此结果只覆盖本轮
750 Mbps offered load，不关闭完整 G0–G6，也不证明此前间歇性停顿已经消除。
未操作生产、签名或发布。失败的 v9 证据仍保留。

## 源与范围

- Core `72b08f2022aa974acfe1ed7431e72510665efa72`。
- Runtime `2b006c340f6f96c8a6a181816a5ec6079053690c`。
- source manifest SHA256
  `2215393d4c2f554c5b7db7f5f3c5d25e9726c64988f11b1c3509aaa38ed31964`。
- 六产物 `--release --locked --offline` 构建通过；manifest 与六个二进制
  SHA256 独立复核通过。仅使用提交源，不包含工作区混合入口或后续诊断草稿。
- 两个隔离 aarch64 Docker/netns，真实 QUIC、TUN、Agent/netd/TUNIO；
  每轮 60 秒、4 TCP 流，方向交替。没有并发构建、VM 测试或其他测试负载；
  原有 Cloud demo 容器保持运行。
- PacketOutput 保持 256 packets、512 KiB、100 ms；执行器诊断关闭。
  输出状态与独立 scheduler 采样保持开启。

此构建含本地 owner 两阶段 API、旧 owner 同步发送 fence 和远端 StageLane
基础 API。但本次 runner 仍使用原有 AttachAuthorized 接线，没有触发续期、
PrepareOwner/CommitOwner、远端 candidate probe 或混合 listener。因此这里只能
评估新增发送 fence 等公共路径的稳态表现，不能作为候选切换验收。

## 四轮实测

| 轮次 | 方向 | 接收 Mbps | 客户端平均 CPU 核 | 服务端平均 CPU 核 |
| --- | --- | --- | --- | --- |
| 1 | 上传 | 749.9851 | 1.5544 | 1.3578 |
| 2 | 下载 | 749.9912 | 2.0513 | 1.0698 |
| 3 | 上传 | 750.0041 | 1.5396 | 1.3358 |
| 4 | 下载 | 750.0041 | 2.0318 | 1.0422 |

CPU 来自容器 cgroup 全部进程的时间差，不是单独 Core CPU。两端四轮 quota
throttling 均为零。Core 两端的 drop、stream read/write error，以及客户端
TUNIO 两个方向的 slot/byte/channel、backpressure、deadline、stale 拒绝均为零。
客户端 Core 输出排队峰值 20.607 ms，TUNIO→Core 排队峰值 73.168 ms；这些是
同一代进程的累计最大值，不能把后续轮次重复出现的最大值当作新事件。

v9 默认轮曾有 Core deadline 183、TUNIO→Core 919，本轮为零。不过这不是
控制单个变量的因果实验：构建包含多个提交，且历史异常具有间歇性。不能据此
声称 owner 锁修复了执行器停顿。仍须保留同步路径细分诊断、候选切换故障注入、
正式 800 Mbps/UDP/p99/mixed/1、2、4 worker 和两小时续期测试。

## 证据

工作区 `docs/artifacts/sdwan-20261015/`：

- `owner-release-v10/`：冻结源、源与二进制 hashes、六产物构建日志。
- `perf-owner-default-v10/`：四轮原始 iperf、前后状态、scheduler、日志、
  `completion.json`、`summary.json`、`scheduler-analysis.json`。

测试容器已清理。Docker 证据不替代物理 1 Gbps 链路、IPQ40xx 或 Android 真机。
