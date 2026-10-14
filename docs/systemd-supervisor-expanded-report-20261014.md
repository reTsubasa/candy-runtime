# systemd Supervisor 扩展门禁（2026-10-14）

脚本：`scripts/systemd_supervisor_gate.sh`。证据：`docs/artifacts/sdwan-20261014/systemd-supervisor-expanded-20261014.json`。

在独立 Docker 容器内使用真实 systemd PID1，加载仓库打包的 `candy-netd.service` 与 `candy-sdwan.service`，仅以 drop-in 替换业务 payload。未访问生产设备，未触碰 Cloud demo。

| 验证项 | 结果 |
| --- | --- |
| netd restart 后 Agent PID 不变 | PASS（121 → 121） |
| Agent SIGKILL 自动恢复 | PASS（121 → 210，NRestarts 0 → 1） |
| 永久无效业务 payload 有界重启 | PASS（恰 5 次启动，随后 failed，额外等待次数不再增长） |
| 无效 Agent 不停止 netd | PASS |
| 修复 payload + reset-failed 后可重新启动 | PASS |
| 正常停止 Agent 无 MainPID，netd 保持 active | PASS |

此 systemd 版本在自动重启耗尽时保留 `Result=exit-code`，同时 journal 输出 `Start request repeated too quickly`。门禁以实际启动次数、失败状态、后续不再启动为断言，不依赖 `Result=start-limit-hit` 字符串。

限制：payload 为隔离 fixture，不是运行中的 Core/TUNIO/Cloud。尚未覆盖真实 Agent 重复实例锁、真实 TUN+Cloud 与 packaged unit 组合、OpenWrt procd、真实安装包或实机启动；这些项目仍未关闭。
