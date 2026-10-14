# Cloud mTLS 失败与真实 TUN 恢复组合门禁

新增 ignored 用例 `signed_cli_mtls_cloud_outage_preserves_real_tun_peer_recovery`，在隔离 `NetworkMode=none` privileged Linux 容器执行，两次运行 PASS。

该用例通过生产 Runtime Agent 的 Cloud `synchronize_once_controlled` 路径，连接本地要求客户端证书的 HTTPS fixture。Cloud 持续返回 HTTP 500 时，同一 Agent 的 domain task 仍运行；真实 QUIC peer 丢失并恢复后，原 Core、TUN 身份与策略 generation 保持，真实 ICMP 恢复。同时启动第二个 Runtime Agent，验证它在 5 秒内被 owner lock 拒绝，原流量继续。

第二次冻结执行证据位于父工作区 `docs/artifacts/sdwan-20261014/runtime-mtls-tun-combination-v1/`：

- `signed-mtls-cloud-tun.log`：1 passed，实际执行 14.58 秒。
- `signed-mtls-cloud-tun-evidence.json`：126 个真实 HTTP 500 请求全部已验证客户端证书；原 Agent PID 415；duplicate Agent rejected。
- `binary-hashes.txt`：运行中的 helper/Core/Agent/netd/fixture SHA256。
- Core/Runtime binary 来自独立 `perf-renewal-build-v1`；新 helper 由当前 Runtime 测试源码构建。

Python fixture 另外验证：有效客户端证书可获取 HTTP 500；无客户端证书在 TLS 层被拒绝，不进入 HTTP 请求记录。证书及私钥仅在独立临时目录生成，不进入报告。

限制：测试 Cloud 是本地 mTLS HTTP 500 fixture，没有签发真实 Cloud publication，也没有跨授权期限/WAN断开/恢复续期。它只补齐 mTLS 失败与真实 TUN peer 恢复同场验证。生产 Cloud 续期组合、mixed Proxy/SD-WAN、OpenWrt procd、签名包安装及实机性能仍未关闭。
