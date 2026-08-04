# OpenWrt server

该目录将提供 OpenWrt server 的 UCI、procd、状态与包装。当前没有可验证的
OpenWrt server 实现，因此不复制 client init 脚本，也不将 Linux server 改名后冒充
平台适配。实现时必须使用与其他三种 Runtime 相同的 Server Core ABI。
