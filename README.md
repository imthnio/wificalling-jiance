# WiFi Calling (VoWiFi) 网络探测 — 64 MB 低内存版

检查 **VPS 到运营商 ePDG 的 IPv4 UDP 500 / 4500 返回路径**。收到与本次请求匹配的 IKEv2 响应，才计为“有效响应”。这是网络诊断工具；**不能证明 SIM 已开通 VoWiFi、手机已注册或实际电话一定可用**。

## 一键运行

用 SSH 登录 VPS，复制执行。无需 root，无需安装 Python、Bash、Docker 或编译器：

```sh
f=$(mktemp) && { if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/imthnio/wificalling-jiance/main/check.sh -o "$f"; else wget -T 30 -q -O "$f" https://raw.githubusercontent.com/imthnio/wificalling-jiance/main/check.sh; fi; } && sh "$f"; r=$?; [ -z "${f:-}" ] || rm -f "$f"; (exit "$r")
```

入口会选择对应 CPU 的静态程序，校验内置 SHA-256，再运行；结束后删除临时文件。下载失败、校验失败和执行失败会返回非零状态，不会输出假的“检测完成”。旧的 `curl .../check.sh | bash` 调用仍兼容，但建议使用上面的先下载、成功后再执行方式。

只查自己的运营商会更快。下载入口文件后执行：

```sh
sh check.sh --filter 英国
sh check.sh --filter T-Mobile
sh check.sh --list
```

也可以使用已知的运营商网关，或更换本次检测使用的 DNS；不修改系统设置：

```sh
sh check.sh --host epdg.epc.mnc030.mcc234.pub.3gppnetwork.org
sh check.sh --filter 德国 --dns 1.1.1.1 --timeout 2000
```

`--timeout` 的单位是毫秒，范围 1–10000，默认 1500。串行检测 39 个候选目标，每个最多检查两个不同 IPv4。默认最差等待预算约 8 分钟（所有 DNS 和端口均超时），实际时间取决于网络；不再承诺全部检测只要半分钟。

## 为什么适合 64 MB NAT 小机

- 检测核心为 C 程序，固定大小缓冲区、单进程、无线程池。
- 提供 Linux x86_64 / aarch64 静态 musl 程序；没有 Python 安装、apt 更新、现场编译或 Docker 开销。
- Alpine 可用自带 `sh` / `wget` / `sha256sum`；Debian、Ubuntu 也可使用同一静态程序。
- 不绑定本机低端口，不需要 root、raw socket、TUN 或 `CAP_NET_ADMIN`。
- 只发起出站 UDP，不要求 NAT 商家映射入站 500 / 4500。
- 不改防火墙、DNS、系统服务或 swap，不默认调用 IP 归属地查询服务。

64 MB 是小机的总额度，其他服务和系统本身也会消耗内存；本项目不能保证一台已经没有可用内存的机器仍能运行。安装入口需要 HTTPS 可用的 curl 或 wget，以及 sha256sum 或 shasum。缺少这些工具时，会给出错误；不会自动启动包管理器。

若临时目录禁止执行，可先选择一个已有的可写、可执行目录：

```sh
WIFICALLING_TMPDIR="$PWD" sh check.sh --filter 英国
```

离线使用：上传 `bin/check-linux-x86_64`（ARM64 选 `check-linux-aarch64`）及 `SHA256SUMS`，在另一台可信机器确认 SHA-256 后：

```sh
chmod +x check-linux-x86_64
./check-linux-x86_64 --filter 英国
```

## 怎样理解结果

| 输出 | 能说明什么 |
|---|---|
| UDP 500 / 4500：有效响应 | 指定 IP / 端口返回了与请求 SPI 匹配的、格式有效的 IKEv2 消息；错误通知也说明返回路径存在 |
| 未确认 | 在时间窗口内未得到有效响应；可能是丢包、路径过滤、算法策略、运营商限制或目标变化，不能直接判定被封锁 |
| 本地发送失败 | 无法创建 / 连接 UDP 套接字或发送数据；检查路由和运行环境权限 |
| 未取得 IPv4 地址 | DNS 无回答、无 A 记录、候选域名不公开等；不能直接认定 DNS 污染 |
| DNS 参考测试失败，但 IKE 有响应 | UDP 500 / 4500 的实际证据有效；UDP 53 的结果不覆盖其他端口 |

“双端口响应”要求**同一个 IP** 的两个端口都收到有效响应。探测没有 SIM 凭据，也不进行 IKE_AUTH、IMS 注册或通话；响应尚未通过身份认证。它也不检测 IPv6、NAT64、手机到 VPS 的隧道、UDP 长连接保持或运营商账户资格。实际使用仍需手机支持、号码开通、必要的 UDP 转发以及真实通话验证。

内置名单保留原有 39 个运营商标签，按 `epdg.epc.mncXXX.mccYYY.pub.3gppnetwork.org` 构造**候选**域名；不是运营商现网地址的认证目录。不同 SIM、MVNO 或运营商配置可能使用不同网关，可通过 `--host` 指定。删除了原来没有依据的 MCC/MNC 反序域名尝试。

DNS 优先读取 `/etc/resolv.conf` 的两个可识别解析器，再尝试 1.1.1.1 / 8.8.8.8；指定 `--dns` 后只用指定地址。自行解析 A / CNAME，校验来源、事务 ID、问题及记录所属域名。当前不实现 TCP DNS 回退、搜索域或 `/etc/hosts`；截断响应不会被误认为成功，而会尝试下一解析器。只支持全限定域名和 IPv4 目标。

## 本次修复

1. 去掉自动安装 Python 及 16 线程依赖，提供可审计源码与小型静态程序。
2. 修正 IKE 载荷链 `SA → KE → Nonce`，Transform 的后续标记，以及 KE 的长度、DH 组和保留字段。
3. 使用 RFC 3526 group 14 的有效 DH 公钥替代无约束随机 KE 字节，随机 SPI / Nonce；算法提议为 AES-CBC-128、HMAC-SHA256 PRF / integrity。
4. 校验响应来源、SPI、IKE 版本、交换类型、响应位、消息编号、总长度、载荷边界和 UDP 4500 的 Non-ESP Marker，忽略错误包直到超时。
5. DNS 校验事务及问题、限制压缩指针跳转和包长度；只接受所属域名或 CNAME 链中的 A 记录。
6. 取消“DNS 失败 = 所有 UDP 被封锁”“任意 UDP 回包 = 支持”“探测通过 = 手机一定能打电话”等错误结论。
7. 下载失败、校验失败、未知 CPU、缺少工具、不可执行临时目录均明确报错，保留子进程退出码并清理临时文件。

## 构建与测试（只在开发机执行）

```sh
sh scripts/test.sh
ZIG=/path/to/zig-0.13.0/zig sh scripts/build.sh
sh scripts/test-64mb.sh
```

`test.sh` 使用 C 编译器和 Python 标准库运行协议/下载入口测试，这些开发依赖不需要安装到目标 VPS。`build.sh` 固定 Zig 0.13.0，交叉构建两种 Linux 静态程序并更新 SHA-256。第三方许可见 `THIRD_PARTY_NOTICES.txt`。

GitHub Actions 配置包含：协议和下载入口回归、ASan/UBSan、二进制校验、Alpine 3.22 / Debian 13 / Ubuntu 24.04 的 **64 MiB RAM、无 swap、普通用户、删除全部 capabilities、只读根文件系统** 容器测试，以及从源码重建后逐字节比较。容器只访问回环地址，不探测公网运营商；CI 配置存在不等于 CI 已通过，实际状态以 Actions 记录为准。

当前本地验证记录见 [VALIDATION.md](VALIDATION.md)。本项目没有在用户的实际 NAT VPS 上完成部署或运营商通话验证。

## 协议来源

- [IETF RFC 7296 — IKEv2](https://www.rfc-editor.org/rfc/rfc7296.html)：消息头、SA / KE / Nonce、响应及错误通知。
- [IETF RFC 3948 — UDP Encapsulation](https://www.rfc-editor.org/rfc/rfc3948.html)：UDP 4500 的 Non-ESP Marker。
- [IETF RFC 3526 — MODP groups](https://www.rfc-editor.org/rfc/rfc3526.html)：group 14 的 2048 位素数。

这些是协议标准，不是运营商现时可用性的保证；运营商策略和实际网络状态只能在目标出口验证。
