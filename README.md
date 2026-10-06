# WiFi Calling (VoWiFi) 网络探测

检测 VPS 与各国运营商 ePDG（WiFi 通话网关）之间的 IKEv2 UDP 500/4500 往返是否通畅。
无需 root，不安装任何软件，内存占用极小。

## 一键运行

用 SSH 登录 VPS，复制执行。无需 root，无需安装 Python、Bash、Docker 或编译器：

```sh
f=$(mktemp) && { if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/imthnio/wificalling-jiance/main/check.sh -o "$f"; else wget -T 30 -q -O "$f" https://raw.githubusercontent.com/imthnio/wificalling-jiance/main/check.sh; fi; } && sh "$f"; r=$?; [ -z "${f:-}" ] || rm -f "$f"; (exit "$r")
```

常用参数（一键命令末尾的 `sh "$f"` 后面可以接参数，或下载后运行）：

```sh
sh check.sh                    # 交互菜单选国家
sh check.sh --country 英国      # 直接检测某国
sh check.sh --all --details    # 全部运营商 + 明细
```


## 检测逻辑

1. **解析 ePDG 域名**：标准域名 `epdg.epc.mncXXX.mccYYY.pub.3gppnetwork.org`，部分运营商额外加上实际使用的域名
   （如 Verizon `wo.vzwwo.com`）。自带 DNS 客户端：EDNS0、截断时转 TCP、跟随 CNAME，每家最多取 6 个 IP。
   区分「域名不存在」（跳过，不算失败）和「DNS 失败」。
2. **探测**：对每个 IP 同时向 UDP 500 和 UDP 4500（带 non-ESP marker）发送与手机相同结构的 IKE_SA_INIT
   （多套常见算法 + NAT_DETECTION），在超时内重传 3 次。
3. **判定**：收到 SPI 匹配、结构合法的 IKE 响应即证明往返通，包括 `NO_PROPOSAL_CHOSEN`、`INVALID_KE_PAYLOAD`、
   `COOKIE` 这类错误通知（运营商拒绝了算法，但网络是通的）。
   - ✅ 通过：同一 IP 的 500 和 4500 都有响应
   - ⚠️ 部分：只有一个端口通（手机经 NAT 时必须用 4500，首包必须走 500，所以两个都要通）
   - ❌ 失败：区分超时、ICMP 拒绝、本机发送失败
4. **汇总推断**：多个国家全部不通 → 多半是 VPS 线路封了 UDP 500/4500；部分通部分不通 → VPS 没问题，
   不通的运营商可能按地区/IP 屏蔽。
5. `--details` 还会根据 ePDG 返回的 NAT_DETECTION 判断 VPS 出口是否经过 NAT。

## 局限

只验证网络层（未认证的 IKE 首包），不验证 SIM 认证（EAP-AKA）、IMS 注册和真实通话；能否通话以手机实际注册为准。
运营商列表是候选，域名不存在的会显示为「跳过」。

## 开发

```sh
sh scripts/test.sh     # ASan/UBSan 编译 + 本地假 DNS / 假 ePDG 回环测试
sh scripts/build.sh    # 用 Zig 交叉编译 x86_64/aarch64 静态程序，并更新 check.sh 中的哈希
```

新增运营商：编辑 `src/carriers.h`。

## 赞赏支持
如果这个脚本帮到了你，欢迎请我喝杯咖啡 ☕  
微信扫一扫下方赞赏码即可：

![赞赏码](./appreciate.png)
