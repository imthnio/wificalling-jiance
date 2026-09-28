# WiFi Calling (VoWiFi) 一键检测

一键检测这台 VPS 的网络能不能让欧洲手机卡正常使用 WiFi Calling（在 WiFi 下打电话、发短信）。

## 一键检测

```bash
curl -fsSL https://raw.githubusercontent.com/imthnio/wificalling-jiance/main/check.sh | bash
```

把上面这一行粘贴到 VPS 的 SSH 终端里，回车，等半分钟，看最后的中文结论。零依赖，缺 python3 会自动装。

## 检测原理

WiFi Calling 就是手机通过互联网，用 IPsec 加密隧道连回运营商的 ePDG 网关（专门管 WiFi 通话的服务器）。脚本会"假装成手机"，给 33 家欧洲主流运营商（德国 Telekom / Vodafone / O2、法国 Orange / SFR / Bouygues / Free、意大利 TIM / Vodafone / WindTre、西班牙 Movistar / Orange / Vodafone、英国 EE / O2 / Vodafone / Three、荷兰 KPN、比利时 Proximus、瑞士 Swisscom、奥地利 A1、波兰 Orange / Play、瑞典 Telia、爱尔兰 Vodafone、葡萄牙 Vodafone / MEO……）的 ePDG 网关各发一个真实的 IKE 握手包，UDP 500 和 UDP 4500 两个端口都测，看对方有没有回应。有回应 = 这条路是通的。

## 能（检测通过）——还需要注意什么

1. **手机号码必须已开通 VoWiFi**：有些运营商默认没开，要去运营商 App 里或联系客服开通。
2. **手机要支持**：机型本身支持 VoWiFi，且系统设置里打开了"WiFi 通话"开关。
3. **手机流量要真正走这台 VPS 出去**：脚本测的是 VPS 的网络，实际用的时候手机得通过代理 / VPN 让流量从这台 VPS 出站，否则测了白测。
4. **运营商可能翻脸**：有些运营商会屏蔽机房 IP 或境外 IP，今天测着能通，不代表以后一直能通。如果某天突然不行了，重跑一遍这个脚本，看结果变没变。
5. **延迟影响通话质量**：VPS 离运营商网关越近延迟越低，跨国绕路的话通话可能会有延迟感。

## 不能（检测不通过）——为什么

按常见程度排序：

1. **VPS 拦截了 UDP 出站（最常见）**：廉价 NAT VPS、防火墙严格的机器会禁 UDP。WiFi Calling 全靠 UDP，UDP 不通就彻底没戏。去服务商后台检查防火墙 / 安全组，把 UDP 出站放行，或换一台 VPS。
2. **运营商屏蔽了机房 IP / 境外 IP**：UDP 是通的，但所有运营商的 ePDG 都不回应。这是运营商那边的限制，不是你的 VPS 的问题。可以试试换离用户更近的机房，或换住宅 IP 线路的 VPS。
3. **VPS 的 DNS 被劫持 / 污染**：表现为所有运营商都"域名解析失败"。把系统 DNS 换成 8.8.8.8 / 1.1.1.1 再测一次。
4. **个别运营商没公开标准 ePDG 域名**：只影响名单里的个别几家，不影响整体结论，看大多数的结果就行。

## 说明

- 仅供自测学习。每次探测只给每家运营商发两个很小的 UDP 包，不会对运营商服务器造成影响。
- 脚本只测"VPS 网络到运营商网关"的通路，手机端的问题（没开通、机型不支持、没开开关）测不出来。
