# WiFi Calling (VoWiFi) 网络探测

检测 VPS 与各国运营商 ePDG（WiFi 通话网关）之间的 IKEv2 UDP 500/4500 往返是否通畅。
无需 root，不安装任何软件，内存占用极小。

## 一键运行

用 SSH 登录 VPS，复制执行。无需 root，无需安装 Python、Bash、Docker 或编译器：

```sh
f=$(mktemp) && { if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/imthnio/wificalling-jiance/main/check.sh -o "$f"; else wget -T 30 -q -O "$f" https://raw.githubusercontent.com/imthnio/wificalling-jiance/main/check.sh; fi; } && sh "$f"; r=$?; [ -z "${f:-}" ] || rm -f "$f"; (exit "$r")
```

## 赞赏支持
如果这个脚本帮到了你，欢迎请我喝杯咖啡 ☕  
微信扫一扫下方赞赏码即可：

![赞赏码](./appreciate.png)
