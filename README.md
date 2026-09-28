# WiFi Calling (VoWiFi) 网络探测

## 一键运行

用 SSH 登录 VPS，复制执行。无需 root，无需安装 Python、Bash、Docker 或编译器：

```sh
f=$(mktemp) && { if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/imthnio/wificalling-jiance/main/check.sh -o "$f"; else wget -T 30 -q -O "$f" https://raw.githubusercontent.com/imthnio/wificalling-jiance/main/check.sh; fi; } && sh "$f"; r=$?; [ -z "${f:-}" ] || rm -f "$f"; (exit "$r")
```
