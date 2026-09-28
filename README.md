# WiFi Calling (VoWiFi) 网络探测

## 一键运行

用 SSH 登录 VPS，复制执行。无需 root，无需安装 Python、Bash、Docker 或编译器：

```sh
f=$(mktemp) && { if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/imthnio/wificalling-jiance/main/check.sh -o "$f"; else wget -T 30 -q -O "$f" https://raw.githubusercontent.com/imthnio/wificalling-jiance/main/check.sh; fi; } && sh "$f"; r=$?; [ -z "${f:-}" ] || rm -f "$f"; (exit "$r")
```

入口会从固定提交下载对应 CPU 的静态程序，校验内置 SHA-256，再运行；结束后删除临时文件。下载失败、校验失败和执行失败会返回非零状态，不会输出假的“检测完成”。旧的 `curl .../check.sh | bash` 调用仍兼容，但建议使用上面的先下载、成功后再执行方式。

默认运行先显示国家菜单：输入编号或中文国家名，只检测该国；空输入或输错会重新询问，输入 `q` 退出，只有输入 `0` 才检测全部。请选择 **手机卡所属国家**，不是 VPS 的机房国家。支持美国（T-Mobile、AT&T、Verizon）和加拿大（Rogers、Bell、TELUS）。

通过 `curl ... | sh` 运行也会从终端读取选择；没有交互终端时明确报错并提示参数，不会悄悄扫描全部。自动运行可跳过菜单：

```sh
sh check.sh --country 英国
sh check.sh --country 美国
sh check.sh --country 加拿大
sh check.sh --all  # 明确选择全部国家
sh check.sh --filter T-Mobile
sh check.sh --list
```

也可以使用已知的运营商网关，或更换本次检测使用的 DNS；不修改系统设置：

```sh
sh check.sh --host epdg.epc.mnc030.mcc234.pub.3gppnetwork.org
sh check.sh --filter 德国 --dns 1.1.1.1 --timeout 2000
```

`--timeout` 的单位是毫秒，范围 1–10000，默认 1500。选择全部时串行检测 42 个候选目标，每个最多检查两个不同 IPv4。全量最差等待预算约 9 分钟（所有 DNS 和端口均超时），实际时间取决于网络；不再承诺全部检测只要半分钟。
