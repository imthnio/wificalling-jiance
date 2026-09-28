#!/bin/bash
# ======================================================================
# WiFi Calling (VoWiFi) 网络支持检测 - 一键脚本(纯 bash 版,零依赖)
# ----------------------------------------------------------------------
# 干什么用的:
#   判断"这台 VPS 的网络"能不能让欧洲、美国、菲律宾的手机卡正常使用
#   WiFi Calling (手机在 WiFi 下打电话/发短信的功能)。
#
# 怎么用(小白版):
#   把下面这一行粘贴到 VPS 的 SSH 终端里,按回车,等结果:
#     curl -fsSL https://raw.githubusercontent.com/imthnio/wificalling-jiance/main/check.sh | bash
#   什么都不用装,64MB 的小鸡也能跑。
#
# 原理(一句话):
#   WiFi Calling 就是手机通过互联网,用 IPsec 加密隧道连回运营商的
#   ePDG 网关(专门管 WiFi 通话的服务器)。所以 VPS 网络只需要满足:
#     1. UDP 500 / UDP 4500 这两个端口出站不被拦截;
#     2. 能解析并连上运营商 ePDG 服务器的域名;
#   这个脚本会"假装成手机",给 39 家运营商的 ePDG 各发一个
#   真实的 IKE 握手包,看对方有没有回应。有回应 = 这条路是通的。
#   全程只用 bash 自带功能发 UDP 包,不依赖 python,不装任何软件。
#
# 注意:
#   脚本只测"VPS 网络到运营商网关"的通路。手机端还需同时满足:
#   运营商给你的号码开通了 VoWiFi、手机机型支持、系统里打开了
#   "WiFi 通话"开关,这三样脚本测不出来。
# ======================================================================

# ---------------- 工具函数 ----------------

# 生成随机十六进制字符串: rand_hex 字节数
# (比如 rand_hex 8 会输出 16 个 hex 字符,用来做握手包里的随机字段)
rand_hex() {
  local n=$1
  if command -v od >/dev/null 2>&1; then
    # 有 od 就用它从系统随机数池取
    od -A n -t x1 -N "$n" /dev/urandom 2>/dev/null | tr -d ' \n'
  else
    # 没有 od 就用 bash 内置的 $RANDOM 拼(兼容性兜底)
    local out="" i v
    for ((i=0; i<n; i+=2)); do
      v=$(( (RANDOM << 15) | RANDOM ))
      out="${out}$(printf '%08x' "$v")"
    done
    printf '%s' "${out:0:$((n*2))}"
  fi
}

# 把十六进制字符串转成二进制输出: hex2bin "2100ff"
# (原理:先把每两个字符前面加上 \x,变成 \x21\x00\xff,再让 printf %b 解析)
hex2bin() {
  printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')"
}

# 拼一个 IKEv2 握手包(IKE_SA_INIT),以十六进制字符串形式返回
# (手机开 WiFi Calling 时,第一个发出去的就是这种包。包里大部分字段是
#  固定的,只有发起方标识、密钥、随机数三处是随机的,每次调用都重新生成)
build_ike_hex() {
  local spi_i ke nonce
  spi_i=$(rand_hex 8)    # 发起方标识:随机 8 字节
  ke=$(rand_hex 256)     # 密钥交换数据:随机 256 字节
  nonce=$(rand_hex 32)   # 随机数:随机 32 字节
  # 下面是固定部分(按 IKEv2 协议拼好):
  # 0000000000000000=响应方标识(首次发包填0) 21202208=版本/类型/标记
  # 00000176=包总长374  28000030=SA载荷头 0000002c01010004=提议头
  # 后面四段=加密算法提议  27000106000e=密钥载荷头  00000024=随机数载荷头
  printf '%s' "${spi_i}0000000000000000212022080000000000000176280000300000002c010100040200000c0100000c800e008003000008020000020400000803000002000000080400000e27000106000e${ke}00000024${nonce}"
}

# 往指定 IP:端口发 IKE 握手包,3 秒内收到任何回包就算通(返回 0),否则返回 1
# (只要对方回了任何内容——哪怕是"不认你的加密算法"——都证明端口是通的)
# 用法: ike_probe 1.2.3.4 500
ike_probe() {
  local ip=$1 port=$2 hex
  hex=$(build_ike_hex)
  # 4500 端口是 NAT 穿透用的,按规范前面要加 4 个 0
  [ "$port" = "4500" ] && hex="00000000${hex}"
  # 用 bash 自带的 /dev/udp 打开一个 UDP 连接(不需要 nc 也不需要 python)
  exec 3<>"/dev/udp/${ip}/${port}" 2>/dev/null || return 1
  hex2bin "$hex" >&3 2>/dev/null
  # 等回包:3 秒内收到哪怕 1 个字节都算通
  if read -t 3 -n 1 -r _ <&3 2>/dev/null; then
    exec 3>&- 2>/dev/null
    return 0
  fi
  exec 3>&- 2>/dev/null
  return 1
}

# 把域名解析成 IPv4 地址,成功就输出 IP,失败返回 1
# (先用系统 DNS,不行就直连 8.8.8.8 / 1.1.1.1 再试)
resolve_host() {
  local host=$1 dns ip
  for dns in "" "8.8.8.8" "1.1.1.1"; do
    if [ -z "$dns" ]; then
      ip=$(nslookup -timeout=3 -retry=1 "$host" 2>/dev/null | awk '/^Name:/{f=1} f{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) ip=$i} END{print ip}')
    else
      ip=$(nslookup -timeout=3 -retry=1 "$host" "$dns" 2>/dev/null | awk '/^Name:/{f=1} f{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) ip=$i} END{print ip}')
    fi
    if [ -n "$ip" ]; then echo "$ip"; return 0; fi
  done
  # nslookup 不可用时的兜底
  if command -v getent >/dev/null 2>&1; then
    ip=$(getent hosts "$host" 2>/dev/null | grep -m1 -o '^[0-9][0-9.]*')
    if [ -n "$ip" ]; then echo "$ip"; return 0; fi
  fi
  ip=$(ping -c1 -W2 "$host" 2>/dev/null | sed -n 's/^PING [^ ]* (\([0-9.]*\)).*/\1/p')
  if [ -n "$ip" ]; then echo "$ip"; return 0; fi
  return 1
}

# 基础测试:UDP 出站到底通不通(手工发个 DNS 查询包给 8.8.8.8,有回包就是通)
# (WiFi Calling 全靠 UDP,如果 VPS 连 UDP 53 都发不出去,后面不用测了)
udp_check() {
  local tid hex
  tid=$(rand_hex 2)
  # DNS 查询包:随机事务ID + 0100(标准查询) + 查 example.com 的 A 记录
  hex="${tid}01000001000000000000076578616d706c6503636f6d0000010001"
  for dns in "8.8.8.8" "1.1.1.1"; do
    exec 3<>"/dev/udp/${dns}/53" 2>/dev/null || continue
    hex2bin "$hex" >&3 2>/dev/null
    if read -t 4 -n 1 -r _ <&3 2>/dev/null; then
      exec 3>&- 2>/dev/null
      return 0
    fi
    exec 3>&- 2>/dev/null
  done
  return 1
}

# ---------------- 运营商名单 ----------------
# 格式:名字|国家代码mcc|运营商代码mnc
# ePDG 域名是国际统一格式: epdg.epc.mncXXX.mccYYY.pub.3gppnetwork.org
CARRIERS=(
"德国 Telekom|262|001" "德国 Vodafone|262|002" "德国 O2|262|003"
"法国 Orange|208|001" "法国 SFR|208|010" "法国 Bouygues|208|020" "法国 Free|208|015"
"意大利 TIM|222|001" "意大利 Vodafone|222|010" "意大利 WindTre|222|088"
"西班牙 Movistar|214|007" "西班牙 Orange|214|003" "西班牙 Vodafone|214|001"
"英国 EE|234|030" "英国 O2|234|010" "英国 Vodafone|234|015" "英国 Three|234|020"
"荷兰 KPN|204|008" "荷兰 Vodafone|204|004"
"比利时 Proximus|206|001" "比利时 Orange|206|010"
"瑞士 Swisscom|228|001" "瑞士 Sunrise|228|002"
"奥地利 A1|232|001" "奥地利 Magenta|232|003"
"波兰 Orange|260|003" "波兰 Play|260|006"
"瑞典 Telia|240|001" "瑞典 Telenor|240|008"
"爱尔兰 Vodafone|272|001" "爱尔兰 Three|272|005"
"葡萄牙 Vodafone|268|001" "葡萄牙 MEO|268|006"
"美国 T-Mobile|310|260" "美国 AT&T|310|410" "美国 Verizon|311|480"
"菲律宾 Globe|515|002" "菲律宾 Smart|515|003" "菲律宾 DITO|515|066"
)

# 测一家运营商:域名解析 -> UDP 500 握手 -> UDP 4500 握手,输出一行结果
check_carrier() {
  local name mcc mnc rest h ip r500 r4500 st
  name=${1%%|*}; rest=${1#*|}; mcc=${rest%%|*}; mnc=${rest##*|}
  ip=""
  # 个别运营商域名两种写法都试一下,哪个能解析用哪个
  for h in "epdg.epc.mnc${mnc}.mcc${mcc}.pub.3gppnetwork.org" \
           "epdg.epc.mcc${mcc}.mnc${mnc}.pub.3gppnetwork.org"; do
    ip=$(resolve_host "$h")
    [ -n "$ip" ] && break
  done
  if [ -z "$ip" ]; then
    echo "  [$name] 域名解析失败 ✗ (该运营商可能没公开 ePDG,看别家就行)"
    return
  fi
  ike_probe "$ip" 500  && r500="✓" || r500="✗"   # IKE 标准端口
  ike_probe "$ip" 4500 && r4500="✓" || r4500="✗"  # IKE NAT 穿透端口
  [ "$r500" = "✓" ] && [ "$r4500" = "✓" ] && st="支持" || st="部分/不支持"
  echo "  [$name] UDP 500 $r500  UDP 4500 $r4500  -> $st"
}

# ---------------- 正式开始 ----------------
echo "============================================================"
echo "  WiFi Calling (VoWiFi) 网络支持检测"
echo "  正在检测这台 VPS 能不能支撑手机卡的 WiFi 通话..."
echo "============================================================"

# 先看一下这台 VPS 的出口 IP 是哪家、哪个国家的(查不到就跳过,不影响检测)
# (有些运营商会屏蔽机房 IP 或国外 IP,知道出口 IP 有助于看懂结果)
info=""
if command -v wget >/dev/null 2>&1; then
  info=$(wget -qO- -T 10 "http://ip-api.com/json/" 2>/dev/null)
elif command -v curl >/dev/null 2>&1; then
  info=$(curl -s --max-time 10 "http://ip-api.com/json/" 2>/dev/null)
fi
if [ -n "$info" ]; then
  echo ""
  echo "本机出口 IP : $(printf '%s' "$info" | sed -n 's/.*"query":"\([^"]*\)".*/\1/p')"
  echo "IP 归属地   : $(printf '%s' "$info" | sed -n 's/.*"country":"\([^"]*\)".*/\1/p')"
  echo "网络运营商   : $(printf '%s' "$info" | sed -n 's/.*"isp":"\([^"]*\)".*/\1/p')"
  echo ""
else
  echo ""
  echo "(查不到出口 IP 信息,跳过这一步,不影响检测)"
  echo ""
fi

echo "第 1 步:测试 UDP 出站是否被拦截(向 8.8.8.8 发 DNS 查询)..."
if udp_check; then
  udp_ok=1
  echo "  UDP 出站: 正常 ✓"
else
  udp_ok=0
  echo "  UDP 出站: 被拦截 ✗ (后面大概率全灭)"
fi
echo ""

total=${#CARRIERS[@]}
echo "第 2 步:逐个探测 $total 家运营商的 ePDG 网关(约需半分钟)..."
echo ""

# 并发探测:每批 8 个,照顾小内存机器;每家的结果先存临时文件,最后按顺序打印
tmpdir=$(mktemp -d 2>/dev/null) || { tmpdir="/tmp/wificheck.$$"; mkdir -p "$tmpdir"; }
i=0; batch=0
for c in "${CARRIERS[@]}"; do
  i=$((i+1)); batch=$((batch+1))
  ( check_carrier "$c" > "$tmpdir/$i" 2>/dev/null ) &
  if [ "$batch" -ge 8 ]; then wait; batch=0; fi
done
wait
j=0
while [ "$j" -lt "$i" ]; do
  j=$((j+1))
  cat "$tmpdir/$j" 2>/dev/null
done

# 统计:几家完全支持、几家域名解析失败
ok_list=$(grep -h -- "-> 支持" "$tmpdir"/* 2>/dev/null | sed 's/^  \[//;s/\].*//')
ok_count=$(printf '%s' "$ok_list" | grep -c .)
dns_fail=$(grep -h "域名解析失败" "$tmpdir"/* 2>/dev/null | wc -l)
rm -rf "$tmpdir"

echo ""
echo "============================================================"
echo "  检测结论"
echo "============================================================"
echo "  完全支持的运营商: $ok_count / $total 家"
if [ "$ok_count" -gt 0 ]; then
  echo "  名单: $(printf '%s\n' "$ok_list" | sed ':a;N;$!ba;s/\n/、/g')"
fi
echo ""
if [ "$udp_ok" = "0" ]; then
  echo "  ❌ 这台 VPS 的 UDP 出站被拦截了,WiFi Calling 用不了。"
  echo "     去服务商后台检查防火墙 / 安全组,把 UDP 出站放行,或换一台 VPS。"
elif [ "$ok_count" -gt 0 ]; then
  echo "  ✅ 这台 VPS 的网络支持 WiFi Calling,上面打勾的运营商都能用。"
  echo "     手机端记得:运营商已开通 VoWiFi + 手机支持 + 打开 WiFi 通话开关。"
elif [ "$dns_fail" -eq "$total" ]; then
  echo "  ⚠️ 所有 ePDG 域名都解析失败,多半是这台 VPS 的 DNS 被劫持/污染。"
  echo "     把系统 DNS 换成 8.8.8.8 / 1.1.1.1 再跑一次试试。"
else
  echo "  ⚠️ UDP 是通的,但没有任何一家运营商的 ePDG 回应。"
  echo "     最可能的原因是运营商那边屏蔽了机房 IP 或境外 IP"
  echo "     (这是运营商侧的限制,不是 VPS 防火墙的问题)。"
  echo "     可以试试:换一个离用户更近的机房、或换住宅 IP 线路的 VPS。"
fi
echo "============================================================"
echo ""
echo "检测完成。"
