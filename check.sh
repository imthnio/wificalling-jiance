#!/bin/bash
# ======================================================================
# WiFi Calling (VoWiFi) 网络支持检测 - 一键脚本
# ----------------------------------------------------------------------
# 干什么用的:
#   判断"这台 VPS 的网络"能不能让欧洲各大运营商的手机卡正常使用
#   WiFi Calling (手机在 WiFi 下打电话/发短信的功能)。
#
# 怎么用(小白版):
#   把这个文件里的全部内容复制,粘贴到 VPS 的 SSH 终端里,按回车,等结果。
#
# 原理(一句话):
#   WiFi Calling 就是手机通过互联网,用 IPsec 加密隧道连回运营商的
#   ePDG 网关(专门管 WiFi 通话的服务器)。所以 VPS 网络只需要满足:
#     1. UDP 500 / UDP 4500 这两个端口出站不被拦截;
#     2. 能解析并连上运营商 ePDG 服务器的域名;
#   这个脚本会"假装成手机",给 30 多家欧洲运营商的 ePDG 各发一个
#   真实的 IKE 握手包,看对方有没有回应。有回应 = 这条路是通的。
#
# 注意:
#   脚本只测"VPS 网络到运营商网关"的通路。手机端还需同时满足:
#   运营商给你的号码开通了 VoWiFi、手机机型支持、系统里打开了
#   "WiFi 通话"开关,这三样脚本测不出来。
# ======================================================================

# ---------- 第 1 步:检查有没有 python3,没有就自动装 ----------
# (后面的检测逻辑全用 python3 写,不需要再装任何别的软件)
if ! command -v python3 >/dev/null 2>&1; then
  echo "没找到 python3,正在自动安装..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq python3
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q python3
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q python3
  else
    echo "自动安装失败,请手动安装 python3 后再跑一次。"
    exit 1
  fi
fi

# ---------- 第 2 步:把真正的检测逻辑交给下面的 python 代码 ----------
python3 << 'PYEOF'
import os, re, json, random, socket, struct, urllib.request
from concurrent.futures import ThreadPoolExecutor

print("=" * 60)
print("  WiFi Calling (VoWiFi) 网络支持检测")
print("  正在检测这台 VPS 能不能支撑欧洲手机卡的 WiFi 通话...")
print("=" * 60)

# ---------- 先看一下这台 VPS 的出口 IP 是哪家、哪个国家的 ----------
# (有些运营商会屏蔽机房 IP 或国外 IP,知道出口 IP 有助于看懂结果)
def get_egress_info():
    for url in ['https://ip-api.com/json/', 'https://ipinfo.io/json']:
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                return json.loads(r.read().decode())
        except Exception:
            continue
    return None

info = get_egress_info()
if info:
    ip = info.get('query') or info.get('ip', '?')
    country = info.get('country', '?')
    isp = info.get('isp') or info.get('org', '?')
    print(f"\n本机出口 IP : {ip}")
    print(f"IP 归属地   : {country}")
    print(f"网络运营商   : {isp}\n")
else:
    print("\n(查不到出口 IP 信息,跳过这一步,不影响检测)\n")

# ---------- 基础测试:UDP 出站到底通不通 ----------
# (WiFi Calling 全靠 UDP,如果 VPS 连 UDP 53 都发不出去,后面不用测了)
def dns_query_udp(server, name, timeout=4):
    """手工组一个 DNS 查询包,用 UDP 发给指定 DNS 服务器,只取 A 记录。
    不依赖系统 DNS,用来判断 UDP 出站是否被拦截。"""
    tid = random.randint(0, 65535)                      # 随机事务 ID
    pkt = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)  # DNS 头:标准查询
    for part in name.split('.'):                       # 把域名切成段逐个编码
        b = part.encode()
        pkt += struct.pack('!B', len(b)) + b
    pkt += b'\x00' + struct.pack('!HH', 1, 1)           # 结尾 0 + 查 A 记录
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(512)                      # 等回包,超时抛异常
    except Exception:
        return []
    finally:
        s.close()
    try:
        ancount = struct.unpack('!H', data[6:8])[0]    # 取回答记录条数
        off = 12                                       # 跳过 12 字节 DNS 头
        while data[off] != 0:                          # 跳过问题区的域名
            off += 1 + data[off]
        off += 5                                       # 跳过结尾 0 + 类型 + 类
        ips = []
        for _ in range(ancount):                       # 逐条解析回答
            if data[off] & 0xC0 == 0xC0:               # 域名用了压缩指针
                off += 2
            else:
                while data[off] != 0:
                    off += 1 + data[off]
                off += 1
            rtype, _, _, rdlen = struct.unpack('!HHIH', data[off:off+10])
            rdata = data[off+10:off+10+rdlen]
            if rtype == 1 and rdlen == 4:               # 只要 IPv4 的 A 记录
                ips.append('.'.join(str(x) for x in rdata))
            off += 10 + rdlen
        return ips
    except Exception:
        return []

print("第 1 步:测试 UDP 出站是否被拦截(向 8.8.8.8 发 DNS 查询)...")
udp_ok = bool(dns_query_udp('8.8.8.8', 'example.com') or
              dns_query_udp('1.1.1.1', 'example.com'))
print("  UDP 出站:", "正常 ✓" if udp_ok else "被拦截 ✗ (后面大概率全灭)")
print()

# ---------- 构造一个真实的 IKEv2 握手包(IKE_SA_INIT) ----------
# (手机开 WiFi Calling 时,第一个发出去的就是这种包。只要对方回了
#  任何内容——哪怕是"不认你的加密算法"——都证明 UDP 500/4500 是通的)
def build_ike_sa_init():
    spi_i = os.urandom(8)            # 发起方 SPI:随机 8 字节,每次不一样
    spi_r = b'\x00' * 8             # 响应方 SPI:首次发包填全 0

    # 4 个"加密算法提议",格式: 下一个(1B) 保留(1B) 长度(2B)
    #                          类型(1B) 保留(1B) 算法ID(2B) [属性]
    t_encr  = struct.pack('!BBHBBH', 2, 0, 12, 1, 0, 12) + struct.pack('!HH', 0x800e, 128)
    t_prf   = struct.pack('!BBHBBH', 3, 0, 8, 2, 0, 2)    # 伪随机函数:HMAC-SHA1
    t_integ = struct.pack('!BBHBBH', 4, 0, 8, 3, 0, 2)    # 完整性:HMAC-SHA1-96
    t_dh    = struct.pack('!BBHBBH', 0, 0, 8, 4, 0, 14)   # DH 组:2048 位 MODP
    transforms = t_encr + t_prf + t_integ + t_dh

    proposal = struct.pack('!BBHBBBB', 0, 0, 8 + len(transforms), 1, 1, 0, 4) + transforms
    sa = struct.pack('!BBH', 40, 0, 4 + len(proposal)) + proposal   # SA 载荷
    ke = struct.pack('!BBHH', 39, 0, 6 + 256, 14) + os.urandom(256) # KE 载荷
    nonce = struct.pack('!BBH', 0, 0, 4 + 32) + os.urandom(32)       # Nonce 载荷
    payloads = sa + ke + nonce
    # IKE 头 28 字节: 下一个载荷=33(SA) 版本=0x20(IKEv2) 交换类型=34(SA_INIT)
    hdr = spi_i + spi_r + struct.pack('!BBBBII', 33, 0x20, 34, 0x08, 0, 28 + len(payloads))
    return hdr + payloads

def ike_probe(ip, port, timeout=3):
    """往指定 IP:端口发 IKE 握手包,3 秒内收到任何回包就算通。
    port=4500 时前面加 4 个 0 (NAT-T 规范要求的非 ESP 标记头)。"""
    pkt = build_ike_sa_init()
    if port == 4500:
        pkt = b'\x00\x00\x00\x00' + pkt
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, port))
        data, _ = s.recvfrom(2048)
        return True
    except Exception:
        return False
    finally:
        s.close()

# ---------- 域名解析:先系统 DNS,不行就直连 8.8.8.8 / 1.1.1.1 ----------
def resolve_host(host):
    try:
        return socket.getaddrinfo(host, 500, socket.AF_INET)[0][4][0]
    except Exception:
        pass
    for dns in ('8.8.8.8', '1.1.1.1'):
        ips = dns_query_udp(dns, host)
        if ips:
            return ips[0]
    return None

# ---------- 欧洲主要运营商名单 ----------
# ePDG 域名是国际统一格式: epdg.epc.mncXXX.mccYYY.pub.3gppnetwork.org
# (mcc=国家代码, mnc=运营商代码)。个别运营商两种顺序都试一下更稳。
CARRIERS = [
    ("德国 Telekom",   "262", "001"), ("德国 Vodafone", "262", "002"),
    ("德国 O2",        "262", "003"),
    ("法国 Orange",    "208", "001"), ("法国 SFR",      "208", "010"),
    ("法国 Bouygues",  "208", "020"), ("法国 Free",     "208", "015"),
    ("意大利 TIM",     "222", "001"), ("意大利 Vodafone","222", "010"),
    ("意大利 WindTre", "222", "088"),
    ("西班牙 Movistar", "214", "007"), ("西班牙 Orange", "214", "003"),
    ("西班牙 Vodafone","214", "001"),
    ("英国 EE",        "234", "030"), ("英国 O2",       "234", "010"),
    ("英国 Vodafone",  "234", "015"), ("英国 Three",    "234", "020"),
    ("荷兰 KPN",       "204", "008"), ("荷兰 Vodafone", "204", "004"),
    ("比利时 Proximus","206", "001"), ("比利时 Orange", "206", "010"),
    ("瑞士 Swisscom",  "228", "001"), ("瑞士 Sunrise",  "228", "002"),
    ("奥地利 A1",      "232", "001"), ("奥地利 Magenta","232", "003"),
    ("波兰 Orange",    "260", "003"), ("波兰 Play",     "260", "006"),
    ("瑞典 Telia",     "240", "001"), ("瑞典 Telenor",  "240", "008"),
    ("爱尔兰 Vodafone","272", "001"), ("爱尔兰 Three",  "272", "005"),
    ("葡萄牙 Vodafone","268", "001"), ("葡萄牙 MEO",    "268", "006"),
]

def check_carrier(item):
    """测一家运营商:域名解析 -> UDP 500 握手 -> UDP 4500 握手"""
    cname, mcc, mnc = item
    ip = None
    for host in (f"epdg.epc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org",
                 f"epdg.epc.mcc{mcc}.mnc{mnc}.pub.3gppnetwork.org"):
        ip = resolve_host(host)
        if ip:
            break
    if not ip:
        return (cname, "域名解析失败", False, False)
    ok500 = ike_probe(ip, 500)       # IKE 标准端口
    ok4500 = ike_probe(ip, 4500)     # IKE NAT 穿透端口
    status = "支持" if (ok500 and ok4500) else "部分/不支持"
    return (cname, status, ok500, ok4500)

print(f"第 2 步:逐个探测 {len(CARRIERS)} 家欧洲运营商的 ePDG 网关(约需 20 秒)...\n")
results = []
with ThreadPoolExecutor(max_workers=16) as pool:   # 16 个并发,省时间
    for r in pool.map(check_carrier, CARRIERS):
        results.append(r)
        cname, status, ok500, ok4500 = r
        mark = lambda ok: "✓" if ok else "✗"
        if status == "域名解析失败":
            print(f"  [{cname}] 域名解析失败 ✗ (该运营商可能没公开 ePDG,换别家看)")
        else:
            print(f"  [{cname}] UDP 500 {mark(ok500)}  UDP 4500 {mark(ok4500)}  -> {status}")

# ---------- 出总结 ----------
ok_list = [r[0] for r in results if r[1] == "支持"]
dns_fail = sum(1 for r in results if r[1] == "域名解析失败")
print()
print("=" * 60)
print("  检测结论")
print("=" * 60)
print(f"  完全支持的运营商: {len(ok_list)} / {len(CARRIERS)} 家")
if ok_list:
    print("  名单:", "、".join(ok_list))
print()
if not udp_ok:
    print("  ❌ 这台 VPS 的 UDP 出站被拦截了,WiFi Calling 用不了。")
    print("     去服务商后台检查防火墙 / 安全组,把 UDP 出站放行,或换一台 VPS。")
elif ok_list:
    print("  ✅ 这台 VPS 的网络支持 WiFi Calling,上面打勾的运营商都能用。")
    print("     手机端记得:运营商已开通 VoWiFi + 手机支持 + 打开 WiFi 通话开关。")
elif dns_fail == len(CARRIERS):
    print("  ⚠️ 所有 ePDG 域名都解析失败,多半是这台 VPS 的 DNS 被劫持/污染。")
    print("     把系统 DNS 换成 8.8.8.8 / 1.1.1.1 再跑一次试试。")
else:
    print("  ⚠️ UDP 是通的,但没有任何一家运营商的 ePDG 回应。")
    print("     最可能的原因是运营商那边屏蔽了机房 IP 或境外 IP")
    print("     (这是运营商侧的限制,不是 VPS 防火墙的问题)。")
    print("     可以试试:换一个离用户更近的机房、或换住宅 IP 线路的 VPS。")
print("=" * 60)
PYEOF

echo ""
echo "检测完成。"
