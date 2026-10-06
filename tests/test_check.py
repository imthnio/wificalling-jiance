#!/usr/bin/env python3
"""本地回环测试：假 DNS（UDP+TCP）+ 假 ePDG（UDP 500/4500 两种模式）。

用法: python3 tests/test_check.py path/to/check
"""
import hashlib
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest

BIN = None
HOST = "127.0.0.1"


def free_port(kind=socket.SOCK_DGRAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------- 假 ePDG ----------------

def payload(next_type, body):
    return struct.pack("!BBH", next_type, 0, 4 + len(body)) + body


def chain(items):
    """items: [(type, body)] -> (first_type, bytes)"""
    out = b""
    for i, (_, body) in enumerate(items):
        nxt = items[i + 1][0] if i + 1 < len(items) else 0
        out += payload(nxt, body)
    return (items[0][0] if items else 0), out


def natd(spi_i, spi_r, ip, port):
    return hashlib.sha1(spi_i + spi_r + socket.inet_aton(ip) + struct.pack("!H", port)).digest()


def ike_reply(req, peer, mode):
    spi_i = req[:8]
    spi_r = os.urandom(8)
    if mode == "accept":
        transforms = [(1, 12, 128), (2, 5, 0), (3, 12, 0), (4, 14, 0)]
        tb = b""
        for i, (t, tid, kl) in enumerate(transforms):
            attr = struct.pack("!HH", 0x800E, kl) if kl else b""
            last = 3 if i + 1 < len(transforms) else 0
            tb += struct.pack("!BBHBBH", last, 0, 8 + len(attr), t, 0, tid) + attr
        prop = struct.pack("!BBHBBBB", 0, 0, 8 + len(tb), 1, 1, 0, len(transforms)) + tb
        items = [
            (33, prop),
            (34, struct.pack("!HH", 14, 0) + os.urandom(256)),
            (40, os.urandom(32)),
            (41, struct.pack("!BBH", 0, 0, 16388) + os.urandom(20)),
            (41, struct.pack("!BBH", 0, 0, 16389) + natd(spi_i, spi_r, peer[0], peer[1])),
        ]
    elif mode == "accept_nat":
        items = [(33, b"\0" * 8), (34, struct.pack("!HH", 14, 0) + os.urandom(256)), (40, os.urandom(32)),
                 (41, struct.pack("!BBH", 0, 0, 16389) + natd(spi_i, spi_r, "203.0.113.9", 4500))]
    elif mode == "no_proposal":
        # Protocol ID = 1：RFC 7296 要求 SPI 为空时忽略该字段，旧版会误判为非法
        spi_r = b"\0" * 8
        items = [(41, struct.pack("!BBH", 1, 0, 14))]
    elif mode == "cookie":
        spi_r = b"\0" * 8
        items = [(41, struct.pack("!BBH", 0, 0, 16390) + os.urandom(16))]
    elif mode == "bad_spi":
        spi_i = os.urandom(8)
        items = [(41, struct.pack("!BBH", 0, 0, 14))]
    elif mode == "bad_len":
        items = [(41, struct.pack("!BBH", 0, 0, 14))]
        first, body = chain(items)
        hdr = spi_i + spi_r + struct.pack("!BBBBII", first, 0x20, 34, 0x20, 0, 28 + len(body) + 5)
        return hdr + body
    else:
        raise ValueError(mode)
    first, body = chain(items)
    return spi_i + spi_r + struct.pack("!BBBBII", first, 0x20, 34, 0x20, 0, 28 + len(body)) + body


def valid_request(req):
    if len(req) < 28 or req[18] != 34 or req[19] != 0x08 or struct.unpack("!I", req[24:28])[0] != len(req):
        return False
    nxt, off, seen = req[16], 28, []
    while nxt:
        ln = struct.unpack("!H", req[off + 2:off + 4])[0]
        seen.append(nxt)
        if nxt == 41:
            seen.append(struct.unpack("!H", req[off + 6:off + 8])[0])
        nxt, off = req[off], off + ln
    return off == len(req) and seen[:3] == [33, 34, 40] and 16388 in seen and 16389 in seen


class IkeServer(threading.Thread):
    def __init__(self, natt, mode, drop_first=0):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((HOST, 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.natt, self.mode, self.drop = natt, mode, drop_first
        self.received = 0
        self.bad_requests = 0
        self.stop = False
        self.start()

    def run(self):
        while not self.stop:
            try:
                data, peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            self.received += 1
            if self.natt:
                if data[:4] != b"\0\0\0\0":
                    self.bad_requests += 1
                    continue
                data = data[4:]
            if not valid_request(data):
                self.bad_requests += 1
                continue
            if self.mode == "silent" or self.received <= self.drop:
                continue
            reply = ike_reply(data, peer, self.mode)
            self.sock.sendto((b"\0\0\0\0" if self.natt else b"") + reply, peer)

    def close(self):
        self.stop = True
        self.join()
        self.sock.close()


# ---------------- 假 DNS ----------------

ZONE = {
    # name: list of (type, value)
    "direct.test": [(1, "127.0.0.1")],
    "alias.test": [(5, "mid.test"), (5, "final.test"), (1, "127.0.0.1")],  # 同一应答内的 CNAME 链
    "cnameonly.test": [(5, "target.test")],  # 只给 CNAME，需要再查
    "target.test": [(1, "127.0.0.1")],
    "big.test": [(1, "127.0.0.1")] + [(1, "10.255.%d.%d" % (i // 250, i % 250 + 1)) for i in range(80)],
    "nodata.test": [],
}


def enc_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_answer(q, udp):
    qid = q[:2]
    off, labels = 12, []
    while q[off]:
        labels.append(q[off + 1:off + 1 + q[off]].decode())
        off += 1 + q[off]
    qname = ".".join(labels).lower()
    qtype = struct.unpack("!H", q[off + 1:off + 3])[0]
    question = q[12:off + 5]
    if qname not in ZONE:
        return qid + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0) + question
    answers, owner = [], qname
    for typ, val in ZONE[qname]:
        if typ == 5:
            answers.append(enc_name(owner) + struct.pack("!HHIH", 5, 1, 60, len(enc_name(val))) + enc_name(val))
            owner = val
        elif typ == qtype:
            answers.append(enc_name(owner) + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(val))
    msg = qid + struct.pack("!HHHHH", 0x8180, 1, len(answers), 0, 0) + question + b"".join(answers)
    if udp and len(msg) > 512:  # 模拟不支持 EDNS 的服务器：截断
        return qid + struct.pack("!HHHHH", 0x8380, 1, 0, 0, 0) + question
    return msg


class DnsServer:
    def __init__(self):
        self.port = free_port()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((HOST, self.port))
        self.udp.settimeout(0.2)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((HOST, self.port))
        self.tcp.listen(8)
        self.tcp.settimeout(0.2)
        self.tcp_queries = 0
        self.stop = False
        self.threads = [threading.Thread(target=f, daemon=True) for f in (self.serve_udp, self.serve_tcp)]
        for t in self.threads:
            t.start()

    def serve_udp(self):
        while not self.stop:
            try:
                q, peer = self.udp.recvfrom(4096)
            except socket.timeout:
                continue
            self.udp.sendto(dns_answer(q, True), peer)

    def serve_tcp(self):
        while not self.stop:
            try:
                c, _ = self.tcp.accept()
            except socket.timeout:
                continue
            with c:
                c.settimeout(2)
                n = struct.unpack("!H", c.recv(2))[0]
                q = c.recv(n)
                self.tcp_queries += 1
                a = dns_answer(q, False)
                c.sendall(struct.pack("!H", len(a)) + a)

    def close(self):
        self.stop = True
        for t in self.threads:
            t.join()
        self.udp.close()
        self.tcp.close()


# ---------------- 测试 ----------------

class CheckTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dns = DnsServer()

    @classmethod
    def tearDownClass(cls):
        cls.dns.close()

    def run_check(self, host, m500="accept", m4500="accept", extra=(), drop=0, timeout=900):
        s500, s4500 = IkeServer(False, m500, drop), IkeServer(True, m4500, drop)
        try:
            cmd = [BIN, "--host", host, "--details", "--timeout", str(timeout),
                   "--dns", HOST, "--dns-port", str(self.dns.port),
                   "--ike-port", str(s500.port), "--natt-port", str(s4500.port), *extra]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env={**os.environ, "NO_COLOR": "1"})
        finally:
            s500.close()
            s4500.close()
        self.assertEqual(s500.bad_requests + s4500.bad_requests, 0, "客户端发出的 IKE 请求格式错误")
        return p, s500, s4500

    def test_pass_both_ports(self):
        p, _, _ = self.run_check("127.0.0.1")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("✅ 通过", p.stdout)
        self.assertIn("完整握手响应", p.stdout)
        self.assertIn("本机无 NAT", p.stdout)  # 验证 SHA-1 / NAT_DETECTION 计算

    def test_nat_detected(self):
        p, _, _ = self.run_check("127.0.0.1", "accept_nat", "accept_nat")
        self.assertIn("本机出口经过 NAT", p.stdout)
        self.assertIn("✅ 通过", p.stdout)

    def test_error_notify_counts_as_reachable(self):
        p, _, _ = self.run_check("127.0.0.1", "no_proposal", "cookie")
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn("NO_PROPOSAL_CHOSEN", p.stdout)
        self.assertIn("COOKIE", p.stdout)

    def test_only_500(self):
        p, _, _ = self.run_check("127.0.0.1", "accept", "silent")
        self.assertEqual(p.returncode, 1)
        self.assertIn("⚠️ 部分：500 有响应", p.stdout)

    def test_only_4500(self):
        p, _, _ = self.run_check("127.0.0.1", "silent", "accept")
        self.assertIn("⚠️ 部分：4500 有响应", p.stdout)

    def test_timeout(self):
        t = time.monotonic()
        p, s500, s4500 = self.run_check("127.0.0.1", "silent", "silent")
        self.assertEqual(p.returncode, 1)
        self.assertIn("均无响应", p.stdout)
        self.assertEqual((s500.received, s4500.received), (3, 3), "应在超时内重传 3 次")
        self.assertLess(time.monotonic() - t, 5)

    def test_retransmit_recovers_loss(self):
        p, _, _ = self.run_check("127.0.0.1", drop=2)
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn("✅ 通过", p.stdout)

    def test_malformed_replies_ignored(self):
        for mode in ("bad_spi", "bad_len"):
            p, _, _ = self.run_check("127.0.0.1", mode, mode)
            self.assertIn("均无响应", p.stdout, mode)

    def test_icmp_refused(self):
        closed = free_port()
        p = subprocess.run([BIN, "--host", "127.0.0.1", "--details", "--timeout", "900",
                            "--ike-port", str(closed), "--natt-port", str(closed)],
                           capture_output=True, text=True, timeout=30, env={**os.environ, "NO_COLOR": "1"})
        self.assertIn("ICMP", p.stdout)
        self.assertEqual(p.returncode, 1)

    def test_dns_direct(self):
        p, _, _ = self.run_check("Direct.Test.")
        self.assertIn("direct.test：1 个地址", p.stdout)
        self.assertIn("✅ 通过", p.stdout)

    def test_dns_cname_chain_same_answer(self):
        p, _, _ = self.run_check("alias.test")
        self.assertIn("✅ 通过", p.stdout)

    def test_dns_cname_only_requery(self):
        p, _, _ = self.run_check("cnameonly.test")
        self.assertIn("✅ 通过", p.stdout)

    def test_dns_truncated_falls_back_to_tcp(self):
        before = self.dns.tcp_queries
        p, _, _ = self.run_check("big.test", m500="silent", m4500="silent", timeout=500)
        self.assertGreater(self.dns.tcp_queries, before)
        self.assertIn("big.test：6 个地址", p.stdout)  # 最多取 MAX_ADDRS 个

    def test_nxdomain_is_skipped_not_failed(self):
        p, _, _ = self.run_check("missing.test")
        self.assertIn("⚪ 跳过", p.stdout)
        self.assertIn("NXDOMAIN", p.stdout)
        self.assertIn("没有进行探测", p.stdout)

    def test_nodata(self):
        p, _, _ = self.run_check("nodata.test")
        self.assertIn("无 A/AAAA 记录", p.stdout)

    def test_dns_unreachable(self):
        dead = free_port()
        p = subprocess.run([BIN, "--host", "x.test", "--details", "--dns", HOST, "--dns-port", str(dead)],
                           capture_output=True, text=True, timeout=30, env={**os.environ, "NO_COLOR": "1"})
        self.assertIn("DNS 查询失败", p.stdout)

    def test_usage_errors(self):
        for args in (["--country", "火星"], ["--all", "--host", "a.b"], ["--timeout", "10"],
                     ["--dns", "not-ip"], ["--host", "bad host"], ["--filter", "不存在的运营商"], ["--host"]):
            p = subprocess.run([BIN, *args], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            self.assertEqual(p.returncode, 2, args)

    def test_list_and_help(self):
        p = subprocess.run([BIN, "--list"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)
        self.assertIn("美国 Verizon  epdg.epc.mnc480.mcc311.pub.3gppnetwork.org  wo.vzwwo.com", p.stdout)
        self.assertEqual(len(p.stdout.splitlines()), 42)
        self.assertEqual(subprocess.run([BIN, "--help"], capture_output=True).returncode, 0)

    def test_no_tty_requires_selection(self):
        p = subprocess.run([BIN], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL,
                           start_new_session=True)  # 无控制终端
        self.assertEqual(p.returncode, 2)
        self.assertIn("没有交互终端", p.stderr)

    def test_country_selection_uses_both_fqdns(self):
        # 用不存在的 DNS 端口让解析快速失败，只验证目标展开逻辑
        dead = free_port()
        p = subprocess.run([BIN, "--country", "美国", "--details", "--dns", HOST, "--dns-port", str(dead)],
                           capture_output=True, text=True, timeout=60, env={**os.environ, "NO_COLOR": "1"})
        self.assertIn("共 3 个目标", p.stdout)
        self.assertIn("ss.epdg.epc.mnc260.mcc310.pub.3gppnetwork.org", p.stdout)
        self.assertIn("epdg.epc.att.net", p.stdout)


if __name__ == "__main__":
    BIN = os.path.abspath(sys.argv.pop(1))
    unittest.main(verbosity=2)
