#!/usr/bin/env python3
"""Deterministic protocol regressions; only loopback networking, no carrier traffic."""
import os
from pathlib import Path
import pty
import select
import signal
import random
import re
import socket
import struct
import subprocess
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = os.environ.get('HARNESS', str(ROOT / 'build/harness'))
BINARY = os.environ.get('BINARY', str(ROOT / 'build/check'))

def run(*args, data=None):
    return subprocess.check_output([HARNESS, *map(str, args)], input=data)

def name(s):
    return b''.join(bytes([len(x)]) + x.encode() for x in s.split('.')) + b'\0'

def dns(answers=(), flags=0x8180, question='epdg.example'):
    return (struct.pack('!6H', 0x1234, flags, 1, len(answers), 0, 0) +
            name(question) + struct.pack('!HH', 1, 1) + b''.join(answers))

def rr(owner, kind, value):
    owner = name(owner) if isinstance(owner, str) else owner
    return owner + struct.pack('!HHIH', kind, 1, 60, len(value)) + value

def response(spi=bytes(range(1, 9)), natt=False):
    # NO_PROPOSAL_CHOSEN is valid evidence of reachability, not authentication.
    body = struct.pack('!BBHBBH', 0, 0, 8, 0, 0, 14)
    hdr = spi + b'\0'*8 + struct.pack('!BBBBII', 41, 0x20, 34, 0x20, 0, 36)
    return (b'\0'*4 if natt else b'') + hdr + body

class ProtocolTests(unittest.TestCase):
    def test_dh_matches_independent_python_modexp(self):
        source = (ROOT/'src/check.c').read_text()
        block = source.split('static const char prime_hex[]=')[1].split(';')[0]
        prime = int(''.join(re.findall(r'"([A-F0-9]+)"', block)), 16)
        self.assertEqual(prime.bit_length(), 2048)
        for exponent in (1, 2, 1 << 255, (1 << 256)-1, random.Random(9).getrandbits(256)):
            actual = int(run('dh', f'{exponent:064x}'), 16)
            self.assertEqual(actual, pow(2, exponent, prime))

    def test_request_wire_format(self):
        p = run('packet')
        self.assertEqual(len(p), 376)
        self.assertEqual(struct.unpack('!BBBBII', p[16:28]), (33, 0x20, 34, 8, 0, 376))
        self.assertEqual(struct.unpack('!BBH', p[28:32]), (34, 0, 48))
        self.assertEqual(struct.unpack('!BBHBBBB', p[32:40]), (0, 0, 44, 1, 1, 0, 4))
        self.assertEqual([p[i] for i in (40, 52, 60, 68)], [3, 3, 3, 0])
        self.assertEqual(struct.unpack('!BBHHH', p[76:84]), (40, 0, 264, 14, 0))
        self.assertEqual(struct.unpack('!BBH', p[340:344]), (0, 0, 36))
        self.assertNotEqual(p[:8], run('packet')[:8])

    def ike(self, data, natt=False):
        return int(run('ike', int(natt), data=data))

    def test_valid_error_response_and_natt(self):
        self.assertEqual(self.ike(response()), 1)
        self.assertEqual(self.ike(response(natt=True), True), 1)

    def test_success_response(self):
        p = bytearray(run('packet')); p[:8] = bytes(range(1, 9)); p[8:16] = b'R'*8; p[19]=0x20
        self.assertEqual(self.ike(p), 1)

    def test_notify_status_alone_and_missing_required_data_rejected(self):
        for kind in (16388, 16389, 16390, 17):
            p=bytearray(response()); p[34:36]=struct.pack('!H', kind)
            self.assertEqual(self.ike(p), 0)
        for kind, data in ((16390, b'cookie'), (17, b'\x00\x0e')):
            p=bytearray(response()); p[34:36]=struct.pack('!H', kind)
            p.extend(data); p[30:32]=struct.pack('!H', 8+len(data)); p[24:28]=struct.pack('!I', len(p))
            self.assertEqual(self.ike(p), 1)

    def test_success_requires_responder_spi_and_full_group14_key(self):
        p=bytearray(run('packet')); p[:8]=bytes(range(1,9)); p[19]=0x20
        self.assertEqual(self.ike(p), 0)
        p[8:16]=b'R'*8
        p[82:340]=b'\0'*258
        p[80:82]=struct.pack('!H', 19)
        self.assertEqual(self.ike(p), 0)

    def test_udp_oversized_datagram_valid_prefix_is_rejected(self):
        for natt in (False, True):
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
                server.bind(('127.0.0.1',0)); server.settimeout(5)
                port=server.getsockname()[1]
                def serve():
                    packet,peer=server.recvfrom(4096); offset=4 if natt else 0
                    p=bytearray(response(packet[offset:offset+8], natt))
                    # A valid Notify prefix exactly fills the receive buffer.
                    p[offset+24:offset+28]=struct.pack('!I',4096-offset)
                    p[offset+30:offset+32]=struct.pack('!H',4096-offset-28)
                    p.extend(b'x'*(4097-len(p)))
                    server.sendto(p,peer)
                t=threading.Thread(target=serve); t.start()
                self.assertEqual(run('probe',port,int(natt),150).strip(),b'0'); t.join()

    def test_ike_rejects_wrong_spi_exchange_flags_id_lengths(self):
        for offset, value in ((0, 0), (17, 0x10), (18, 35), (19, 8), (19, 0x28), (23, 1), (27, 35), (31, 3), (35, 0)):
            with self.subTest(offset=offset, value=value):
                p=bytearray(response()); p[offset]=value
                self.assertEqual(self.ike(p), 0)

    def test_ike_rejects_empty_echo_esp_and_truncation(self):
        for p in (b'', b'garbage', response()[:28], response()+b'extra', run('packet'), b'\xff', b'\x01'*4+response()):
            self.assertEqual(self.ike(p), 0)
        self.assertEqual(self.ike(response(), True), 0)
        for n in range(36):
            self.assertEqual(self.ike(response()[:n]), 0)

    def test_ike_rejects_broken_transform_chain(self):
        p=bytearray(run('packet')); p[:8]=bytes(range(1,9)); p[19]=0x20; p[40]=2
        self.assertEqual(self.ike(p), 0)

    def parse(self, p):
        return run('dns', data=p).decode().splitlines()

    def test_dns_compressed_a_and_deduplicate_cap(self):
        a=rr(b'\xc0\x0c',1,socket.inet_aton('192.0.2.1'))
        b=rr('epdg.example',1,socket.inet_aton('192.0.2.2'))
        c=rr('epdg.example',1,socket.inet_aton('192.0.2.3'))
        self.assertEqual(self.parse(dns([a,a,b,c])), ['2','192.0.2.1','192.0.2.2'])

    def test_dns_cname_chain(self):
        p=dns([rr('alias.example',1,socket.inet_aton('192.0.2.9')),
               rr(b'\xc0\x0c',5,name('alias.example'))])
        self.assertEqual(self.parse(p),['1','192.0.2.9'])

    def test_dns_reject_unrelated_a(self):
        self.assertEqual(self.parse(dns([rr('other.example',1,b'\x01'*4)])),['0'])

    def test_dns_wrong_id_question_flags_and_errors(self):
        p=bytearray(dns()); p[0]=0
        for data in (p,dns(question='other.example'),dns(flags=0x0100),dns(flags=0x8380),dns(flags=0x8182)):
            self.assertEqual(self.parse(data),['-1'])
        self.assertEqual(self.parse(dns(flags=0x8183)),['0'])

    def test_dns_truncation_pointer_loop_and_rdata_overrun(self):
        p=dns([rr(b'\xc0\x0c',1,b'\x01'*4)])
        for n in range(len(p)):
            self.assertEqual(self.parse(p[:n]),['-1'])
        loop=struct.pack('!6H',0x1234,0x8180,1,0,0,0)+b'\xc0\x0c'+b'\x00\x01'*2
        self.assertEqual(self.parse(loop),['-1'])

    def test_dns_cname_loop(self):
        p=dns([rr('epdg.example',5,name('other.example')),rr('other.example',5,name('epdg.example'))])
        self.assertEqual(self.parse(p),['-1'])

    def test_random_malformed_packets_do_not_crash(self):
        rand=random.Random(7)
        for _ in range(80):
            p=bytes(rand.randrange(256) for _ in range(rand.randrange(500)))
            self.assertEqual(self.ike(p),0)
            self.assertEqual(self.parse(p),['-1'])

    def test_udp_connected_socket_rejects_other_source_and_then_accepts_valid(self):
        for natt in (False, True):
            server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); server.bind(('127.0.0.1',0)); server.settimeout(5)
            alien=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            def serve():
                try:
                    packet,peer=server.recvfrom(4096); offset=4 if natt else 0
                    good=response(packet[offset:offset+8], natt)
                    alien.sendto(good, peer); server.sendto(b'garbage',peer)
                    time.sleep(.02); server.sendto(good,peer)
                finally:
                    server.close(); alien.close()
            t=threading.Thread(target=serve); t.start()
            self.assertEqual(run('probe',server.getsockname()[1],int(natt),500).strip(),b'1'); t.join()

    def test_udp_wrong_source_alone_does_not_pass(self):
        server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); server.bind(('127.0.0.1',0)); server.settimeout(5)
        port=server.getsockname()[1]
        def serve():
            try:
                p,peer=server.recvfrom(4096)
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as alien: alien.sendto(response(p[:8]),peer)
                time.sleep(.3)
            finally: server.close()
        t=threading.Thread(target=serve); t.start()
        self.assertEqual(run('probe',port,0,150).strip(),b'0'); t.join()

    def test_udp_timeout_is_bounded(self):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as silent:
            silent.bind(('127.0.0.1',0)); start=time.monotonic()
            self.assertEqual(run('probe',silent.getsockname()[1],0,80).strip(),b'0')
            self.assertLess(time.monotonic()-start,3)

    def test_cli_bad_options(self):
        for args in (['--unknown'],['--timeout','-1'],['--timeout','10001'],['--timeout','1x'],['--dns','nonsense'],['--host','a'*254]):
            self.assertEqual(subprocess.run([BINARY,*args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode,2)

    def test_country_menu_selection_retry_cancel_and_eof(self):
        for data, expected in ((b'5\n', '1:英国'), ('加拿大\n'.encode(), '1:加拿大'),
                               ('美国\n'.encode(), '1:美国'), (b'0\n','0:'),
                               (b'q\n','-1:'), (b'', '-1:'),
                               (b'\n999\nbad\n5\n','1:英国'),
                               (b'x'*200+b'\n5\n','1:英国')):
            p=subprocess.run([HARNESS,'menu'],input=data,capture_output=True,check=True)
            self.assertEqual(p.stdout.decode().strip(),expected)
            self.assertIn('手机卡所属国家',p.stderr.decode())
            self.assertIn('加拿大（3 家）',p.stderr.decode())
            self.assertIn('美国（3 家）',p.stderr.decode())

    def test_country_filter_and_all_are_explicit(self):
        for country in ('美国','加拿大','英国'):
            p=subprocess.run([BINARY,'--country',country,'--dns','127.0.0.1','--timeout','1'],
                             capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,0,p.stderr)
            rows=[row for row in p.stdout.splitlines() if row.startswith('[')]
            self.assertEqual(len(rows),4 if country=='英国' else 3)
            self.assertTrue(all(row.startswith('['+country+' ') for row in rows))
        p=subprocess.run([BINARY,'--all','--dns','127.0.0.1','--timeout','1'],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('共检查 42 家',p.stdout)

    def test_piped_stdin_still_reads_country_from_terminal(self):
        pid,fd=pty.fork()
        if pid==0:
            os.execl('/bin/sh','sh','-c',
                     'printf ignored | "$1" --dns 127.0.0.1 --timeout 1','sh',BINARY)
        output=b''; sent=False; finished=False
        try:
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                if select.select([fd],[],[],.1)[0]:
                    try: chunk=os.read(fd,4096)
                    except OSError: break
                    if not chunk: break
                    output+=chunk
                    if not sent and '输入编号或国家名称：'.encode() in output:
                        os.write(fd,'加拿大\n'.encode()); sent=True
                done,status=os.waitpid(pid,os.WNOHANG)
                if done:
                    finished=True
                    self.assertEqual(os.waitstatus_to_exitcode(status),0)
                    break
            text=output.decode(errors='replace')
            self.assertTrue(sent,text)
            self.assertIn('共检查 3 家',text)
            self.assertIn('[加拿大 Rogers]',text)
            self.assertNotIn('[美国 ',text)
        finally:
            os.close(fd)
            if not finished:
                try: os.kill(pid,signal.SIGKILL)
                except ProcessLookupError: pass
                os.waitpid(pid,0)

    def test_no_terminal_does_not_start_full_scan(self):
        p=subprocess.run([BINARY],stdin=subprocess.DEVNULL,capture_output=True,text=True,start_new_session=True,timeout=3)
        self.assertEqual(p.returncode,2)
        self.assertIn('--country',p.stderr)
        self.assertNotIn('正在检测',p.stdout)

    def test_country_bad_args_fail_before_network(self):
        for args in (['--country','不存在'],['--country',''],['--filter',''],
                     ['--all','--country','英国'],['--country','美国','--filter','加拿大']):
            p=subprocess.run([BINARY,*args],capture_output=True,text=True,timeout=3)
            self.assertEqual(p.returncode,2)
            self.assertNotIn('正在检测',p.stdout)

    def test_ike_sa_rejects_unoffered_duplicate_and_malformed_transforms(self):
        good=bytearray(run('packet')); good[:8]=bytes(range(1,9)); good[8:16]=b'R'*8; good[19]=0x20
        for offset,value in ((36,2),(47,99),(56,1),(55,9),(51,0),(75,19)):
            p=bytearray(good); p[offset]=value
            self.assertEqual(self.ike(p),0,(offset,value))

    def test_ike_selected_transforms_may_be_reordered_or_use_tlv_key_length(self):
        p=bytearray(run('packet')); p[:8]=bytes(range(1,9));p[8:16]=b'R'*8;p[19]=0x20
        reordered=bytearray(p)
        reordered[40:76]=p[52:60]+p[40:52]+p[60:76]
        self.assertEqual(self.ike(reordered),1)
        p[48:52]=b'\x00\x0e\x00\x02\x00\x80'
        p[42:44]=struct.pack('!H',14);p[30:32]=struct.pack('!H',50)
        p[34:36]=struct.pack('!H',46);p[24:28]=struct.pack('!I',len(p))
        self.assertEqual(self.ike(p),1)

    def test_unsupported_critical_notify_requires_payload_type(self):
        p=bytearray(response());p[34:36]=b'\x00\x01'
        self.assertEqual(self.ike(p),0)
        p.append(99);p[30:32]=struct.pack('!H',9);p[24:28]=struct.pack('!I',len(p))
        self.assertEqual(self.ike(p),1)

    def test_dns_rejects_missing_sections_and_trailing_bytes(self):
        base=dns([rr('epdg.example',1,b'\x01'*4)])
        for field in (8,10):
            p=bytearray(base);p[field:field+2]=b'\x00\x01'
            self.assertEqual(self.parse(p),['-1'])
        self.assertEqual(self.parse(base+b'extra'),['-1'])
        p=bytearray(dns(flags=0x8183));p[8:10]=b'\x00\x01'
        self.assertEqual(self.parse(p),['-1'])
        p=bytearray(base);p[8:10]=b'\x00\x01';p.extend(rr('example',2,name('ns.example')))
        self.assertEqual(self.parse(p),['1','1.1.1.1'])

    def test_dns_rejects_contradictory_cname_and_bad_a_length(self):
        for records in ([rr('epdg.example',1,b'abc')],
                        [rr('epdg.example',1,b'\x01'*4),rr('epdg.example',5,name('alias.example'))],
                        [rr('epdg.example',5,name('a.example')),rr('epdg.example',5,name('b.example'))]):
            self.assertEqual(self.parse(dns(records)),['-1'])

    def test_invalid_target_and_no_match_fail_before_probes(self):
        for args in (['--host','bad host'],['--host','::1'],['--host','bad\x1b[31m'],['--filter','no-such-carrier']):
            p=subprocess.run([BINARY,*args,'--dns','127.0.0.1','--timeout','1'],capture_output=True,text=True,timeout=5)
            self.assertEqual(p.returncode,2)
            self.assertNotIn('正在检测',p.stdout)

    def test_host_trailing_root_dot_is_normalized(self):
        p=subprocess.run([BINARY,'--host','epdg.example.','--dns','127.0.0.1','--timeout','1'],capture_output=True,text=True,timeout=5)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('[epdg.example]',p.stdout)

    def test_plain_results_distinguish_evidence_from_errors(self):
        cases=[((1,1,0,0),'✅ 网络检测通过'),((0,1,0,0),'⚠️ 只测通了部分连接'),
               ((0,0,0,0),'⚠️ 暂未测通'),((0,0,1,0),'找不到运营商服务器'),
               ((0,0,0,1),'❌ 检测出错')]
        for args,expected in cases:
            result=run('result',*args).decode()
            self.assertIn(expected,result)
            self.assertNotIn('\x1b',result)
            self.assertNotIn('不能使用',result)

    def test_terminal_color_and_no_color_opt_out(self):
        for disabled in (False,True):
            pid,fd=pty.fork()
            if pid==0:
                if disabled: os.environ['NO_COLOR']='1'
                else: os.environ.pop('NO_COLOR',None)
                os.execl(HARNESS,HARNESS,'result','1','1','0','0')
            output=b''
            try:
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    if select.select([fd],[],[],.1)[0]:
                        try: chunk=os.read(fd,4096)
                        except OSError: break
                        if not chunk: break
                        output+=chunk
                self.assertIn('网络检测通过'.encode(),output)
                self.assertEqual(b'\x1b[1;36m' in output,not disabled)
                self.assertEqual(b'\x1b[1;32m' in output,not disabled)
            finally:
                os.close(fd)
                try: os.kill(pid,signal.SIGKILL)
                except ProcessLookupError: pass
                os.waitpid(pid,0)

    def test_details_are_opt_in(self):
        base=[BINARY,'--country','加拿大','--dns','127.0.0.1','--timeout','1']
        plain=subprocess.check_output(base,text=True)
        detail=subprocess.check_output(base+['--details'],text=True)
        self.assertNotIn('DNS/UDP 53',plain)
        self.assertNotIn('技术汇总',plain)
        self.assertIn('技术汇总',detail)
        self.assertIn('DNS/UDP 53',detail)
        self.assertIn('共检查 3 家',plain)

    def test_carrier_list_and_version(self):
        self.assertEqual(len(subprocess.check_output([BINARY,'--list']).splitlines()),42)
        self.assertEqual(subprocess.check_output([BINARY,'--version']).strip(),b'2.2.0')

if __name__=='__main__': unittest.main(verbosity=2)
