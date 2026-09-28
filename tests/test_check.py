#!/usr/bin/env python3
"""Deterministic protocol regressions; only loopback networking, no carrier traffic."""
import os
from pathlib import Path
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

    def test_carrier_list_and_version(self):
        self.assertEqual(len(subprocess.check_output([BINARY,'--list']).splitlines()),39)
        self.assertEqual(subprocess.check_output([BINARY,'--version']).strip(),b'2.0.0')

if __name__=='__main__': unittest.main(verbosity=2)
