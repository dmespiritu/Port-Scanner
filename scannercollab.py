import socket
import argparse
import traceback
import struct
import os
import datetime
import threading
import copy_reg
import types
import multiprocessing
from random import randint

from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor


BUFFER_SIZE = 1024
FP = 31337
PSIZE = 100

ports = [_ for _ in range(FP, FP+PSIZE)]
used_ports = [False] * PSIZE
MESSAGE = 192 * b'Q'

UNKNOWN = 'unknown'

def _pickle_method(m):
    if m.im_self is None:
        return getattr, (m.im_class.func_name)
    else:
        return getattr, (m.im_self, m.im_func.func_name)

copy_reg.pickle(types.MethodType, _pickle_method)

def get_cur_time():
    diff = datetime.datetime.utcnow() - datetime.datetime(1900, 1, 1, 0, 0, 0)
    return diff.days * 24 * 60 * 60 + diff.seconds


class ProtoScanner:
    def __init__(self):
        self.checkers = [(self.scan_if_pop3, 'pop3'), (self.scan_if_smtp, 'smtp'),
                         (self.scan_if_imap, 'imap'), (self.scan_if_http, 'http'), 
                         (self.scan_if_dns, 'dns'), (self.scan_if_ntp, 'ntp')]

    def get_sockets(self, timeout=2):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        for s in [udp, tcp]:
            s.settimeout(timeout)
        return [(udp, 'udp'), (tcp, 'tcp')]

    def send_data(self, sock, data, udpaddr=None):
        resp = b''
        try:
            if udpaddr:
                sock.sendto(data, udpaddr)
                resp, _ = sock.recvfrom(BUFFER_SIZE)
            else:
                sock.send(data)
                resp = sock.recv(BUFFER_SIZE)
        except socket.error:
            pass
        return resp

    def scan_receivable(self, sendata, checkdata, sock, udpaddr):
        resp = self.send_data(sock, sendata, udpaddr)

        for cdata in checkdata:
            if cdata in resp:
                return True
        return False

    def check_if_correct(self, resp):
        return resp not in [None, b''] and resp[-5:] != b'\x00' * 5

    def scan_if_smtp(self, sock, udpaddr=None):
        return self.scan_receivable(b'EHLO a', [b'smtp', b'SMTP'], sock, udpaddr)

    def scan_if_ntp(self, sock, udpaddr=None):
        ntp_request = b'\xe3\x00\x03\xfa' + b'\x00\x01\x00\x00' * 2 + 28 * b'\x00'
        ntp_request += struct.pack('!I ', get_cur_time()) + b'\x00' * 4
        resp = self.send_data(sock, ntp_request, udpaddr)
        return self.check_if_correct(resp)

    def scan_if_dns(self, sock, udpaddr=None):
        google = b'\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00'
        dns_query = (b'\xb9\x73\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                     b'\x03\x77\x77\x77') + google + b'\x00\x01\x00\x01'
        resp = self.send_data(sock, dns_query, udpaddr)
        return self.check_if_correct(resp) and google in resp

    def scan_if_pop3(self, sock, udpaddr=None):
        return self.scan_receivable(b'test', [b'+OK POP', b'+OK pop'], sock, udpaddr)

    def scan_if_imap(self, sock, udpaddr=None):
        return self.scan_receivable(b'test', [b'* OK ', b'IMAP'], sock, udpaddr)

    def scan_if_http(self, sock, udpaddr=None):
        return self.scan_receivable(b'ping\r\n', [b'HTTP'], sock, udpaddr)


class Scanner(object):
    def __init__(self, host, min_port, max_port, tcp, udp):
        super(Scanner, self).__init__()

        self.host       = host
        self.min_port   = min_port
        self.max_port   = max_port
        self.open_ports = []
        self._tcp = tcp
        self._udp = udp

        self.proto_scan = ProtoScanner()

    def _write_res(self, addr, prot, state):
        port = addr[1]
        checkers = self.proto_scan.checkers

        service = UNKNOWN
        try:
            for checker, proto in checkers:
                is_set = False
                for sock, sock_prot in self.proto_scan.get_sockets():
                    if sock_prot == 'tcp':
                        try:
                            sock.connect(addr)
                        except socket.error:
                            continue
                    if checker(sock, None if sock_prot == 'tcp' else addr):
                        service = proto
                        is_set = True
                        break
                if is_set:
                    break
            # service = socket.getservbyport(port, prot)
        except OSError as e:
            pass
        finally:
            if service == UNKNOWN:
                service = socket.getservbyport(int(port))
        return ['{:>5}\\{}'.format(port, prot), state, service]

    def _check_valid_udp_packet(self, packet, port):
        src_port = struct.unpack('>H', packet[-8:-6])[0]
        dst_port = struct.unpack('>H', packet[-6:-4])[0]

        if port != src_port:
            return None
        ptype = packet[(packet[0] & 0xF) * 4]
        if ptype != 3:
            return True
        return False

    def _inner_scan_udp(self, host):
        resp = []
        is_reachable = False
        is_set = False

        send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv.settimeout(3)

        recv.bind(('', 0))
        main_packet = MESSAGE
        send.sendto(main_packet, host)

        try:
            last_packet = b''
            while not is_set:
                data, _ = recv.recvfrom(BUFFER_SIZE)
                if not data:
                    break 
                packets = []
                if MESSAGE in data:
                    packets = data.split(MESSAGE)[:-1]
                    if last_packet:
                        last_packet += packets[0]
                elif last_packet:
                    last_packet += data
                for packet in packets:
                    is_reachable = self._check_valid_udp_packet(packet, send.getsockname()[1])
                    if is_reachable != None:
                        is_set = True
        except socket.error:
            is_reachable = True
        finally:
            send.close()
        
        return is_reachable

    def _st_udp_scan(self, host):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(b'', host)
            resp, _ = sock.recvfrom(BUFFER_SIZE)
            return True
        except socket.error:
            return False

    def scan_udp(self, host):
        if not self._udp:
            return []
        is_reachable = False
        for i in range(3):
            if self._inner_scan_udp(host):
                is_reachable = True
                break
        return self._write_res(host, 'udp', 'open') if is_reachable else []

    def scan_tcp(self, host):
        if not self._tcp:
            return []
        resp = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        res = sock.connect_ex(host)
        if res == 0:
            resp = self._write_res(host, 'tcp', 'open')
        sock.close()
        return resp

    def scan(self):
        open_ports = []
        protocol_scans = [self.scan_tcp, self.scan_udp]

        for i in range(self.min_port, self.max_port):
            for _scan in protocol_scans:
                resp = _scan((self.host, i))
                if resp != []:
                    self.open_ports.append(resp)
        return self.open_ports


class ThreadScanner(Scanner, threading.Thread):
    def __init__(self, host, min_port, max_port, tcp, udp):
        super(ThreadScanner, self).__init__(host, min_port, max_port, tcp, udp)

    def run(self):
        self.scan()