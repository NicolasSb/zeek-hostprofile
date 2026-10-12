#!/usr/bin/env python3
"""Generates the synthetic traces in testing/Traces/ (pure stdlib).

Each trace is a small, deterministic scenario whose expected features can be
computed by hand; the scenario is described above each builder. Run it again
after changing a scenario, then refresh the baselines with ``btest -U``.

    python3 testing/Scripts/gen-traces.py
"""

import os
import struct

T0 = 1700000100.0  # Multiple of 60 s and 300 s: window starts are predictable.
TRACES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Traces")

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def ip2b(ip):
    return bytes(int(x) for x in ip.split("."))


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64,
                      proto, 0, ip2b(src), ip2b(dst))
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def l4_csum(src, dst, proto, seg):
    pseudo = ip2b(src) + ip2b(dst) + struct.pack("!BBH", 0, proto, len(seg))
    return csum(pseudo + seg)


def tcp(src, sport, dst, dport, seq, ack, flags, data=b""):
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                      65535, 0, 0) + data
    seg = seg[:16] + struct.pack("!H", l4_csum(src, dst, 6, seg)) + seg[18:]
    return ipv4(src, dst, 6, seg)


def udp(src, sport, dst, dport, data):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    seg = seg[:6] + struct.pack("!H", l4_csum(src, dst, 17, seg) or 0xFFFF) + seg[8:]
    return ipv4(src, dst, 17, seg)


class Trace:
    def __init__(self):
        self.pkts = []

    def add(self, t, ip_pkt):
        eth = b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" + b"\x08\x00"
        self.pkts.append((t, eth + ip_pkt))

    def write(self, name):
        with open(os.path.join(TRACES, name), "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for t, p in sorted(self.pkts, key=lambda x: x[0]):
                sec = int(t)
                usec = int(round((t - sec) * 1e6))
                f.write(struct.pack("<IIII", sec, usec, len(p), len(p)) + p)

    def tcp_conn(self, t, cli, sport, srv, dport, out=b"", back=b"", reject=False):
        """A TCP connection starting at t: full handshake, optional data each
        way, graceful close (state SF); or SYN answered by RST (state REJ)."""
        c, s = 1000, 5000
        self.add(t, tcp(cli, sport, srv, dport, c, 0, SYN))
        if reject:
            self.add(t + 0.01, tcp(srv, dport, cli, sport, 0, c + 1, RST | ACK))
            return
        c += 1
        self.add(t + 0.01, tcp(srv, dport, cli, sport, s, c, SYN | ACK))
        s += 1
        self.add(t + 0.02, tcp(cli, sport, srv, dport, c, s, ACK))
        dt = 0.03
        if out:
            self.add(t + dt, tcp(cli, sport, srv, dport, c, s, PSH | ACK, out))
            c += len(out)
            dt += 0.01
        if back:
            self.add(t + dt, tcp(srv, dport, cli, sport, s, c, PSH | ACK, back))
            s += len(back)
            dt += 0.01
        self.add(t + dt, tcp(cli, sport, srv, dport, c, s, FIN | ACK))
        self.add(t + dt + 0.01, tcp(srv, dport, cli, sport, s, c + 1, FIN | ACK))
        self.add(t + dt + 0.02, tcp(cli, sport, srv, dport, c + 1, s + 1, ACK))


def conn_windows():
    """Connection features over 1-minute windows (the test redefs window_len).

    A = 10.0.0.1, window [T0, T0+60): 5 connections starting every 10 s
      (regular rhythm, start_cv = 0):
        93.184.216.34:7777  SF, 100 bytes out / 300 in
        93.184.216.34:7777  SF, 100 / 300
        1.1.1.1:8080        SF, no payload
        10.0.0.2:22         SF, no payload (internal destination)
        104.16.0.1:445      REJ (failed)
    A, window [T0+60, T0+120): nothing (no row, window skipped).
    A, window [T0+120, T0+180): 93.184.216.34:7777 again, 50 / 50
      (not new; idle_before = 60).
    B = 10.0.0.9, window [T0, T0+60): 93.184.216.34:7777, 10 / 20
      (new for B: novelty memory is per host).
    151.101.1.1 (external) -> A: never profiled.
    """
    tr = Trace()
    a, b = "10.0.0.1", "10.0.0.9"
    tr.tcp_conn(T0 + 1, a, 40001, "93.184.216.34", 7777, b"o" * 100, b"i" * 300)
    tr.tcp_conn(T0 + 5, b, 40100, "93.184.216.34", 7777, b"o" * 10, b"i" * 20)
    tr.tcp_conn(T0 + 11, a, 40002, "93.184.216.34", 7777, b"o" * 100, b"i" * 300)
    tr.tcp_conn(T0 + 15, "151.101.1.1", 50000, a, 7777, b"o" * 10, b"i" * 10)
    tr.tcp_conn(T0 + 21, a, 40003, "1.1.1.1", 8080)
    tr.tcp_conn(T0 + 31, a, 40004, "10.0.0.2", 22)
    tr.tcp_conn(T0 + 41, a, 40005, "104.16.0.1", 445, reject=True)
    tr.tcp_conn(T0 + 125, a, 40006, "93.184.216.34", 7777, b"o" * 50, b"i" * 50)
    tr.write("conn-windows.pcap")


def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_msg(qid, name, reply=False, rcode=0, answer=None):
    flags = 0x8180 | rcode if reply else 0x0100
    msg = struct.pack("!HHHHHH", qid, flags, 1, 1 if answer else 0, 0, 0)
    msg += dns_name(name) + struct.pack("!HH", 1, 1)
    if answer:
        msg += struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + ip2b(answer)
    return msg


def dns():
    """DNS features, one 5-minute window. Host 10.0.0.1 asks 10.0.0.53:
        example.com           -> NOERROR
        EXAMPLE.com           -> NOERROR (same name: not new, not distinct)
        nonexistent.invalid   -> NXDOMAIN, then a duplicate NXDOMAIN (ignored)
        foo.test              -> no reply
    Expected: n_dns 4, n_domains 3, frac_new_domain 0.75, frac_nxdomain 0.25.
    """
    tr = Trace()
    h, ns = "10.0.0.1", "10.0.0.53"
    queries = [
        (1, "example.com", 0, "93.184.216.34"),
        (2, "EXAMPLE.com", 0, "93.184.216.34"),
        (3, "nonexistent.invalid", 3, None),
        (4, "foo.test", None, None),
    ]
    for i, (qid, name, rcode, ans) in enumerate(queries):
        t = T0 + 1 + 10 * i
        sport = 53001 + i
        tr.add(t, udp(h, sport, ns, 53, dns_msg(qid, name)))
        if rcode is not None:
            tr.add(t + 0.01, udp(ns, 53, h, sport,
                                 dns_msg(qid, name, True, rcode, ans)))
        if rcode == 3:
            tr.add(t + 0.02, udp(ns, 53, h, sport, dns_msg(qid, name, True, rcode)))
    tr.write("dns.pcap")


def client_hello(sni):
    name = sni.encode()
    sni_ext = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    exts = struct.pack("!HH", 0, len(sni_ext)) + sni_ext
    body = (b"\x03\x03" + bytes(range(32)) + b"\x00"
            + struct.pack("!H", 4) + b"\xc0\x2f\x00\x2f" + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def tls():
    """TLS features, one 5-minute window. Host 10.0.0.1 sends client hellos
    to port 443 with SNI Example.COM, example.com (same name, not new) and
    other.org. Expected: n_sni 3, frac_new_sni 2/3.
    """
    tr = Trace()
    h = "10.0.0.1"
    for i, sni in enumerate(["Example.COM", "example.com", "other.org"]):
        tr.tcp_conn(T0 + 1 + 10 * i, h, 41001 + i, "93.184.216.34", 443,
                    client_hello(sni))
    tr.write("tls.pcap")


def beacon():
    """Per-destination regularity, one 5-minute window.
    A = 10.0.0.1: 6 connections to 198.51.100.7 every 30 s (a beacon), mixed
      with 5 irregular ones to other destinations: the beacon gives
      beacon_cv 0.0 while start_cv over all 11 connections stays high.
    B = 10.0.0.2: 4 connections to 198.51.100.7 with gaps 10, 20, 30 s:
      beacon_cv = std / mean = 8.165 / 20 = 0.408.
    C = 10.0.0.3: 3 connections every 10 s, under beacon_min_conns (4):
      beacon_cv -1.0.
    """
    tr = Trace()
    a, b, c, c2 = "10.0.0.1", "10.0.0.2", "10.0.0.3", "198.51.100.7"
    sport = 42000
    for i in range(6):
        tr.tcp_conn(T0 + 10 + 30 * i, a, sport, c2, 443, b"x")
        sport += 1
    for i, (t, dst) in enumerate([(3, "1.1.1.1"), (4, "8.8.8.8"), (51, "9.9.9.9"),
                                  (52, "1.0.0.1"), (200, "8.8.4.4")]):
        tr.tcp_conn(T0 + t, a, sport, dst, 80, b"x")
        sport += 1
    for t in (0, 10, 30, 60):
        tr.tcp_conn(T0 + t, b, sport, c2, 443, b"x")
        sport += 1
    for t in (0, 10, 20):
        tr.tcp_conn(T0 + t, c, sport, c2, 443, b"x")
        sport += 1
    tr.write("beacon.pcap")


if __name__ == "__main__":
    conn_windows()
    dns()
    tls()
    beacon()
