#!/usr/bin/env python3
"""
Basic network sniffer (standard library only).

Captures raw packets and decodes: Ethernet -> IPv4 -> TCP / UDP / ICMP.

Usage (needs admin/root):
    sudo python3 sniffer.py                       # capture everything
    sudo python3 sniffer.py -i eth0 -c 50         # 50 packets on eth0
    sudo python3 sniffer.py -p tcp --port 443     # only TCP port 443
    sudo python3 sniffer.py -x                    # also show payload hex dump
    sudo python3 sniffer.py -o capture.log        # also write output to a file

Platforms:
    Linux   - AF_PACKET raw socket (sees Ethernet headers)
    Windows - SIO_RCVALL raw socket (starts at the IP header)
    macOS   - no AF_PACKET; use scapy or tcpdump instead

Only capture traffic on networks you own or have permission to monitor.
"""

import argparse
import platform
import socket
import struct
import sys
import time
from collections import Counter

ETH_P_ALL = 0x0003
ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "VLAN"}
IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
ICMP_TYPES = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
TCP_FLAGS = [(0x20, "URG"), (0x10, "ACK"), (0x08, "PSH"),
             (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN")]


# ---------------------------------------------------------------- parsers
def fmt_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def parse_ethernet(data: bytes):
    dst, src, ethertype = struct.unpack("!6s6sH", data[:14])
    return {"dst": fmt_mac(dst), "src": fmt_mac(src), "type": ethertype}, data[14:]


def parse_ipv4(data: bytes):
    ver_ihl = data[0]
    ihl = (ver_ihl & 0x0F) * 4
    total_len = struct.unpack("!H", data[2:4])[0]
    ttl, proto, src, dst = struct.unpack("!8xBB2x4s4s", data[:20])
    return {
        "version": ver_ihl >> 4,
        "header_len": ihl,
        "total_len": total_len,
        "ttl": ttl,
        "proto": proto,
        "src": socket.inet_ntoa(src),
        "dst": socket.inet_ntoa(dst),
    }, data[ihl:]


def parse_tcp(data: bytes):
    sport, dport, seq, ack, off_flags, window = struct.unpack("!HHLLHH", data[:16])
    offset = (off_flags >> 12) * 4
    flags = [name for bit, name in TCP_FLAGS if off_flags & bit]
    return {"sport": sport, "dport": dport, "seq": seq, "ack": ack,
            "flags": ",".join(flags) or "-", "window": window}, data[offset:]


def parse_udp(data: bytes):
    sport, dport, length = struct.unpack("!HHH", data[:6])
    return {"sport": sport, "dport": dport, "length": length}, data[8:]


def parse_icmp(data: bytes):
    icmp_type, code = struct.unpack("!BB", data[:2])
    return {"type": icmp_type, "code": code}, data[4:]


def hexdump(data: bytes, width: int = 16, limit: int = 128) -> str:
    lines = []
    for i in range(0, min(len(data), limit), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"      {i:04x}  {hex_part} {ascii_part}")
    if len(data) > limit:
        lines.append(f"      ... ({len(data) - limit} more bytes)")
    return "\n".join(lines)


# --------------------------------------------------------------- sniffing
def open_socket(interface):
    system = platform.system()
    if system == "Linux":
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        if interface:
            s.bind((interface, 0))
        return s, True  # True -> frames include an Ethernet header
    if system == "Windows":
        host = socket.gethostbyname(socket.gethostname())
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((host, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return s, False
    sys.exit(f"{system} is not supported by this raw-socket sniffer (try scapy).")


def analyse(frame: bytes, has_eth: bool, args, stats: Counter):
    """Decode one frame. Returns a printable string, or None if filtered out."""
    lines = []
    payload = frame

    if has_eth:
        eth, payload = parse_ethernet(frame)
        etype = ETHERTYPES.get(eth["type"], f"0x{eth['type']:04x}")
        if eth["type"] != 0x0800:          # not IPv4: summarise and stop
            stats[etype] += 1
            if args.protocol != "all":
                return None
            return f"[{etype}] {eth['src']} -> {eth['dst']} ({len(frame)} bytes)"
        lines.append(f"  Ethernet: {eth['src']} -> {eth['dst']}  ({etype})")

    ip, payload = parse_ipv4(payload)
    proto_name = IP_PROTOCOLS.get(ip["proto"], f"proto-{ip['proto']}")

    if args.protocol != "all" and proto_name.lower() != args.protocol:
        return None

    summary = f"[{proto_name}] {ip['src']} -> {ip['dst']}"
    lines.append(f"  IPv4:     ttl={ip['ttl']} len={ip['total_len']} hdr={ip['header_len']}")

    if proto_name == "TCP" and len(payload) >= 20:
        tcp, payload = parse_tcp(payload)
        ports = (tcp["sport"], tcp["dport"])
        if args.port and args.port not in ports:
            return None
        summary = (f"[TCP] {ip['src']}:{tcp['sport']} -> {ip['dst']}:{tcp['dport']} "
                   f"flags={tcp['flags']}")
        lines.append(f"  TCP:      seq={tcp['seq']} ack={tcp['ack']} win={tcp['window']}")
    elif proto_name == "UDP" and len(payload) >= 8:
        udp, payload = parse_udp(payload)
        ports = (udp["sport"], udp["dport"])
        if args.port and args.port not in ports:
            return None
        summary = f"[UDP] {ip['src']}:{udp['sport']} -> {ip['dst']}:{udp['dport']} len={udp['length']}"
    elif proto_name == "ICMP" and len(payload) >= 4:
        icmp, payload = parse_icmp(payload)
        if args.port:
            return None
        desc = ICMP_TYPES.get(icmp["type"], f"type {icmp['type']}")
        summary = f"[ICMP] {ip['src']} -> {ip['dst']} {desc}"
    elif args.port:
        return None

    stats[proto_name] += 1
    out = [summary + f"  ({len(payload)} B payload)"]
    if args.verbose:
        out += lines
    if args.hex and payload:
        out.append(hexdump(payload))
    return "\n".join(out)


def main():
    p = argparse.ArgumentParser(description="Basic network sniffer")
    p.add_argument("-i", "--interface", help="interface to bind to (Linux), e.g. eth0")
    p.add_argument("-c", "--count", type=int, default=0, help="stop after N shown packets (0 = unlimited)")
    p.add_argument("-p", "--protocol", choices=["all", "tcp", "udp", "icmp"], default="all")
    p.add_argument("--port", type=int, help="only show packets using this port")
    p.add_argument("-v", "--verbose", action="store_true", help="show header details")
    p.add_argument("-x", "--hex", action="store_true", help="hex dump the payload")
    p.add_argument("-o", "--output", help="also write output to this file")
    args = p.parse_args()

    try:
        sock, has_eth = open_socket(args.interface)
    except PermissionError:
        sys.exit("Permission denied: run as root/Administrator (e.g. with sudo).")

    log = open(args.output, "a") if args.output else None
    stats, shown, start = Counter(), 0, time.time()
    sock.settimeout(1.0)  # wake up every second so Ctrl+C works on Windows
    print("Sniffing... press Ctrl+C to stop.\n")

    try:
        while True:
            try:
                frame, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                text = analyse(frame, has_eth, args, stats)
            except (struct.error, IndexError):
                stats["malformed"] += 1
                continue
            if text is None:
                continue
            shown += 1
            line = f"{time.strftime('%H:%M:%S')} #{shown} {text}"
            print(line)
            if log:
                log.write(line + "\n")
            if args.count and shown >= args.count:
                break
    except KeyboardInterrupt:
        pass
    finally:
        if platform.system() == "Windows":
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sock.close()
        if log:
            log.close()

    print(f"\n--- {shown} packets shown in {time.time() - start:.1f}s ---")
    for name, n in stats.most_common():
        print(f"  {name:<10} {n}")


if __name__ == "__main__":
    main()
