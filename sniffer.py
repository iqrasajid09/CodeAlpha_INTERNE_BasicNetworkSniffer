#!/usr/bin/env python3
"""
Task 1: Basic Network Sniffer (scapy version)

Kya karta hai:
  - Network se packets capture karta hai
  - Har packet ko analyze karta hai (Ethernet -> IP -> TCP/UDP/ICMP -> Payload)
  - Source/Destination IP, protocol, ports, flags aur payload dikhata hai
  - Optional: packets .pcap file mein save karta hai (Wireshark mein khul jati hai)

Usage (admin/root zaroori hai):
  Linux/Mac : sudo python3 sniffer.py
  Windows   : Admin CMD/PowerShell se  ->  python sniffer.py   (Npcap installed ho)

Examples:
  python3 sniffer.py -c 20                     # sirf 20 packets
  python3 sniffer.py -f "tcp port 80"          # sirf HTTP traffic
  python3 sniffer.py -f "udp port 53"          # sirf DNS
  python3 sniffer.py -i wlan0 -c 50 -o out.pcap
  python3 sniffer.py --list-interfaces

NOTE: Sirf apne network / permission wale network par use karein.
"""

import argparse
import sys
from collections import Counter
from datetime import datetime

from scapy.all import (
    ARP,
    ICMP,
    IP,
    TCP,
    UDP,
    DNS,
    IPv6,
    Raw,
    get_if_list,
    sniff,
    wrpcap,
)

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-alt",
}

captured = []          # saved packets (pcap ke liye)
stats = Counter()      # protocol counts


def payload_preview(data: bytes, limit: int = 64):
    """Payload ka hex aur ASCII preview banata hai."""
    chunk = data[:limit]
    hex_part = chunk.hex(" ")
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    more = " ..." if len(data) > limit else ""
    return hex_part, ascii_part + more


def tcp_flags(tcp_layer) -> str:
    """TCP flags ko readable form mein (SYN, ACK, ...) convert karta hai."""
    names = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}
    return ",".join(names[f] for f in str(tcp_layer.flags) if f in names) or "-"


def service(port):
    return f"{port}/{WELL_KNOWN_PORTS[port]}" if port in WELL_KNOWN_PORTS else str(port)


def process_packet(pkt, show_payload=True):
    """Har captured packet par ye function call hota hai."""
    ts = datetime.now().strftime("%H:%M:%S")
    captured.append(pkt)

    # ---- ARP (layer 2, IP nahi hota) ----
    if ARP in pkt:
        arp = pkt[ARP]
        op = "who-has" if arp.op == 1 else "is-at"
        stats["ARP"] += 1
        print(f"[{ts}] ARP  {op}  {arp.psrc} -> {arp.pdst}  ({arp.hwsrc})")
        return

    # ---- IPv4 / IPv6 ----
    if IP in pkt:
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        proto = PROTO_NAMES.get(ip.proto, f"OTHER({ip.proto})")
        ttl = ip.ttl
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        src, dst = ip.src, ip.dst
        proto = PROTO_NAMES.get(ip.nh, f"OTHER({ip.nh})")
        ttl = ip.hlim
    else:
        stats["Non-IP"] += 1
        print(f"[{ts}] Non-IP packet: {pkt.summary()}")
        return

    stats[proto] += 1
    line = f"[{ts}] {proto:<5} {src} -> {dst}  len={len(pkt)} ttl={ttl}"

    if TCP in pkt:
        t = pkt[TCP]
        line += f"\n           ports: {service(t.sport)} -> {service(t.dport)}  flags={tcp_flags(t)}  seq={t.seq}"
    elif UDP in pkt:
        u = pkt[UDP]
        line += f"\n           ports: {service(u.sport)} -> {service(u.dport)}"
        if DNS in pkt and pkt[DNS].qd is not None:
            qname = pkt[DNS].qd.qname.decode(errors="ignore")
            line += f"\n           DNS query: {qname}"
    elif ICMP in pkt:
        i = pkt[ICMP]
        line += f"\n           ICMP type={i.type} code={i.code}"

    print(line)

    # ---- Payload ----
    if show_payload and Raw in pkt:
        data = bytes(pkt[Raw].load)
        hex_part, ascii_part = payload_preview(data)
        print(f"           payload ({len(data)} bytes)")
        print(f"             hex  : {hex_part}")
        print(f"             ascii: {ascii_part}")
    print("-" * 70)


def print_summary():
    print("\n=== Capture Summary ===")
    print(f"Total packets: {len(captured)}")
    for name, count in stats.most_common():
        print(f"  {name:<8} {count}")


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (scapy)")
    parser.add_argument("-i", "--interface", help="interface name (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0, help="kitne packets (0 = infinite, Ctrl+C se stop)")
    parser.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 80"')
    parser.add_argument("-o", "--output", help="packets .pcap file mein save karo")
    parser.add_argument("--no-payload", action="store_true", help="payload na dikhao")
    parser.add_argument("--list-interfaces", action="store_true", help="available interfaces dikhao")
    args = parser.parse_args()

    if args.list_interfaces:
        print("\n".join(get_if_list()))
        return

    print("[*] Sniffing shuru... (band karne ke liye Ctrl+C)")
    print(f"[*] interface={args.interface or 'default'}  filter='{args.filter or 'none'}'  count={args.count or 'unlimited'}\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter or None,
            prn=lambda p: process_packet(p, show_payload=not args.no_payload),
            count=args.count,
            store=False,
        )
    except PermissionError:
        sys.exit("[!] Permission denied - admin/root (sudo) se run karein.")
    except KeyboardInterrupt:
        pass
    except OSError as e:
        sys.exit(f"[!] Error: {e}\n    Windows par Npcap install hai? Sahi interface diya hai?")

    print_summary()
    if args.output and captured:
        wrpcap(args.output, captured)
        print(f"[+] {len(captured)} packets '{args.output}' mein save ho gaye (Wireshark se khol sakte hain).")


if __name__ == "__main__":
    main()
