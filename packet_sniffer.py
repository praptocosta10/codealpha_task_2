#!/usr/bin/env python3
"""
Basic Network Sniffer
======================
Educational tool to capture and analyze network traffic on your own machine/network.

Requirements:
    pip install scapy

Usage:
    sudo python3 packet_sniffer.py                  # sniff all interfaces
    sudo python3 packet_sniffer.py -i eth0           # sniff a specific interface
    sudo python3 packet_sniffer.py -c 50             # stop after 50 packets
    sudo python3 packet_sniffer.py -f "tcp port 80"  # apply a BPF filter

NOTE: Raw packet capture requires elevated privileges.
    - Linux/macOS: run with sudo
    - Windows: run as Administrator (and install Npcap first: https://npcap.com)

IMPORTANT: Only capture traffic on networks/devices you own or have explicit
permission to monitor. Sniffing traffic you don't own or lack authorization
for can be illegal.
"""

import argparse
import datetime
import sys

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, conf
except ImportError:
    print("scapy is not installed. Install it with:\n    pip install scapy")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def protocol_name(packet):
    """Return a human-readable protocol name for the packet's top layer."""
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    return "OTHER"


def guess_application_protocol(packet):
    """Make a best-effort guess at the application-layer protocol from ports."""
    port_map = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
        25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        3306: "MySQL", 3389: "RDP", 5353: "mDNS",
    }
    for layer in (TCP, UDP):
        if packet.haslayer(layer):
            sport = packet[layer].sport
            dport = packet[layer].dport
            if sport in port_map:
                return port_map[sport]
            if dport in port_map:
                return port_map[dport]
    return None


def format_payload(packet, max_bytes=64):
    """Return a short, safe preview of the payload (hex + printable ascii)."""
    if not packet.haslayer(Raw):
        return None
    data = bytes(packet[Raw].load)[:max_bytes]
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    hex_str = data.hex()
    suffix = "..." if len(bytes(packet[Raw].load)) > max_bytes else ""
    return f"{printable}{suffix}  |  hex: {hex_str}{suffix}"


# ---------------------------------------------------------------------------
# Core packet handler
# ---------------------------------------------------------------------------

packet_count = 0


def handle_packet(packet):
    global packet_count
    packet_count += 1

    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto = protocol_name(packet)

    # Determine source/destination addresses
    if packet.haslayer(IP):
        src, dst = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        src, dst = packet[IPv6].src, packet[IPv6].dst
    elif packet.haslayer(ARP):
        src, dst = packet[ARP].psrc, packet[ARP].pdst
    else:
        src, dst = "?", "?"

    line = f"[{packet_count:>5}] {timestamp}  {proto:<5}  {src:>21} -> {dst:<21}"

    # Add port info for TCP/UDP
    if packet.haslayer(TCP):
        line += f"  ports {packet[TCP].sport}->{packet[TCP].dport}"
        flags = packet[TCP].flags
        line += f"  flags={flags}"
    elif packet.haslayer(UDP):
        line += f"  ports {packet[UDP].sport}->{packet[UDP].dport}"

    app_proto = guess_application_protocol(packet)
    if app_proto:
        line += f"  ({app_proto})"

    line += f"  len={len(packet)}"

    print(line)

    payload_preview = format_payload(packet)
    if payload_preview:
        print(f"          payload: {payload_preview}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Basic educational network packet sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter string, e.g. 'tcp port 80'")
    args = parser.parse_args()

    print("=" * 70)
    print(" Basic Network Sniffer — for educational use on your own network")
    print("=" * 70)
    print(f"Interface : {args.interface or conf.iface}")
    print(f"Filter    : {args.filter or '(none)'}")
    print(f"Count     : {'infinite (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("-" * 70)

    try:
        sniff(
            iface=args.interface if args.interface else None,
            filter=args.filter if args.filter else None,
            prn=handle_packet,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("\nPermission denied. Packet capture requires elevated privileges.")
        print("Try running with sudo (Linux/macOS) or as Administrator (Windows).")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n\nStopped. Captured {packet_count} packets.")
        sys.exit(0)


if __name__ == "__main__":
    main()
