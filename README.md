# codealpha_task_2
# Basic Network Packet Sniffer

A lightweight command-line packet sniffer written in Python with [Scapy](https://scapy.net/). It captures live network traffic, decodes the main protocol layers, and prints a concise one-line summary per packet, with an optional payload preview. Built as an educational tool for learning how network traffic is structured and how protocols behave on the wire.

---

## Features

- **Live packet capture** on any network interface, or on Scapy's default interface.
- **Multi-protocol decoding** for TCP, UDP, ICMP and ARP, over both IPv4 and IPv6.
- **Application-layer identification** based on well-known ports (HTTP, HTTPS, DNS, SSH, FTP, SMTP, DHCP, mDNS, MySQL, RDP and others).
- **BPF filtering** using standard Berkeley Packet Filter syntax (for example `tcp port 80`).
- **Packet limit option** to stop automatically after a set number of packets.
- **Payload preview** showing the first 64 bytes of raw data as both printable ASCII and hexadecimal.
- **TCP flag display** for inspecting handshakes and connection state.
- **Low memory footprint**: packets are processed as they arrive and are not stored.
- **Graceful error handling** for missing privileges, missing dependencies and `Ctrl+C` interruption.

## Requirements

- Python 3.8 or newer
- [Scapy](https://pypi.org/project/scapy/)
- Administrator or root privileges (required for raw packet capture)
- **Windows only:** [Npcap](https://npcap.com) must be installed

## Installation

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
pip install scapy
```

## Usage

```bash
python packet_sniffer.py [-i INTERFACE] [-c COUNT] [-f FILTER]
```

| Option | Description | Default |
|---|---|---|
| `-i`, `--interface` | Network interface to sniff on | Scapy default |
| `-c`, `--count` | Number of packets to capture (`0` = unlimited) | `0` |
| `-f`, `--filter` | BPF filter expression | none |

### Examples

```bash
# Capture on the default interface until stopped with Ctrl+C
sudo python3 packet_sniffer.py

# Capture on a specific interface
sudo python3 packet_sniffer.py -i eth0

# Capture exactly 50 packets
sudo python3 packet_sniffer.py -c 50

# Capture only HTTP traffic
sudo python3 packet_sniffer.py -f "tcp port 80"

# Capture 8 DNS packets (Windows, from an elevated terminal)
python packet_sniffer.py -f "udp port 53" -c 8
```

On Linux and macOS, run with `sudo`. On Windows, run from a terminal opened as Administrator.

## Sample Output

DNS capture using `-f "udp port 53" -c 8`:

```
======================================================================
 Basic Network Sniffer — for educational use on your own network
======================================================================
Interface : \Device\NPF_{...}
Filter: udp port 53
Count     : 8
----------------------------------------------------------------------
[    1] 01:31:53.186  UDP      192.168.10.180 -> 1.1.1.1          ports 49762->53  (DNS)  len=83
[    2] 01:31:53.196  UDP             1.1.1.1 -> 192.168.10.180   ports 53->49762  (DNS)  len=136
[    3] 01:32:05.350  UDP      192.168.10.180 -> 1.1.1.1          ports 49665->53  (DNS)  len=85
[    4] 01:32:05.360  UDP      192.168.10.180 -> 1.1.1.1          ports 49666->53  (DNS)  len=85
```

Each line reports the packet number, timestamp, transport protocol, source and destination addresses, ports, TCP flags (where applicable), the inferred application protocol, and the total packet length. When a packet carries a raw payload, a second line shows a preview of its contents.

## How It Works

1. `scapy.sniff()` captures packets from the chosen interface, applying the optional BPF filter at capture time.
2. Each packet is passed to a handler that identifies the transport protocol and extracts source and destination addresses from the IPv4, IPv6 or ARP layer.
3. Port numbers are matched against a lookup table to infer the application protocol.
4. If a raw payload is present, a bounded preview is rendered in ASCII and hex.
5. The formatted result is printed immediately, and the packet is discarded.

## Project Structure

```
.
├── packet_sniffer.py   # Main application
└── README.md
```

## Limitations

- Application protocol detection is port-based, so traffic on non-standard ports may be labelled incorrectly or not at all.
- Encrypted traffic (for example HTTPS) is displayed as ciphertext; the tool does not decrypt it.
- Packets that are not TCP, UDP, ICMP or ARP (including ICMPv6) are labelled `OTHER`.
- Output is written to the console only; there is no built-in export to `.pcap` or log files.

## Roadmap

- Export captured packets to `.pcap` for analysis in Wireshark
- Dedicated DNS query and response parsing
- Optional colour-coded output
- Capture statistics summary on exit (protocol breakdown, top talkers)
- Log-to-file option

## Legal and Ethical Notice

This tool is intended **for educational purposes only**. Capture network traffic only on networks and devices that you own or have explicit, written permission to monitor. Intercepting traffic without authorization may violate local laws and regulations. The author accepts no responsibility for misuse of this software.

## Contributing

Suggestions and pull requests are welcome. For significant changes, please open an issue first to discuss what you would like to change.


## Author

Prapto Charles Costa
Department of Information & Communication Engineering, Daffodil International University
