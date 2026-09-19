<p align="center">
  <img src="logo.png" alt="CodeAlpha" width="180">
</p>

<h2 align="center">CodeAlpha Cyber Security Internship - Task 1</h2>

**Name:** Iqra Sajid
**Program:** BS Geoinformatics (Student)
**Internship:** CodeAlpha - Cyber Security
**Task:** Task 1

## 1. Objective
Build a Python program that captures network packets, analyzes their structure and content, and displays useful details such as source/destination IPs, protocols, ports and payloads. The goal is to understand how data flows through a network and the basics of protocols.

## 2. Tools Used
- Python 3.12
- Scapy (packet capture and parsing)
- Npcap (packet capture driver on Windows)
- Wireshark (optional, to open the saved `.pcap` file)

## 3. How It Works
1. `sniff()` from Scapy captures packets from the network interface.
2. For every packet, `process_packet()` is called.
3. The packet is read layer by layer: **Ethernet -> IP -> TCP/UDP/ICMP -> Payload**.
4. The program prints:
   - Timestamp, source IP -> destination IP, packet length, TTL
   - Protocol (TCP / UDP / ICMP / ARP)
   - Source and destination ports (with service names such as 80/HTTP, 53/DNS, 443/HTTPS)
   - TCP flags (SYN, ACK, PSH, FIN, ...)
   - DNS query names
   - Payload preview in hex and ASCII
5. When capture stops, a summary of packet counts per protocol is shown, and packets can be saved to a `.pcap` file.

## 4. How to Run
Run the terminal as Administrator (Windows) or with `sudo` (Linux/Mac).

```
py -m pip install scapy
py sniffer.py --list-interfaces
py sniffer.py -c 20                          # capture 20 packets
py sniffer.py -f "icmp" -c 8 -o ping.pcap    # ping traffic, saved to file
py sniffer.py -f "udp port 53" -c 8          # DNS traffic
py sniffer.py -f "tcp port 80" -c 5          # HTTP traffic
```

Options: `-i` interface, `-c` packet count, `-f` BPF filter, `-o` save to pcap, `--no-payload` hide payload.

Optional: a second version, `sniffer_socket.py`, uses only Python's raw `socket` and `struct` modules to parse Ethernet, IP, TCP, UDP and ICMP headers manually. It is Linux only and was not run on Windows; the main submission is `sniffer.py`.

## 5. Observations
- **HTTPS payload is unreadable:** payloads starting with `17 03 03` are TLS encrypted data, so the ASCII view shows random characters.
- **DNS:** the PC sends a query (for example for a website name) to the router on UDP port 53, and the router replies. The reply also contains the original question, so the query name appears in both packets.
- **TCP flags:** `PSH,ACK` shows data being sent, and `FIN,ACK` shows a connection being closed.
- **QUIC / HTTP3:** UDP traffic on port 443 with large encrypted payloads is QUIC.
- **HTTP is readable:** on a plain HTTP site, the payload shows text such as `GET / HTTP/1.1` and the `Host:` header, because HTTP is not encrypted.
- **SSDP:** `M-SEARCH * HTTP/1.1` packets are device-discovery messages and are readable in plain text.

## 6. Screenshots
1. General capture (`py sniffer.py -c 20`)
2. ICMP / ping capture
3. DNS capture
4. HTTP capture showing readable payload

## 7. Conclusion
The sniffer successfully captures packets and shows source/destination IPs, protocols, ports and payloads. It showed how different protocols behave (TCP handshake flags, DNS lookups, ICMP ping) and why encryption (HTTPS/TLS) protects data from being read by a sniffer.

## 8. Ethical Note
Packet sniffing should only be done on networks you own or have permission to monitor.
