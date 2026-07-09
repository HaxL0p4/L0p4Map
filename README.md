<div align="center">

# L0p4Map
![Traffic Analyzer](ui/assets/logosite.png)

**Nmap was blind. L0p4Map sees.**

![Python](https://img.shields.io/badge/Python-3.11+-00ff99?style=flat-square&logo=python&logoColor=black)
![Platform](https://img.shields.io/badge/Platform-Linux-00ff99?style=flat-square&logo=linux&logoColor=black)
![License](https://img.shields.io/badge/License-GPL--v3-00ff99?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)

Professional network monitoring & visualization tool built for security researchers.

https://github.com/user-attachments/assets/745eb888-0636-47e8-9293-38a706a8e897

</div>

---

## What is L0p4Map? 👁️

L0p4Map is a professional-grade network monitoring tool that combines the power of nmap with a clean, modern dark UI. Designed for security researchers and network administrators who need fast, detailed visibility into their infrastructure.

No bloat. No BS. Just raw network intelligence.

---

## Features

- **ARP Network Scan** — fast host discovery with local IEEE OUI database lookup
- **Range Cartography** — scan any IP / CIDR / range. routed ranges are mapped via traceroute (hosts grouped under their last-hop router)
- **Hostname Resolution** — multi-method detection via reverse DNS, NetBIOS (Windows) and mDNS/Avahi (Linux, Mac, IoT)
- **Device Fingerprinting** — TTL-based OS hint (Linux/macOS, Windows, network device), TCP port probing on topology-relevant ports, raw SNMP `sysDescr` query (no external libs)
- **Embedded Service Fingerprinting** — passively detects iLO / InfoPrint / XPort / SATO / Zebra via banner grabbing and flags them on the graph as devices known to ship with default credentials, for manual verification
- **Role Detection** — automatic classification of each host: gateway, router, access point, switch, PC, Apple, mobile, Raspberry Pi, virtual machine, unknown — combining vendor, hostname, TTL, open ports and SNMP response
- **Real Network Topology Graph** — hierarchical vis.js graph that reflects the actual network structure: gateway at the top, intermediate devices (routers/APs/switches) on a second tier, clients grouped below their parent. Toggleable between Hierarchical and Force Atlas layouts
- **Subnet Bounding Boxes** — each detected subnet is drawn as a dashed overlay directly on the graph canvas, labeled with its CIDR
- **Typed Edges** — three visually distinct link types: uplink (gateway → internet), backbone (intermediate → gateway), client link (device → parent)
- **Topology Panel** — live overlay showing subnet, gateway IP, total devices and intermediate count
- **Full nmap Integration** — SYN scan, UDP, OS detection, service version, NSE scripts
- **Banner Grabbing** — HTTP, SMB, FTP, SSH, SSL enumeration
- **Vulnerability Detection** — CVE lookup via vulners, vuln and malware scripts
- **Attack Surface** — exposed services, open ports and CVE overview per host with CVSS scoring and direct NVD link; results exportable as CSV
- **Traffic Analyzer** — real-time packet capture with per-device stats, protocol coloring, filter bar, double-click to port scan; exportable as CSV
- **Traceroute** — ICMP-based with real-time output
- **Interface Selection** — choose which network interface to scan on
- **Live Monitoring** — auto-refresh the network graph at configurable intervals (30s / 60s / 120s)
- **Scan Export** — save full nmap output to `.txt`
- **Graph Export** — export the network topology as CSV or PNG
- **Custom Node Labels** — assign custom names to any device directly on the graph (double-click)
- **Dark Professional UI** — built with PyQt6

---

## Screenshots

### Home — Network Scanner
![Home](img/lopamap1.png)

### Port Scan — Full nmap Integration
![Port Scan](img/lopamap2.png)

### Network Topology — Hierarchical topology graph
![Network Topology Graph | Hierarchical](img/retepng1.png)

### Network Topology — Force Atlas layout
![Network Topology Graph | Force Atlas](img/retepng2.png)

### Attack Surface — Exposed services, open ports and vulnerability overview
![Attack surface section](img/Ats.png)

### Traffic Analyzer — Real-time network traffic analysis
![Traffic Analyzer](img/traffic2.png)

---

## Requirements

- Linux (Debian or Arch)
- Python 3.11+
- nmap installed (`sudo pacman -S nmap` or `sudo apt install nmap`)
- Root privileges (required for ARP scanning and packet capture)

---

## Installation

```bash
git clone https://github.com/HaxL0p4/L0p4Map.git
cd L0p4Map
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo chmod +x L0p4Map.sh
```

---

## Usage

Launch the tool with root privileges:

```bash
sudo ./L0p4Map.sh
```

1. Select the network interface from the toolbar dropdown
2. Press **[ SCAN ]** to discover all devices — each host is fingerprinted via TTL, port probing and SNMP
3. Click a device to see details and run quick actions (ping, traceroute, port scan)
4. Switch to **Graph** to explore the real network topology — hover nodes for full device info, double-click to assign a custom label
5. Toggle between **[ HIERARCHICAL ]** and **[ FORCE ATLAS ]** layout from the graph view
6. Use **Attack Surface** to run a deep nmap + vulners scan on any host and review CVEs
7. Use **Traffic Analyzer** to capture live packets, filter by device or protocol, and export to CSV
8. Enable **[ LIVE ]** in the graph view to keep the topology updated automatically

---

## Legal Disclaimer

This tool is designed for **authorized network auditing only**. Only use L0p4Map on networks you own or have explicit permission to test. Unauthorized scanning is illegal.

---

## Author

**HaxL0p4** — [GitHub](https://github.com/HaxL0p4)

---