<div align="center">

# L0p4Map

**nmap was blind. Not anymore.**

![Python](https://img.shields.io/badge/Python-3.11+-00ff99?style=flat-square&logo=python&logoColor=black)
![Platform](https://img.shields.io/badge/Platform-Linux-00ff99?style=flat-square&logo=linux&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-00ff99?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)

Professional network monitoring & visualization tool built for security researchers.

</div>

---

## What is L0p4Map?

L0p4Map is a professional-grade network monitoring tool that combines the power of nmap with a clean, modern dark UI. Designed for security researchers and network administrators who need fast, detailed visibility into their infrastructure.

No bloat. No BS. Just raw network intelligence.

---

## Features

- **ARP Network Scan** — fast host discovery with parallel MAC vendor lookup
- **Hostname Resolution** — automatic reverse DNS for every device
- **Full nmap Integration** — SYN scan, UDP, OS detection, service version, NSE scripts
- **Banner Grabbing** — HTTP, SMB, FTP, SSH, SSL enumeration
- **Vulnerability Detection** — CVE lookup via vulners, vuln scripts, malware detection
- **Traceroute** — ICMP-based with real-time output
- **Dark Professional UI** — built with PyQt6, designed for researchers
- **Network Graph** — interactive topology visualization *(coming soon)*

---

## Requirements

- Linux (tested on Arch Linux)
- Python 3.11+
- nmap installed (`sudo pacman -S nmap` or `sudo apt install nmap`)
- Root privileges (required for ARP scanning)

---

## Installation
```bash
git clone https://github.com/HaxL0p4/L0p4Map.git
cd L0p4Map
pip install -r requirements.txt
sudo python3 ui/app.py
```

---

## Usage

Launch the tool with root privileges:
```bash
sudo python3 ui/app.py
```

1. Press **[ SCAN ]** to discover all devices on your network
2. Click a device to see details and run quick actions (ping, traceroute)
3. Press **[ PORT SCAN ]** to open the full nmap scan interface
4. Select scan options and press **[ RUN SCAN ]**

---

## Legal Disclaimer

This tool is designed for **authorized network auditing only**. Only use L0p4Map on networks you own or have explicit permission to test. Unauthorized scanning is illegal.

---

## Author

**HaxL0p4** — [GitHub](https://github.com/HaxL0p4)

> *Built from scratch. No wrappers. No shortcuts.*

---

<div align="center">
<sub>🚧 Under active development — star the repo to follow updates</sub>
</div>
