<div align="center">

# L0p4Map

**Nmap was blind. L0p4Map sees.**

![Python](https://img.shields.io/badge/Python-3.11+-00ff99?style=flat-square&logo=python&logoColor=black)
![Platform](https://img.shields.io/badge/Platform-Linux-00ff99?style=flat-square&logo=linux&logoColor=black)
![License](https://img.shields.io/badge/License-GPL--v3-00ff99?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)

Professional network monitoring & visualization tool built for security researchers.

![L0p4Map Home](img/Lopamap.gif)

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
- **Network Graph** — interactive topology visualization 

---

## Screenshots

### Home — Network Scanner
![Home](img/lopamap1.png)

### Port Scan — Full nmap Integration
![Port Scan](img/lopamap2.png)

### Network Topology — Interactive network topology graph
![Network Topology Graph](img/retepng.png)

---

## Requirements

- Linux (Debian or Arch)
- Python 3.11+
- nmap installed (`sudo pacman -S nmap` or `sudo apt install nmap`)
- Root privileges (required for ARP scanning)

---

## Installation

```bash
git clone https://github.com/HaxL0p4/L0p4Map.git
cd L0p4Map
pip install -r requirements.txt
sudo chmod +x L0p4Map.sh
```

---

## Usage

Launch the tool with root privileges:

```bash
sudo ./L0p4Map.sh
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

---

<div align="center">
<sub>🚧 Under active development — star the repo to follow updates</sub>
</div>
