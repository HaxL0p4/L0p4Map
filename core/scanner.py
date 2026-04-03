import ipaddress
import socket
import psutil
import requests
import csv as _csv
from scapy.all import ARP, Ether, srp
import os
from concurrent.futures import ThreadPoolExecutor

_vendor_cache: dict[str, str] = {}
_oui_db: dict[str, str] = {}

def _load_oui_db():
    global _oui_db
    if _oui_db:
        return
    db_path = os.path.join(os.path.dirname(__file__), "oui.csv")
    if not os.path.exists(db_path):
        return
    with open(db_path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = _csv.DictReader(f)
        for row in reader:
            oui = row.get("Assignment", "").upper().strip()
            name = row.get("Organization Name", "").strip()
            if oui and name:
                _oui_db[oui] = name

def get_network_interfaces():
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for iface, addr_list in addrs.items():
        if iface not in stats or not stats[iface].isup:
            continue
        ip = None
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ip = addr.address
        if not ip or ip.startswith("127."):
            continue
        interfaces.append({"name": iface, "ip": ip})
    return interfaces

def check_root():
    if os.getuid() != 0:
        raise PermissionError("Execute the program with SUDO!")

def get_local_subnet(iface_name=None) -> str:
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    if iface_name:
        if iface_name not in interfaces:
            raise RuntimeError(f"Interface '{iface_name}' not found.")
        if not stats[iface_name].isup:
            raise RuntimeError(f"Interface '{iface_name}' not active.")
        for addr in interfaces[iface_name]:
            if addr.family == socket.AF_INET:
                return str(ipaddress.IPv4Network(
                    f"{addr.address}/{addr.netmask}", strict=False))
        raise RuntimeError(f"No IPv4 address on '{iface_name}'.")
    for nome, indirizzi in interfaces.items():
        if not stats[nome].isup:
            continue
        for addr in indirizzi:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if ip.startswith("127."):
                    continue
                return str(ipaddress.IPv4Network(
                    f"{ip}/{addr.netmask}", strict=False))
    raise RuntimeError("No active interface found.")

def get_vendor(mac: str) -> str:
    global _vendor_cache
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    if oui in _vendor_cache:
        return _vendor_cache[oui]
    _load_oui_db()
    if oui in _oui_db:
        vendor = _oui_db[oui]
        _vendor_cache[oui] = vendor
        return vendor
    _vendor_cache[oui] = "Unknown"
    return "Unknown"

def _dns_hostname(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except socket.herror:
        pass
    return None

def _netbios_hostname(ip: str) -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        query = (
            b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            b'\x00\x00!\x00\x01'
        )
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 72:
            name = data[57:72].decode("ascii", errors="ignore").strip()
            name = "".join(c for c in name if c.isprintable()).strip()
            if name:
                return name
    except Exception:
        pass
    return None

def _mdns_hostname(ip: str) -> str | None:
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        ptr = f"{reversed_ip}.in-addr.arpa"
        result = socket.getaddrinfo(ptr, None)
        if result:
            name = result[0][4][0]
            if name and name != ip:
                return name
    except Exception:
        pass
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1)
        name = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old_timeout)
        if name and name != ip:
            return name
    except Exception:
        pass
    return None

def resolve_hostname(ip: str) -> str:
    name = _dns_hostname(ip)
    if name:
        return name
    name = _netbios_hostname(ip)
    if name:
        return name
    name = _mdns_hostname(ip)
    if name:
        return name
    return ip

def scan_network(subnet: str) -> list[dict]:
    pacchetto = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    risposte, _ = srp(pacchetto, timeout=2, retry=2, inter=0.01 ,verbose=False)

    seen_macs = {}
    for _, risposta in risposte:
        mac = risposta[Ether].src
        ip = risposta[ARP].psrc
        if mac not in seen_macs:
            seen_macs[mac] = ip

    hosts = []
    for mac, ip in seen_macs.items():
        hosts.append({
            "ip": ip,
            "mac": mac,
            "hostname": ip,
            "vendor": "...",
        })

    def enrich(host):
        host["hostname"] = resolve_hostname(host["ip"])
        host["vendor"] = get_vendor(host["mac"])
        return host

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(enrich, hosts))

    results.sort(key=lambda h: [int(x) for x in h["ip"].split(".")])
    return results
