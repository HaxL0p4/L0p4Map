import ipaddress
import socket
import psutil
import requests
from scapy.all import ARP, Ether, srp
import os
from concurrent.futures import ThreadPoolExecutor

_vendor_cache: dict[str, str] = {}

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
    oui = mac.replace(":", "").upper()[:6]
    if oui in _vendor_cache:
        return _vendor_cache[oui]
    try:
        response = requests.get(
            f"https://api.macvendors.com/{oui}",
            timeout=3
        )
        if response.status_code == 200:
            vendor = response.text.strip()
            _vendor_cache[oui] = vendor
            return vendor
        _vendor_cache[oui] = "Unknown"
        return "Unknown"
    except requests.RequestException:
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
    risposte, _ = srp(pacchetto, timeout=3, retry=2, verbose=False)

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
            "hostname": resolve_hostname(ip),
            "vendor": "...",
        })

    def lookup(host):
        host["vendor"] = get_vendor(host["mac"])
        return host

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(lookup, hosts))

    results.sort(key=lambda h: [int(x) for x in h["ip"].split(".")])
    return results
