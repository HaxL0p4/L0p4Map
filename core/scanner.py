import ipaddress
import socket
import psutil
import requests
from scapy.all import ARP, Ether, srp
import os 
from concurrent.futures import ThreadPoolExecutor, as_completed

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
                ip = ip.address

        if not ip or ip.startswith("127."):
            continue

        interfaces.append({
            "name":iface,
            "ip":ip
        })
        return interfaces

def check_root():
    if os.getuid() != 0:
        raise PermissionError(
            "Execute the program with SUDO!"
        )

def get_local_subnet() -> str:
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for nome_interfaccia, indirizzi in interfaces.items():
        if not stats[nome_interfaccia].isup:
            continue

        for addr in indirizzi:
            if addr.family == socket.AF_INET:
                ip = addr.address 
                netmask = addr.netmask 

                if ip.startswith("127."):
                    continue

                rete = ipaddress.IPv4Network(
                    f"{ip}/{netmask}",
                    strict=False
                )
                return str(rete)
    raise RuntimeError("Nessuna interfaccia di rete attiva trovata...")


def get_vendor(mac: str) -> str:
    try:
        oui = mac.replace(":", "").upper()[:6]
        response = requests.get(
            f"https://api.macvendors.com/{oui}",
            timeout=3
        )
        if response.status_code == 200:
            return response.text.strip()
        return "Unknown"
    except requests.RequestException:
        return "Unknown"


def scan_network(subnet: str) -> list[dict]:
    pacchetto = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    risposte, _ = srp(pacchetto, timeout=2, verbose=False)

    hosts = []

    for _, risposta in risposte:
        ip = risposta[ARP].psrc
        mac = risposta[Ether].src
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = ip

        hosts.append(
            {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": "...",
            }
        )

    def lookup(host):
        host["vendor"] = get_vendor(host["mac"])
        return host 
    
    with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(lookup,hosts))

    return results
