import csv as _csv
import ipaddress
import os
import re
import socket
import struct
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil
from scapy.all import ARP, ICMP, TCP, UDP, Ether, conf, sniff, sr1, srp
from scapy.all import IP as ScapyIP

_vendor_cache: dict[str, str] = {}
_oui_db: dict[str, str] = {}

TOPOLOGY_PROBE_PORTS = [80, 443, 22, 23, 53, 8080, 8443, 179, 161, 8291, 2601, 4786]

NETWORK_DEVICE_VENDORS = [
    "cisco",
    "mikrotik",
    "ubiquiti",
    "juniper",
    "fortinet",
    "palo alto",
    "aruba",
    "ruckus",
    "meraki",
    "extreme",
    "brocade",
    "h3c",
    "huawei",
    "zyxel",
    "dlink",
    "tp-link",
    "netgear",
    "linksys",
    "tenda",
    "openwrt",
    "dd-wrt",
    "edgecore",
    "cambium",
    "aerohive",
]

PC_VENDORS = [
    "intel",
    "dell",
    "lenovo",
    "hp",
    "hewlett",
    "acer",
    "gigabyte",
    "msi",
    "asrock",
    "asus",
    "supermicro",
    "fujitsu",
]

MOBILE_VENDORS = [
    "samsung",
    "xiaomi",
    "oneplus",
    "oppo",
    "realme",
    "motorola",
    "lg electronics",
    "sony mobile",
    "zte",
]


def capture_traffic(iface: str, duration: int = 15) -> list[dict]:
    connections = defaultdict(
        lambda: {"packets": 0, "bytes": 0, "proto": "OTHER", "port": "-"}
    )

    def process(pkt):
        if ScapyIP not in pkt:
            return
        src = pkt[ScapyIP].src
        dst = pkt[ScapyIP].dst
        size = len(pkt)
        proto = "OTHER"
        port = "-"

        if TCP in pkt:
            proto = "TCP"
            port = str(pkt[TCP].dport)
        elif UDP in pkt:
            proto = "UDP"
            port = str(pkt[UDP].dport)

        key = tuple(sorted([src, dst]))
        connections[key]["packets"] += 1
        connections[key]["bytes"] += size
        connections[key]["proto"] = proto
        connections[key]["port"] = port

    sniff(iface=iface, prn=process, timeout=duration, store=False, filter="ip")

    edges = []
    for (src, dst), data in connections.items():
        edges.append(
            {
                "src": src,
                "dst": dst,
                "packets": data["packets"],
                "bytes": data["bytes"],
                "proto": data["proto"],
                "port": data["port"],
                "weight": min(data["packets"] / 10, 10),
            }
        )

    return sorted(edges, key=lambda e: e["packets"], reverse=True)


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


def _get_interfaces_from_ip_addr() -> dict[str, str]:
    result = {}
    try:
        out = subprocess.check_output(
            ["ip", "addr", "show"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        current_iface = None
        for line in out.splitlines():
            iface_match = re.match(r"^\d+:\s+(\S+?)(?:@\S+)?:\s+<([^>]*)>", line)
            if iface_match:
                current_iface = iface_match.group(1)
                flags = iface_match.group(2).split(",")
                if "UP" not in flags:
                    current_iface = None
                elif current_iface not in result:
                    result[current_iface] = ""
                continue
            if current_iface:
                addr_match = re.match(r"^\s+inet\s+(\d+\.\d+\.\d+\.\d+)/\d+", line)
                if addr_match:
                    ip = addr_match.group(1)
                    if not ip.startswith("127."):
                        result[current_iface] = ip
    except Exception:
        pass
    return result


def get_network_interfaces():
    interfaces = []
    seen: set[str] = set()
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface, addr_list in addrs.items():
        if iface == "lo" or iface not in stats or not stats[iface].isup:
            continue
        ip = ""
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ip = addr.address
        if ip.startswith("127."):
            continue
        interfaces.append({"name": iface, "ip": ip})
        seen.add(iface)

    fallback = _get_interfaces_from_ip_addr()
    for iface, ip in fallback.items():
        if iface not in seen and iface != "lo":
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
                return str(
                    ipaddress.IPv4Network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )
                )
        raise RuntimeError(f"No IPv4 address on '{iface_name}'.")
    for nome, indirizzi in interfaces.items():
        if not stats[nome].isup:
            continue
        for addr in indirizzi:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if ip.startswith("127."):
                    continue
                return str(ipaddress.IPv4Network(f"{ip}/{addr.netmask}", strict=False))
    raise RuntimeError("No active interface found.")


def get_default_gateway() -> str | None:
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) < 3:
                    continue
                if fields[1] == "00000000":
                    gw_hex = fields[2]
                    gw_int = int(gw_hex, 16)
                    gw = socket.inet_ntoa(struct.pack("<I", gw_int))
                    if gw and not gw.startswith("0."):
                        return gw
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for token in out.split():
            if token not in ("default", "via", "dev", "proto", "metric", "src"):
                try:
                    ipaddress.ip_address(token)
                    return token
                except ValueError:
                    pass
    except Exception:
        pass
    return None


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
            b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            b"\x00\x00!\x00\x01"
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


def _probe_ttl(ip: str) -> int | None:
    try:
        pkt = ScapyIP(dst=ip, ttl=64) / ICMP()
        reply = sr1(pkt, timeout=1, verbose=False)
        if reply and ICMP in reply:
            return reply[ScapyIP].ttl
    except Exception:
        pass
    return None


def _ttl_to_os_hint(ttl: int | None) -> str:
    if ttl is None:
        return "unknown"
    if ttl <= 64:
        return "linux/macos"
    if ttl <= 128:
        return "windows"
    return "network_device"


def _probe_open_ports(ip: str, ports: list[int], timeout: float = 0.5) -> list[int]:
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
    return open_ports


def _infer_role(
    ip: str,
    vendor: str,
    hostname: str,
    ttl: int | None,
    open_ports: list[int],
    is_gateway: bool,
) -> str:
    v = vendor.lower()
    h = hostname.lower()
    os_hint = _ttl_to_os_hint(ttl)

    if is_gateway:
        return "gateway"

    if h in ("router", "gateway", "_gateway", "default-gateway"):
        return "gateway"

    if any(
        k in v
        for k in [
            "cisco",
            "mikrotik",
            "ubiquiti",
            "juniper",
            "fortinet",
            "edgecore",
            "brocade",
            "h3c",
        ]
    ):
        if any(p in open_ports for p in [22, 23, 179, 8291, 2601, 4786]):
            return "router"
        return "router"

    if any(
        k in v
        for k in [
            "tp-link",
            "netgear",
            "dlink",
            "linksys",
            "tenda",
            "zyxel",
            "aruba",
            "ruckus",
            "meraki",
            "cambium",
            "aerohive",
            "ubiquiti",
        ]
    ):
        if any(p in open_ports for p in [80, 443, 8080, 8443]):
            return "ap"
        return "ap"

    if any(
        k in h
        for k in [
            "router",
            "gw",
            "gateway",
            "firewall",
            "pfsense",
            "opnsense",
            "vyos",
            "mikrotik",
        ]
    ):
        return "router"

    if any(
        k in h
        for k in [
            "ap",
            "wifi",
            "wlan",
            "wireless",
            "access-point",
            "access_point",
            "hotspot",
            "ssid",
        ]
    ):
        return "ap"

    if any(k in h for k in ["switch", "sw-", "sw_", "core-sw", "dist-sw"]):
        return "switch"

    if any(k in v for k in ["raspberry"]) or "raspberry" in h:
        return "raspberry"

    if any(k in v for k in ["vmware", "virtualbox", "proxmox", "parallels"]):
        return "vm"

    if any(k in v for k in ["apple"]) or any(
        k in h for k in ["iphone", "ipad", "macbook", "imac", "apple"]
    ):
        return "apple"

    if any(
        k in v
        for k in [
            "samsung",
            "xiaomi",
            "oneplus",
            "oppo",
            "realme",
            "motorola",
            "lg electronics",
            "sony mobile",
            "zte",
        ]
    ):
        return "mobile"
    if any(k in h for k in ["android", "iphone", "phone", "mobile"]):
        return "mobile"

    if os_hint == "network_device":
        if any(p in open_ports for p in [80, 443, 8080]):
            return "ap"
        return "router"

    if any(k in v for k in PC_VENDORS):
        return "pc"
    if any(
        k in h
        for k in [
            "desktop",
            "pc-",
            "-pc",
            "workstation",
            "laptop",
            "linux",
            "windows",
            "ubuntu",
            "debian",
            "fedora",
        ]
    ):
        return "pc"

    if os_hint == "linux/macos" and 22 in open_ports:
        return "pc"

    if os_hint == "windows" and any(p in open_ports for p in [135, 139, 445]):
        return "pc"

    return "unknown"


def _probe_snmp_sysdescr(ip: str) -> str | None:
    try:
        community = b"public"
        oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
        request = (
            b"\x30\x29"
            b"\x02\x01\x00"
            b"\x04" + bytes([len(community)]) + community + b"\xa0\x1c"
            b"\x02\x04\x00\x00\x00\x01"
            b"\x02\x01\x00"
            b"\x02\x01\x00"
            b"\x30\x0e"
            b"\x30\x0c"
            b"\x06\x08" + oid + b"\x05\x00"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(request, (ip, 161))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if data and len(data) > 30:
            payload = data[30:]
            try:
                return payload.decode("ascii", errors="ignore").strip()
            except Exception:
                pass
    except Exception:
        pass
    return None


def _enrich_host(host: dict, known_gateway_ip: str | None) -> dict:
    ip = host["ip"]
    host["hostname"] = resolve_hostname(ip)
    host["vendor"] = get_vendor(host["mac"])

    ttl = _probe_ttl(ip)
    host["ttl"] = ttl
    host["os_hint"] = _ttl_to_os_hint(ttl)

    open_ports = _probe_open_ports(ip, TOPOLOGY_PROBE_PORTS, timeout=0.4)
    host["open_ports"] = open_ports
    host["embedded_device"] = fingerprint_embedded_device(ip, open_ports) if open_ports else ""

    snmp_desc = None
    if 161 in open_ports or ttl is None or (ttl is not None and ttl > 128):
        snmp_desc = _probe_snmp_sysdescr(ip)
    host["snmp_desc"] = snmp_desc or ""

    vendor_for_role = host["vendor"]
    if snmp_desc:
        vendor_for_role = snmp_desc + " " + vendor_for_role

    is_gw = ip == known_gateway_ip
    host["role"] = _infer_role(
        ip,
        vendor_for_role,
        host["hostname"],
        ttl,
        open_ports,
        is_gw,
    )

    return host


def scan_network(subnet: str) -> list[dict]:
    conf.verb = 0

    known_gateway = get_default_gateway()

    pacchetto = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    risposte, _ = srp(pacchetto, timeout=2, retry=2, inter=0.01, verbose=False)

    seen_macs: dict[str, str] = {}
    for _, risposta in risposte:
        mac = risposta[Ether].src
        ip = risposta[ARP].psrc
        if mac not in seen_macs:
            seen_macs[mac] = ip

    if known_gateway and known_gateway not in seen_macs.values():
        gw_mac = _arp_resolve_mac(known_gateway, subnet)
        if gw_mac:
            seen_macs[gw_mac] = known_gateway

    hosts = []
    for mac, ip in seen_macs.items():
        hosts.append(
            {
                "ip": ip,
                "mac": mac,
                "hostname": ip,
                "vendor": "...",
                "ttl": None,
                "os_hint": "unknown",
                "open_ports": [],
                "role": "unknown",
                "snmp_desc": "",
            }
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {
            executor.submit(_enrich_host, host, known_gateway): host for host in hosts
        }
        results = []
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                results.append(futures[future])

    results.sort(key=lambda h: [int(x) for x in h["ip"].split(".")])
    return results


def _arp_resolve_mac(ip: str, subnet: str) -> str | None:
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=1, retry=1, verbose=False)
        for _, reply in ans:
            return reply[Ether].src
    except Exception:
        pass


EMBEDDED_DEVICE_SIGNATURES = {
    "hp ilo": ["integrated lights-out", "ilo standard", "hp ilo"],
    "infoprint": ["infoprint", "ricoh infoprint"],
    "lantronix xport": ["xport", "lantronix"],
    "sato printer": ["sato", "nicelabel sato"],
    "zebra printer": ["zebra technologies", "zebra printer", "zpl"],
}


def _grab_http_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        data = b""
        while len(data) < 4096:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        return data.decode("latin-1", errors="ignore")
    except Exception:
        return ""


def fingerprint_embedded_device(ip: str, open_ports: list[int]) -> str:
    for port in (p for p in (80, 443, 8080) if p in open_ports):
        banner = _grab_http_banner(ip, port).lower()
        if not banner:
            continue
        for device_name, signatures in EMBEDDED_DEVICE_SIGNATURES.items():
            if any(sig in banner for sig in signatures):
                return device_name
    return ""


def _local_networks() -> list[ipaddress.IPv4Network]:
    nets = []
    try:
        for _, addr_list in psutil.net_if_addrs().items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and addr.netmask:
                    try:
                        nets.append(
                            ipaddress.IPv4Network(
                                f"{addr.address}/{addr.netmask}", strict=False
                            )
                        )
                    except Exception:
                        pass
    except Exception:
        pass
    return nets


def _is_local_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _local_networks())


def parse_target_range(target: str) -> list[str]:
    target = target.strip()
    m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", target)
    if m:
        prefix, start, end = m.groups()
        start, end = int(start), int(end)
        if start > end:
            start, end = end, start
        return [f"{prefix}{i}" for i in range(start, end + 1)]
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass
    try:
        return [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
    except ValueError:
        return []


def is_target_fully_local(target: str) -> bool:
    ips = parse_target_range(target)
    if not ips:
        return False
    return all(_is_local_ip(ip) for ip in ips)


def _traceroute_hops(ip: str, max_hops: int = 15, timeout: float = 0.8) -> list[str | None]:
    hops: list[str | None] = []
    for ttl in range(1, max_hops + 1):
        pkt = ScapyIP(dst=ip, ttl=ttl) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=False)
        if reply is None:
            hops.append(None)
            continue
        hops.append(reply.src)
        if reply.src == ip:
            break
    return hops


def _last_known_hop(hops: list[str | None]) -> str | None:
    for hop in reversed(hops):
        if hop:
            return hop
    return None


def scan_range(target: str) -> list[dict]:
    conf.verb = 0
    known_gateway = get_default_gateway()
    ip_list = parse_target_range(target)

    def probe(ip: str) -> dict | None:
        if _is_local_ip(ip):
            mac = _arp_resolve_mac(ip, ip)
            if not mac:
                return None
            return {"ip": ip, "mac": mac, "router_hop": None}

        alive = sr1(ScapyIP(dst=ip) / ICMP(), timeout=1.0, verbose=False)
        if alive is None:
            return None

        hops = _traceroute_hops(ip)
        if hops and hops[-1] == ip:
            hop = _last_known_hop(hops[:-1]) or known_gateway
        else:
            hop = _last_known_hop(hops) or known_gateway
        return {"ip": ip, "mac": "", "router_hop": hop}

    raw_hosts = []
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {executor.submit(probe, ip): ip for ip in ip_list}
        for future in as_completed(futures):
            result = future.result()
            if result:
                raw_hosts.append(result)

    hosts = []
    for raw in raw_hosts:
        hosts.append(
            {
                "ip": raw["ip"],
                "mac": raw["mac"],
                "hostname": raw["ip"],
                "vendor": "..." if raw["mac"] else "",
                "ttl": None,
                "os_hint": "unknown",
                "open_ports": [],
                "role": "unknown",
                "snmp_desc": "",
                "embedded_device": "",
                "router_hop": raw["router_hop"],
            }
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {
            executor.submit(_enrich_host, host, known_gateway): host for host in hosts
        }
        results = []
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                results.append(futures[future])

    results.sort(key=lambda h: [int(x) for x in h["ip"].split(".")])
    return results
