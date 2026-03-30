from scanner import scan_network, get_local_subnet, check_root

check_root()

subnet = get_local_subnet()

print(f"Scansione di {subnet}...\n")
hosts = scan_network(subnet)

for d in hosts:
    print(f"IP: {d['ip']}")
    print(f"MAC: {d['mac']}")
    print(f"Hostname: {d['hostname']}")
    print(f"Vendor: {d['vendor']}")
    print('-' * 30)

print(f"\nTotale hosts trovati: {len(hosts)}")

