import argparse
import csv
import json
import os
import sys

__version__ = "0.2.0"

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))


def _check_root():
    if os.getuid() != 0:
        print("error: root privileges required (run with sudo)", file=sys.stderr)
        sys.exit(1)


def _output_json(hosts: list, outfile=None):
    data = json.dumps(hosts, indent=2)
    if outfile:
        with open(outfile, "w") as f:
            f.write(data)
    else:
        print(data)


def _output_csv(hosts: list, outfile=None):
    fields = ["ip", "mac", "hostname", "vendor", "role", "os_hint", "open_ports", "ttl"]
    rows = []
    for h in hosts:
        rows.append(
            {
                "ip": h.get("ip", ""),
                "mac": h.get("mac", ""),
                "hostname": h.get("hostname", ""),
                "vendor": h.get("vendor", ""),
                "role": h.get("role", ""),
                "os_hint": h.get("os_hint", ""),
                "open_ports": " ".join(str(p) for p in h.get("open_ports", [])),
                "ttl": h.get("ttl", ""),
            }
        )
    if outfile:
        with open(outfile, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _output_table(hosts: list):
    if not hosts:
        print("no hosts found.")
        return
    col_ip = max(len(h.get("ip", "")) for h in hosts)
    col_mac = max(len(h.get("mac", "")) for h in hosts)
    col_hn = max(len(h.get("hostname", "")) for h in hosts)
    col_v = max(len(h.get("vendor", "")) for h in hosts)
    col_r = max(len(h.get("role", "")) for h in hosts)

    col_ip = max(col_ip, 15)
    col_mac = max(col_mac, 17)
    col_hn = max(col_hn, 20)
    col_v = max(col_v, 20)
    col_r = max(col_r, 10)

    header = (
        f"{'IP':<{col_ip}}  {'MAC':<{col_mac}}  "
        f"{'HOSTNAME':<{col_hn}}  {'VENDOR':<{col_v}}  {'ROLE':<{col_r}}"
    )
    print(header)
    print("-" * len(header))
    for h in hosts:
        print(
            f"{h.get('ip', ''):<{col_ip}}  {h.get('mac', ''):<{col_mac}}  "
            f"{h.get('hostname', ''):<{col_hn}}  {h.get('vendor', ''):<{col_v}}  "
            f"{h.get('role', ''):<{col_r}}"
        )


def cmd_scan(args):
    _check_root()
    from core.scanner import get_local_subnet, scan_network

    subnet = args.target
    if not subnet:
        try:
            subnet = get_local_subnet()
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)

    if not args.quiet:
        print(f"scanning {subnet}...", file=sys.stderr)

    hosts = scan_network(subnet)

    fmt = args.output or "table"
    outfile = args.file

    if fmt == "json":
        _output_json(hosts, outfile)
    elif fmt == "csv":
        _output_csv(hosts, outfile)
    else:
        _output_table(hosts)
        if outfile:
            _output_json(hosts, outfile)

    if not args.quiet:
        print(f"\n{len(hosts)} host(s) found.", file=sys.stderr)


def cmd_gui(_args):
    _check_root()
    import os

    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QApplication

    from ui.app import LogoIniziale, MainWindow

    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
        "--no-sandbox --disable-gpu --disable-software-rasterizer"
    )
    os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"

    app = QApplication(sys.argv)
    logo = LogoIniziale()
    logo.show()
    app.processEvents()
    window = MainWindow()
    QTimer.singleShot(2500, lambda: (logo.finish(window), window.show()))
    sys.exit(app.exec())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="l0p4map",
        description="L0p4Map — network monitoring & visualization tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  sudo l0p4map                          launch GUI\n"
            "  sudo l0p4map scan                     scan local subnet, table output\n"
            "  sudo l0p4map scan -t 192.168.1.0/24   scan specific subnet\n"
            "  sudo l0p4map scan -o json             JSON output\n"
            "  sudo l0p4map scan -o csv -f out.csv   save CSV to file\n"
        ),
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"l0p4map {__version__}",
    )

    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="scan network and print results")
    scan_p.add_argument(
        "-t",
        "--target",
        metavar="SUBNET",
        default=None,
        help="target subnet or IP (default: auto-detect local subnet)",
    )
    scan_p.add_argument(
        "-o",
        "--output",
        choices=["table", "json", "csv"],
        default="table",
        help="output format (default: table)",
    )
    scan_p.add_argument(
        "-f",
        "--file",
        metavar="PATH",
        default=None,
        help="write output to file instead of stdout",
    )
    scan_p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress progress messages",
    )

    sub.add_parser("gui", help="launch the GUI (default when no command given)")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "gui" or args.command is None:
        cmd_gui(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
