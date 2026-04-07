import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit,
    QComboBox, QStackedWidget, QCheckBox, QLineEdit, QScrollArea,
    QFileDialog, QSplashScreen, QMenu
)

from PyQt6.QtWebEngineWidgets import QWebEngineView
import json
import re
import time
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl, QSize, QUrl as QtUrl
from PyQt6.QtGui import QFont, QColor, QIcon, QPixmap, QPainter, QAction, QDesktopServices
from PyQt6.QtSvg import QSvgRenderer
import subprocess
import os
import csv
from scapy.all import ARP, Ether, srp, sniff, IP as ScapyIP, TCP,UDP, ICMP
from collections import defaultdict
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from core.scanner import scan_network, get_local_subnet, check_root, get_network_interfaces, capture_traffic

def load_colored_svg(path, color, size=24):
    renderer = QSvgRenderer(path)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
    painter.fillRect(pixmap.rect(), QColor(color))
    painter.end()
    return QIcon(pixmap)


class LogoIniziale(QSplashScreen):
    def __init__(self):
        pixmap = QPixmap(600,350)
        pixmap.fill(QColor("#0d0d0d"))

        painter = QPainter(pixmap)
        
        logo_path = os.path.join(os.path.dirname(__file__), "assets", "screenLogo.png")
        if os.path.exists(logo_path):
            maxL = 540
            maxA = 190
            logo = QPixmap(logo_path).scaled(
                maxL,
                maxA,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            x = (600 - logo.width()) // 2
            painter.drawPixmap(x, 40, logo)

        painter.setPen(QColor("#00ff99"))
        painter.setFont(QFont("JetBrains Mono" , 28, QFont.Weight.Bold))
        painter.drawText(
            pixmap.rect().adjusted(0,210,0,0),
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
            "L0p4Map"
        )

        painter.setPen(QColor("#444444"))
        painter.setFont(QFont("JetBrains Mono", 10))
        painter.drawText(
            pixmap.rect().adjusted(0,270,0,0),
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
            "Nmap was blind. L0p4Map sees."
        )

        painter.setPen(QColor("#333333"))
        painter.setFont(QFont("JetBrains Mono", 8))
        painter.drawText(
            pixmap.rect().adjusted(0,300,0,0),
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
            "v0.1.0-beta - loading..."
        )

        painter.setPen(QColor("#00ff22"))
        painter.drawRect(0,0,599,349)
        painter.end()

        super().__init__(pixmap)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)


class ActionWorker(QThread):
    output = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, cmd: list):
        super().__init__()
        self.cmd = cmd

    def run(self):
        process = subprocess.Popen(
            self.cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        for riga in process.stdout:
            self.output.emit(riga.rstrip())
        process.wait()
        self.finished.emit()


class ScanWorker(QThread):
    finished = pyqtSignal(list)

    def __init__(self, subnet):
        super().__init__()
        self.subnet = subnet

    def run(self):
        hosts = scan_network(self.subnet)
        self.finished.emit(hosts)


class TrafficWorker(QThread):
    packet_captured = pyqtSignal(dict)
    finished = pyqtSignal()

    def __init__(self, iface: str):
        super().__init__()
        self.iface = iface
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        def process(pkt):
            if not self._running:
                return
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
            elif ICMP in pkt:
                proto = "ICMP"

            self.packet_captured.emit({
                "src": src,
                "dst": dst,
                "proto": proto,
                "port": port,
                "size": size
            })

        sniff(
            iface=self.iface,
            prn=process,
            store=False,
            filter="ip",
            stop_filter=lambda _: not self._running
        )
        self.finished.emit()


CVSS_MIN = 4.0
MAX_CVES_PER_PORT = 5
GENERIC_SERVICES = {"tcpwrapped", "unknown", "filtered", ""}
HIGH_RISK_PORTS  = {21,23,25,110,135,139,445,512,513,514,3389,5900,6379,27017}
MEDIUM_RISK_PORTS = {22,80,8080,3306,5432,1433,2375,2376,4444}

def cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0: return "CRITICAL"
    if cvss >= 7.0: return "HIGH"
    if cvss >= 4.0: return "MEDIUM"
    return "LOW"   


class AttackSurfaceWorker(QThread):
    finished = pyqtSignal(dict)
    status_update = pyqtSignal(str)
    port_found = pyqtSignal(dict)

    def __init__(self, target: str):
        super().__init__()
        self.target = target

    def run(self):
        import tempfile, xml.etree.ElementTree as ET

        tmp = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
        tmp_path = tmp.name
        tmp.close()

        cmd = [
            "nmap", "-sV", "-O", "-sC",
            "--script", "vuln,vulners",
            "--open", "-Pn", "-T4",
            "-oX", tmp_path,
            self.target
        ]

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        seen_ports = set()

        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            if "Scanning" in line or "scan report" in line:
                self.status_update.emit(f"// {line.lower()}")
            elif "OS details" in line or "Running:" in line:
                self.status_update.emit(f"// {line.lower()}")
            elif "/tcp" in line or "/udp" in line:
                self.status_update.emit(f"// port found: {line}")
                match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
                if match:
                    portid = match.group(1)
                    if portid in seen_ports:
                        continue
                    seen_ports.add(portid)
                    proto = match.group(2)
                    svc = match.group(3)
                    version = match.group(4).strip()
                    portnum = int(portid)
                    if portnum in {21,23,25,110,135,139,445,512,513,514,3389,5900,6379,27017}:
                        risk = "HIGH"
                    elif portnum in {22,80,8080,3306,5432,1433,2375,2376,4444}:
                        risk = "MEDIUM"
                    else:
                        risk = "LOW"
                    self.port_found.emit({
                        "port": portid, "protocol": proto,
                        "service": svc, "version": version or "-", "risk": risk,
                    })

        process.wait()
        self.status_update.emit("// parsing vulnerabilities...")

        result = self._parse(tmp_path)
        os.unlink(tmp_path)

        self.status_update.emit("// scan complete")
        self.finished.emit(result)

    def _parse(self, xml_path: str) -> dict:
        import xml.etree.ElementTree as ET
        from collections import defaultdict

        result = {
            "target": self.target,
            "os": "Unknown",
            "ports": [],
            "cves": [],
        }

        try:
            tree = ET.parse(xml_path)  
            root = tree.getroot()
        except (ET.ParseError, FileNotFoundError):
            return result

        host = root.find("host")
        if host is None:
            return result

        cpe_list = [cpe.text or "" for cpe in host.findall(".//cpe")]
        is_windows = any("windows" in c for c in cpe_list)
        is_linux   = any("linux"   in c for c in cpe_list)
        is_macos   = any("mac_os"  in c or "macos" in c for c in cpe_list)

        osmatch = host.find(".//osmatch")
        if osmatch is not None:
            os_name  = osmatch.get("name", "")
            accuracy = osmatch.get("accuracy", "?")
            result["os"] = f"{os_name} ({accuracy}%)"
            if not any([is_windows, is_linux, is_macos]):
                osL = os_name.lower()
                is_windows = "windows" in osL
                is_linux   = any(k in osL for k in ["linux","ubuntu","debian"])
                is_macos   = any(k in osL for k in ["mac os","macos","darwin"])

        port_cve_count = defaultdict(int)

        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            portid   = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")
            service  = port.find("service")

            svc_name    = service.get("name",    "-") if service is not None else "-"
            svc_product = service.get("product", "") if service is not None else ""
            svc_version = service.get("version", "") if service is not None else ""
            svc_full    = f"{svc_product} {svc_version}".strip() or "-"
            svc_ostype  = service.get("ostype",  "").lower() if service is not None else ""

            portnum = int(portid)
            if portnum in HIGH_RISK_PORTS:
                risk = "HIGH"
            elif portnum in MEDIUM_RISK_PORTS:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            result["ports"].append({
                "port":     portid,
                "protocol": protocol,
                "service":  svc_name,
                "version":  svc_full,
                "risk":     risk,
            })

            for script in port.findall("script"):
                scriptID = script.get("id", "")
                output   = script.get("output", "")

                if not any(x in scriptID for x in ["vulners", "vuln", "exploit"]):
                    continue

                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    match = re.match(r"(CVE-\d{4}-\d+)\s+(\d+\.\d+)\s+https?://", line)
                    if not match:
                        continue

                    cve_id = match.group(1)
                    cvss   = float(match.group(2))

                    if cvss < CVSS_MIN:
                        continue

                    if svc_name.lower() in GENERIC_SERVICES:
                        continue

                    if not svc_product:
                        continue

                    if any(c["id"] == cve_id for c in result["cves"]):
                        continue

                    if port_cve_count[portid] >= MAX_CVES_PER_PORT:
                        continue

                    windows_only = {"netlogon", "msrpc", "microsoft-ds", "ms-wbt-server"}
                    if svc_name.lower() in windows_only and not is_windows:
                        continue

                    if svc_ostype:
                        if "windows" in svc_ostype and not is_windows:
                            continue
                        if "linux" in svc_ostype and not is_linux:
                            continue

                    port_cve_count[portid] += 1
                    result["cves"].append({
                        "id":      cve_id,
                        "cvss":    cvss,
                        "port":    portid,
                        "service": svc_name,
                        "detail":  f"{svc_name} {svc_full} — {cve_id}",
                    })

        result["cves"].sort(key=lambda c: c["cvss"], reverse=True)

        for port_entry in result["ports"]:
            port_cves = [c for c in result["cves"] if c["port"] == port_entry["port"]]
            if not port_cves:
                continue
            max_cvss = max(c["cvss"] for c in port_cves)
            port_entry["risk"] = cvss_to_severity(max_cvss)

        return result


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("L0p4Map")
        self.setMinimumSize(1200, 700)

        icon_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
        self.setWindowIcon(QIcon(icon_path))

        self._apply_theme()
        self._build_ui()

        self.live_timer = QTimer()
        self.live_timer.timeout.connect(self._live_scan)

    def _apply_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #0d0d0d;
                color: #e0e0e0;
                font-family: 'JetBrains Mono', 'Fira Code', monospace;
                font-size: 13px;
            }
            QPushButton {
                background-color: #1a1a2e;
                color: #00ff99;
                border: 1px solid #00ff99;
                padding: 6px 18px;
                font-weight: bold;
                letter-spacing: 1px;
            }
            QPushButton:hover {
                background-color: #00ff99;
                color: #0d0d0d;
            }
            QPushButton:disabled {
                color: #333;
                border-color: #333;
            }
            QTableWidget {
                background-color: #111111;
                gridline-color: #1e1e1e;
                border: none;
            }
            QTableWidget::item:selected {
                background-color: #00ff9922;
                color: #00ff99;
            }
            QHeaderView::section {
                background-color: #0d0d0d;
                color: #00ff99;
                border: none;
                border-bottom: 1px solid #00ff99;
                padding: 4px;
                font-weight: bold;
                letter-spacing: 1px;
            }
            QLabel#subnet_label {
                color: #888888;
                font-size: 12px;
            }
            QLabel#title_label {
                color: #00ff99;
                font-size: 24px;
                font-weight: bold;
                letter-spacing: 4px;
            }
        """)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        root_layout = QVBoxLayout(central)
        root_layout.setSpacing(0)
        root_layout.setContentsMargins(0, 0, 0, 0)

        root_layout.addWidget(self._build_toolbar())

        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setSpacing(0)
        body_layout.setContentsMargins(0, 0, 0, 0)

        body_layout.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_home_page())   
        self.stack.addWidget(self._build_scan_page())   
        self.stack.addWidget(self._build_graph_page())
        self.stack.addWidget(self._build_attackSurface_page())
        self.stack.addWidget(self._build_trafficAnalyzer_page())
        body_layout.addWidget(self.stack, stretch=1)

        root_layout.addWidget(body, stretch=1)

        self.statusBar().showMessage("Ready.")
        self.statusBar().setStyleSheet("color: #555; font-size: 11px;")

    def _build_sidebar(self):
        sidebar = QWidget()
        sidebar.setFixedWidth(56)
        sidebar.setStyleSheet("""
            QWidget {
                background-color: #080808;
                border-right: 1px solid #1a1a1a;
            }
        """)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(4, 8, 4, 8)
        layout.setSpacing(4)

        assets = os.path.join(os.path.dirname(__file__), "../img", "icons")

        def make_btn(icon_file, tooltip):
            icon_path = os.path.join(assets, icon_file)
            btn = QPushButton()
            btn.setIcon(load_colored_svg(icon_path, "#666666", size=22))
            btn.setIconSize(QSize(20, 20))
            btn.setToolTip(tooltip)
            btn.setFixedSize(48, 48)
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    border: none;
                    border-radius: 0px;
                }
                QPushButton:hover {
                    background-color: #111111;
                }
            """)
            return btn, icon_path

        btn_home,  path_home  = make_btn("home.svg",     "Home")
        btn_scan,  path_scan  = make_btn("eye.svg", "Port Scan")
        btn_graph, path_graph = make_btn("network2.svg",    "Network Graph")
        btn_attack, path_attack = make_btn("attack.svg", "Attack Surface")
        btn_traffic, path_traffic = make_btn("traffic.svg", "Traffic Analyzer")

        self.nav_btns = [
            (btn_home,  path_home),
            (btn_scan,  path_scan),
            (btn_graph, path_graph),
            (btn_attack, path_attack),
            (btn_traffic, path_traffic)
        ]

        def navigate(index):
            self.stack.setCurrentIndex(index)
            self._set_active_nav(index)

        btn_home.clicked.connect(lambda: navigate(0))
        btn_scan.clicked.connect(lambda: navigate(1))
        btn_graph.clicked.connect(lambda: navigate(2))
        btn_traffic.clicked.connect(lambda: navigate(4))
        btn_attack.clicked.connect(lambda: navigate(3))

        for btn, path in self.nav_btns:
            layout.addWidget(btn)

        self._set_active_nav(0)

        layout.addStretch()
        return sidebar

    def _set_active_nav(self, index):
        for i, (btn, path) in enumerate(self.nav_btns):
            color = "#00ff99" if i == index else "#666666"
            btn.setIcon(load_colored_svg(path, color))

    def _build_toolbar(self):
        toolbar = QWidget()
        toolbar.setFixedHeight(56)
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(16, 0, 16, 0)

        title = QLabel("L0p4Map")
        title.setObjectName("title_label")

        self.subnet_label = QLabel("subnet detection...")
        self.subnet_label.setObjectName("subnet_label")

        self.iface_selector = QComboBox()
        self.iface_selector.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.iface_selector.setStyleSheet("""
                QComboBox {
                    background-color: #111111;
                    color: #aaaaaa;
                    border: 1px solid #222222;
                    padding: 4px 10px;
                    font-size: 11px;                          
                }
                QComboBox:hover {
                    border-color: #00f999;
                    color: #00ff99;                          
                }
                QComboBox QAbstractItemView {
                    background-color: #111111;
                    color: #aaaaaa;
                    selection-background-color: #00ff99;
                    selection-color: #00ff99;
                    border: 1px solid #1a1a1a;                         
                }
        """)
        
        self._load_interfaces()
        self.iface_selector.currentIndexChanged.connect(self._on_iface_changed)

        self.scan_button = QPushButton("[ SCAN ]")
        self.scan_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.scan_button.clicked.connect(self._start_scan)

        layout.addWidget(title)
        layout.addSpacing(16)
        layout.addWidget(self.subnet_label)
        layout.addSpacing(12)
        layout.addWidget(self.iface_selector)
        layout.addStretch()
        layout.addWidget(self.scan_button)

        return toolbar
    
    def _load_interfaces(self):
        interfaces = get_network_interfaces()
        self.interfaces = interfaces

        self.iface_selector.blockSignals(True)
        self.iface_selector.clear()

        for iface in interfaces:
            self.iface_selector.addItem(f"{iface['name']} {iface['ip']}", userData=iface)

        self.iface_selector.blockSignals(False)

    def _on_iface_changed(self,index):
        iface = self.iface_selector.itemData(index)
        if iface:
            self.subnet_label.setText(f"subnet: {iface['ip']}")

    def _build_home_page(self):
        
        home = QWidget()
        layout = QVBoxLayout(home)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_table())
        splitter.addWidget(self._build_detail_panel())
        splitter.setSizes([800, 400])
        splitter.setStyleSheet("QSplitter::handle { background-color: #1a1a1a; }")
        layout.addWidget(splitter, stretch=1)

        return home

    def _build_scan_page(self):
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setSpacing(0)
        layout.setContentsMargins(0,0,0,0)

        layout.addWidget(self._build_scan_options())
        layout.addWidget(self._build_scan_output(), stretch=1)

        self.scan_button.clicked.connect(
            lambda: (self.stack.setCurrentIndex(0), self._set_active_nav(0)) 
        )

        return page
    
    def _build_scan_options(self):
        scroll = QScrollArea()
        scroll.setFixedWidth(260)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(6)

        target_label = QLabel("TARGET")
        target_label.setStyleSheet("""
                color: #00ff99;
                font-size: 11px;
                letter-spacing: 2px;
        """)
        layout.addWidget(target_label)

        self.scan_target = QLineEdit()
        self.scan_target.setPlaceholderText("192.168.1.1")
        self.scan_target.setStyleSheet("""
            QLineEdit {
                background-color: #111111;
                color: #e0e0e0;
                border: 1px solid #1a1a1a;
                padding: 6px;
                font-family: 'JetBrains Mono', monospace;                          
            }
            QLineEdit:focus {
                border: 1px solid #00ff99;                           
            }
        """)
        layout.addWidget(self.scan_target)
        layout.setSpacing(8)

        self._scan_checks = {}
        sections = {
        "SCAN TYPE": [
            ("-F", "Fast scan"),
            ("-sS", "SYN scan"),
            ("-sT", "TCP connect"),
            ("-sU", "UDP scan"),
            ("-sN", "NULL scan"),
            ("-sX", "Xmas scan"),
            ("-p-", "All ports"),
            ("-A", "Aggressive"),
            ("-Pn", "No ping"),
        ],
        "DETECTION": [
            ("-sV", "Service version"),
            ("-O", "OS detection"),
            ("--osscan-guess", "OS guess"),
        ],
        "SCRIPTS": [
            ("-sC", "Default scripts"),
            ("--script banner", "Banner grab"),
            ("--script safe", "Safe scripts"),
            ("--script vuln", "Vuln scan"),
            ("--script vulners", "Vulners CVE"),
            ("--script malware", "Malware detect"),
            ("--script discovery", "Discovery"),
            ("--script http-enum", "HTTP enum"),
            ("--script http-headers", "HTTP headers"),
            ("--script http-methods", "HTTP methods"),
            ("--script ssl-cert", "SSL cert"),
            ("--script ssl-enum-ciphers", "SSL ciphers"),
            ("--script smb-enum-shares", "SMB shares"),
            ("--script smb-enum-users", "SMB users"),
            ("--script dns-brute", "DNS brute"),
            ("--script ftp-anon", "FTP anon"),
            ("--script ssh-auth-methods", "SSH auth"),
        ],
        "OUTPUT": [
            ("--open", "Show open only"),
            ("-v", "Verbose"),
            ("--reason", "Show reason"),
        ],
        "TIMING": [
            ("-T1", "Sneaky (slow)"),
            ("-T2", "Polite"),
            ("-T3", "Normal"),
            ("-T4", "Aggressive"),
            ("-T5", "Insane (fast)"),
        ],
    }

        for section_name, options in sections.items():
            sep = QWidget()
            sep.setFixedHeight(1)
            sep.setStyleSheet("background-color: #1a1a1a;")
            layout.addWidget(sep)
            layout.addSpacing(4)

            sec_label = QLabel(section_name)
            sec_label.setStyleSheet("""
                    color: #00ff99;
                    font-size: 11px;
                    letter-spacing: 2px;
            """)
            layout.addWidget(sec_label)
            layout.addSpacing(2)

            for flag, description in options:
                cb = QCheckBox(f"{description}")
                cb.setFocusPolicy(Qt.FocusPolicy.NoFocus)
                cb.setToolTip(flag)
                cb.setStyleSheet("""
                    QCheckBox {
                        color: #aaaaaa;
                        font-size: 12px;
                        spacing: 6px;
                    }
                    QCheckBox:hover {
                        color: #e0e0e0;
                    }
                    QCheckBox::indicator {
                        width: 12px;
                        height: 12px;
                        border: 1px solid #333;
                        background-color: #111;
                    }
                    QCheckBox::indicator:checked {
                        background-color: #00ff99;
                        border: 1px solid #00ff99;
                    }
            """)
                self._scan_checks[flag] = cb
                layout.addWidget(cb)
            layout.addSpacing(4)

        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #1a1a1a;")
        layout.addWidget(sep)
        layout.addSpacing(4)

        custom_label = QLabel("CUSTOM FLAGS")
        custom_label.setStyleSheet("color: #00ff99; font-size: 11px; letter-spacing: 2px;")
        layout.addWidget(custom_label)

        self.custom_flags = QLineEdit()
        self.custom_flags.setPlaceholderText("-p 80,443 --script http-title")
        self.custom_flags.setStyleSheet("""
                QLineEdit {
                    background-color: #111111;
                    color: #e0e0e0;
                    border: 1px solid #1a1a1a;
                    padding: 6px;
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 11px;                        
                }
                QLineEdit:focus {
                    border: 1px solid #00ff99;                        
                }
        """)
        layout.addWidget(self.custom_flags)
        layout.addSpacing(12)

        self.btn_run_scan = QPushButton("[ RUN SCAN ]")
        self.btn_run_scan.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_run_scan.clicked.connect(self._run_nmap_scan)
        layout.addWidget(self.btn_run_scan)

        self.btn_export_scan = QPushButton("[ EXPORT SCAN ]")
        self.btn_export_scan.setStyleSheet("QPushButton:pressed {font-size: 12px;}")
        self.btn_export_scan.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_export_scan.setDisabled(True)
        self.btn_export_scan.clicked.connect(self._export_scan)

        layout.addSpacing(6)
        layout.addWidget(self.btn_export_scan)

        layout.addStretch()
        scroll.setWidget(container)
        return scroll
    
    def _export_scan(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export L0p4Map scan",
            "scan.txt",
            "Text Files (*.txt);;All Files(*)"
        )
        if not path:
            return

        with open(path,"w") as f:
            f.write(self.scan_output.toPlainText())

    def _build_scan_output(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        self.scan_cmd_label = QLabel("// no active scan.")
        self.scan_cmd_label.setStyleSheet("""
                background-color: #080808;
                color: #444444;
                font-size: 11px;
                padding: 8px 12px;
                border-bottom: 1px solid #1a1a1a;
        """)
        layout.addWidget(self.scan_cmd_label)

        self.scan_output = QTextEdit()
        self.scan_output.setReadOnly(True)
        self.scan_output.setStyleSheet("""
                QTextEdit {
                    background-color: #0a0a0a;
                    color: #00ff99;
                    border: none;
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 12px;
                    padding: 12px;                       
                }
        """)
        self.scan_output.setPlaceholderText("// select options and run scan...")
        layout.addWidget(self.scan_output, stretch=1)
        return container

    def _run_nmap_scan(self):
        target = self.scan_target.text().strip()
        if not target:
            self.scan_output.append("// error: no target specified")
            return

        cmd = ["nmap"]
        for flag, cb in self._scan_checks.items():
            if cb.isChecked():
                cmd.extend(flag.split())

        custom = self.custom_flags.text().strip()
        if custom:
            cmd.extend(custom.split())

        cmd.append(target)

        self.scan_cmd_label.setText("// " + " ".join(cmd))
        self.scan_cmd_label.setStyleSheet("""
                background-color: #080808;
                color: #00ff99;
                font-size: 11px;
                padding: 8px 12px;
                border-bottom: 1px solid #1a1a1a;
        """)
        self.scan_output.clear()
        self.scan_output.append(f"// {''.join(cmd)}\n")

        self.btn_run_scan.setText("[ STOP ]")
        self.btn_run_scan.clicked.disconnect()
        self.btn_run_scan.clicked.connect(self._stop_nmap_scan)

        self.action_worker = ActionWorker(cmd)
        self.action_worker.output.connect(self.scan_output.append)
        self.action_worker.finished.connect(self._on_nmap_finished)
        self.action_worker.start()

    def _stop_nmap_scan(self):
        if hasattr(self, 'action_worker') and self.action_worker.isRunning():
            self.action_worker.finished.disconnect()
            self.action_worker.terminate()
        self.scan_output.append("\n// Interrupted.")
        self.btn_export_scan.setDisabled(True)
        self.btn_run_scan.setText("[ RUN SCAN ]")
        self.btn_run_scan.clicked.disconnect()
        self.btn_run_scan.clicked.connect(self._run_nmap_scan)

    def _on_nmap_finished(self):
        self.scan_output.append("\n// Done.")
        self.btn_export_scan.setDisabled(False)
        self.btn_run_scan.setText("[ RUN SCAN ]")
        self.btn_run_scan.clicked.disconnect()
        self.btn_run_scan.clicked.connect(self._run_nmap_scan)

    def _build_graph_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        header = QWidget()
        header.setFixedHeight(36)
        header.setStyleSheet("background-color: #080808; border-bottom: 1px solid #1a1a1a;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12,0,12,0)

        header_label = QLabel("// network topology graph")
        header_label.setStyleSheet("color: #444444; font-size: 11px; padding-right: 10px; padding-left: 10px; padin")
        header_layout.addWidget(header_label)
        header_layout.addSpacing(10)

        self.btn_export_graph = QComboBox()
        self.btn_export_graph.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_export_graph.addItem("EXPORT")
        self.btn_export_graph.addItem("CSV", userData="csv")
        self.btn_export_graph.addItem("PNG", userData="png")
        self.btn_export_graph.setFixedWidth(120)
        self.btn_export_graph.setStyleSheet("""
                QComboBox {
                    background-color: #111111;
                    color: #aaaaaa;
                    border: 1px solid #222222;
                    padding: 2px 8px;
                    font-size: 11px;                            
                }
                QComboBox:hover {
                    border-color: #00ff99;
                    color: #00ff99;                            
                }
                QComboBox QAbstractItemView {
                    background-color: #111111;
                    color: #aaaaaa;
                    selection-background-color: #00ff22;
                    selection-color: #00ff99;
                    border: 1px solid #1a1a1a;                            
                }
        """)
        self.btn_export_graph.currentIndexChanged.connect(self._export_graph)
        self.btn_export_graph.setDisabled(True)
        header_layout.addWidget(self.btn_export_graph)
        header_layout.addStretch()

        self.live_interval = QComboBox()
        self.live_interval.addItem("30s", userData=30)
        self.live_interval.addItem("60", userData=60)
        self.live_interval.addItem("120", userData=120)
        self.live_interval.setFixedWidth(70)
        self.live_interval.setDisabled(True)
        self.live_interval.setStyleSheet("""
            QComboBox {
                background-color: #111111;
                color: #555555;
                border: 1px solid #1a1a1a;
                padding: 2px 6px;
                font-size: 10px;
            }
            QComboBox QAbstractItemView {
                background-color: #111111;
                color: #aaaaaa;
                selection-background-color: #00ff9922;
                selection-color: #00ff99;
            }
        """)
        header_layout.addWidget(self.live_interval)
        header_layout.addSpacing(10)

        self.btn_live = QPushButton("[ LIVE ]")
        self.btn_live.setFixedWidth(80)
        self.btn_live.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_live.setCheckable(True)
        self.btn_live.clicked.connect(self._toggle_live)
        self.btn_live.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #444444;
                border: 1px solid #333333;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:checked {
                background-color: #003322;
                color: #00ff99;
                border: 1px solid #00ff99;
            }
            QPushButton:hover {
                color: #00ff99;
                border-color: #00ff99;
            }
            QPushButton:focus {
                outline: 0;
            }
        """)
        header_layout.addWidget(self.btn_live)
        layout.addWidget(header)

        # web engine view con vis.js
        self.graph_view = QWebEngineView()
        self.graph_view.setStyleSheet("background-color: #0d0d0d;")
        self.graph_ready = False

        html_path = os.path.join(
            os.path.dirname(__file__), "assets", "graph.html"
        )
        self.graph_view.load(QUrl.fromLocalFile(html_path))
        self.graph_view.loadFinished.connect(self._on_graph_loaded)
        layout.addWidget(self.graph_view, stretch=1)

        return page
    

    def _toggle_live(self):
        if self.btn_live.isChecked():
            interval = self.live_interval.currentData() * 1000
            self.live_timer.start(interval)
            self.live_interval.setDisabled(False)
            self.statusBar().showMessage(f"Live monitoring active — refresh every {self.live_interval.currentText()}")
        else:
            self.live_timer.stop()
            self.live_interval.setDisabled(True)
            self.statusBar().showMessage("Live Monitoring Stopped.")

        
    def _live_scan(self):
        if hasattr(self, 'live_worker') and self.live_worker.isRunning():
            return
        
        iface = self.iface_selector.currentData()
        subnet = get_local_subnet(iface["name"])

        self.live_worker = ScanWorker(subnet)
        self.live_worker.finished.connect(self._on_live_scan_finished)
        self.live_worker.start()

    def _on_live_scan_finished(self, hosts):
        self._update_graph(hosts)
        self.last_hosts = hosts 
        self.statusBar().showMessage(
        f"Live update — {len(hosts)} devices — {self.live_interval.currentText()} refresh")

    
    def _export_graph(self, index):
        if index == 0:
            return
    
        fmt = self.btn_export_graph.itemData(index)
        if not hasattr(self, 'last_hosts') or not self.last_hosts:
            self.statusBar().showMessage("No scan data to export.")
            self.btn_export_graph.setCurrentIndex(0)
            return

        if fmt == "csv":
            self._export_graph_csv()
            pass
        else:
            self._export_graph_png()
            pass

        self.btn_export_graph.setCurrentIndex(0)

    def _export_graph_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export csv graph",
            "graph.csv",
            "CSV Files (*.csv);;All Files (*)"
        )
        if not path:
            return

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["ip","mac","vendor","hostname"])
            writer.writeheader()
            writer.writerows(self.last_hosts)
            
        self.statusBar().showMessage(f"Graph (csv) exported in {path}")

    def _export_graph_png(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export png Graph",
            "graph.png",
            "PNG Images (*.png);;All Files(*)"
        )
        if not path:
            return
        
        pixmap = self.graph_view.grab()
        pixmap.save(path, "PNG")
        self.statusBar().showMessage(f"Graph (png) exported to {path}")

    def _on_graph_loaded(self, ok):
        self.graph_ready = True
        if hasattr(self, '_pending_graph_data'):
            self._update_graph(self._pending_graph_data)


    def _ta_send_to_scan(self, item):
        row = item.row()
        ipR = self.ta_table.item(row, 2).text()
        ip = ipR.split(" ")[0]
        self.scan_target.setText(ip)
        self.stack.setCurrentIndex(1)
        self._set_active_nav(1)

    def _export_ta_csv(self):
        if not self._ta_packets:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Traffic", "traffic.csv", "CSV Files (*.csv);;All Files (*)"
        )
        if not path:
            return
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["n","time","src","dst","proto","port","size"])
            writer.writeheader()
            for p in self._ta_packets:
                writer.writerow({k: p[k] for k in ["n","time","src","dst","proto","port","size"]})
        self.statusBar().showMessage(f"Traffic exported to {path}")

    # ancora in beta
    def _build_trafficAnalyzer_page(self):
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        left = QWidget()
        left.setFixedWidth(200)
        left.setStyleSheet("background-color: #080808; border-right: 1px solid #1a1a1a;")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(8, 8, 8, 8)
        left_layout.setSpacing(4)

        dev_label = QLabel("DEVICES")
        dev_label.setStyleSheet("color: #444; font-size: 10px; letter-spacing: 2px;")
        left_layout.addWidget(dev_label)

        self.ta_device_list = QTableWidget()
        self.ta_device_list.setColumnCount(2)
        self.ta_device_list.setHorizontalHeaderLabels(["IP", "PKTS"])
        self.ta_device_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.ta_device_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.ta_device_list.setColumnWidth(1, 50)
        self.ta_device_list.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ta_device_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ta_device_list.verticalHeader().setVisible(False)
        self.ta_device_list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.ta_device_list.itemClicked.connect(self._ta_filter_by_device)
        left_layout.addWidget(self.ta_device_list, stretch=1)

        btn_clear_filter = QPushButton("[ SHOW ALL ]")
        btn_clear_filter.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        btn_clear_filter.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #555;
                border: 1px solid #222;
                padding: 3px;
                font-size: 9px;
            }
            QPushButton:hover { color: #aaa; border-color: #555; }
        """)
        btn_clear_filter.clicked.connect(lambda: self._ta_apply_filter(""))
        left_layout.addWidget(btn_clear_filter)

        layout.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setSpacing(0)
        right_layout.setContentsMargins(0, 0, 0, 0)

        header = QWidget()
        header.setFixedHeight(36)
        header.setStyleSheet("background-color: #080808; border-bottom: 1px solid #1a1a1a;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 0, 12, 0)

        header_label = QLabel("// traffic analyzer")
        header_label.setStyleSheet("color: #444444; font-size: 11px;")
        header_layout.addWidget(header_label)
        header_layout.addStretch()

        self.btn_start_capture = QPushButton("[ START ]")
        self.btn_start_capture.setFixedWidth(80)
        self.btn_start_capture.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_start_capture.clicked.connect(self._ta_start)
        self.btn_start_capture.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #00ccff;
                border: 1px solid #00ccff;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #001a33; }
            QPushButton:disabled { color: #333; border-color: #222; }
        """)
        header_layout.addWidget(self.btn_start_capture)
        header_layout.addSpacing(6)

        self.btn_stop_capture = QPushButton("[ STOP ]")
        self.btn_stop_capture.setFixedWidth(80)
        self.btn_stop_capture.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_stop_capture.setEnabled(False)
        self.btn_stop_capture.clicked.connect(self._ta_stop)
        self.btn_stop_capture.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ff4444;
                border: 1px solid #ff444444;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #330000; border-color: #ff4444; }
            QPushButton:disabled { color: #333; border-color: #222; }
        """)
        header_layout.addWidget(self.btn_stop_capture)
        header_layout.addSpacing(6)

        self.btn_clear_capture = QPushButton("[ CLEAR ]")
        self.btn_clear_capture.setFixedWidth(80)
        self.btn_clear_capture.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_clear_capture.clicked.connect(self._ta_clear)
        self.btn_clear_capture.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #666666;
                border: 1px solid #333333;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover { color: #aaaaaa; border-color: #666666; }
        """)
        header_layout.addWidget(self.btn_clear_capture)
        header_layout.addSpacing(6)

        self.btn_ta_export = QPushButton("[ EXPORT CSV ]")
        self.btn_ta_export.setFixedWidth(120)
        self.btn_ta_export.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_ta_export.setEnabled(False)
        self.btn_ta_export.clicked.connect(self._export_ta_csv)
        self.btn_ta_export.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #00ff99;
                border: 1px solid #00ff99;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #001a0d; }
            QPushButton:disabled { color: #333; border-color: #222; }
        """)
        header_layout.addWidget(self.btn_ta_export)
        right_layout.addWidget(header)

        filter_bar = QWidget()
        filter_bar.setFixedHeight(28)
        filter_bar.setStyleSheet("background-color: #0a0a0a; border-bottom: 1px solid #111;")
        filter_layout = QHBoxLayout(filter_bar)
        filter_layout.setContentsMargins(12, 0, 12, 0)

        filter_label = QLabel("FILTER:")
        filter_label.setStyleSheet("color: #444; font-size: 10px;")
        filter_layout.addWidget(filter_label)
        filter_layout.addSpacing(8)

        self.ta_filter = QLineEdit()
        self.ta_filter.setPlaceholderText("IP, protocol, port or hostname...")
        self.ta_filter.setStyleSheet("""
            QLineEdit {
                background-color: #0d0d0d;
                color: #aaaaaa;
                border: 1px solid #1a1a1a;
                padding: 2px 8px;
                font-size: 11px;
                font-family: 'JetBrains Mono', monospace;
            }
            QLineEdit:focus { border-color: #00ff99; }
        """)
        self.ta_filter.textChanged.connect(self._ta_apply_filter)
        filter_layout.addWidget(self.ta_filter)
        right_layout.addWidget(filter_bar)

        self.ta_table = QTableWidget()
        self.ta_table.setColumnCount(7)
        self.ta_table.setHorizontalHeaderLabels([
            "#", "TIME", "SRC", "DST", "PROTO", "PORT", "SIZE"
        ])
        self.ta_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.ta_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for col, w in [(0, 50), (1, 80), (4, 60), (5, 60), (6, 60)]:
            self.ta_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.Fixed)
            self.ta_table.setColumnWidth(col, w)
        self.ta_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ta_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ta_table.verticalHeader().setVisible(False)
        self.ta_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.ta_table.itemDoubleClicked.connect(self._ta_send_to_scan)
        self.ta_table.setAlternatingRowColors(True)
        self.ta_table.setStyleSheet("""
            QTableWidget { alternate-background-color: #0f0f0f; }
        """)
        right_layout.addWidget(self.ta_table, stretch=1)

        self.ta_status = QLabel("// ready — press [ START ] to begin capture")
        self.ta_status.setStyleSheet("""
            background-color: #080808;
            color: #333333;
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #1a1a1a;
        """)
        right_layout.addWidget(self.ta_status)
        layout.addWidget(right, stretch=1)

        self._ta_packets = []
        self._ta_packet_count = 0
        self._ta_start_time = None
        self._ta_device_stats = {}

        return page
    

    def _ta_start(self):
        iface = self.iface_selector.currentData()
        if not iface:
            return

        self._ta_packets = []
        self._ta_packet_count = 0
        self._ta_start_time = None
        self._ta_device_stats = {}
        self._ta_data = []
        self.ta_table.setRowCount(0)
        self.ta_device_list.setRowCount(0)

        self.btn_start_capture.setEnabled(False)
        self.btn_stop_capture.setEnabled(True)
        self.ta_status.setText(f"// capturing on {iface['name']}...")
        self.ta_status.setStyleSheet("""
            background-color: #080808;
            color: #00ccff;
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #1a1a1a;
        """)

        self.ta_worker = TrafficWorker(iface["name"])
        self.ta_worker.packet_captured.connect(self._ta_on_packet)
        self.ta_worker.finished.connect(self._ta_on_finished)
        self.ta_worker.start()

    def _ta_stop(self):
        if hasattr(self, 'ta_worker') and self.ta_worker.isRunning():
            self.ta_worker.stop()
        self.btn_start_capture.setEnabled(True)
        self.btn_stop_capture.setEnabled(False)
        self.ta_status.setStyleSheet("""
            background-color: #080808;
            color: #333333;
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #1a1a1a;
        """)

    def _ta_clear(self):
        if hasattr(self, 'ta_worker') and self.ta_worker.isRunning():
            self.ta_worker.stop()
            self.btn_start_capture.setEnabled(True)
            self.btn_stop_capture.setEnabled(False)
        self._ta_packets = []
        self._ta_packet_count = 0
        self._ta_start_time = None
        self._ta_device_stats = {}
        self._ta_data = []
        self.ta_table.setRowCount(0)
        self.ta_device_list.setRowCount(0)
        self.btn_ta_export.setEnabled(False)
        self.ta_status.setText("// cleared — press [ START ] to begin capture")

    def _ta_on_packet(self, pkt: dict):
        if not hasattr(self, '_ta_packets'):
            return
    
        if self._ta_start_time is None:
            self._ta_start_time = time.time()
    
        elapsed = time.time() - self._ta_start_time
        self._ta_packet_count += 1
    
        src_label = self._resolve_ip_label(pkt["src"])
        dst_label = self._resolve_ip_label(pkt["dst"])
    
        packet_data = {
            "n": self._ta_packet_count,
            "time": f"{elapsed:.3f}s",
            "src": pkt["src"],
            "dst": pkt["dst"],
            "src_label": src_label,
            "dst_label": dst_label,
            "proto": pkt["proto"],
            "port": pkt["port"],
            "size": pkt["size"],
        }
    
        self._ta_packets.append(packet_data)
    
        for ip in [pkt["src"], pkt["dst"]]:
            if ip not in self._ta_device_stats:
                self._ta_device_stats[ip] = 0
            self._ta_device_stats[ip] += 1

        self._ta_add_row(packet_data)
    
        if self._ta_packet_count % 20 == 0 or self._ta_packet_count <= 5:
            self._ta_add_row(packet_data)
            self._ta_update_device_list()
            self.ta_status.setText(
                f"// {self._ta_packet_count} packets captured — {elapsed:.1f}s"
            )
            if self._ta_packet_count > 0:
                self.btn_ta_export.setEnabled(True)

    
    def _resolve_ip_label(self, ip: str) -> str:
        if hasattr(self, 'last_hosts'):
            for h in self.last_hosts:
                if h["ip"] == ip:
                    hostname = h.get("hostname", ip)
                    if hostname != ip:
                        return f"{ip} ({hostname.split('.')[0]})"
        return ip
    

    def _ta_add_row(self, pkt: dict):
        proto_colors = {
            "TCP":  "#1a1a2e",
            "UDP":  "#1a2e1a",
            "ICMP": "#2e1a1a",
            "OTHER": "#111111",
        }
        bg = QColor(proto_colors.get(pkt["proto"], "#111111"))

        row = self.ta_table.rowCount()
        self.ta_table.insertRow(row)

        items = [
            str(pkt["n"]),
            pkt["time"],
            pkt["src_label"],
            pkt["dst_label"],
            pkt["proto"],
            pkt["port"],
            f"{pkt['size']}B",
        ]

        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            item.setBackground(bg)
            if col == 4: 
                colors = {"TCP": "#4488ff", "UDP": "#44cc88", "ICMP": "#ff8844", "OTHER": "#888888"}
                item.setForeground(QColor(colors.get(pkt["proto"], "#888888")))
            self.ta_table.setItem(row, col, item)

        self.ta_table.scrollToBottom()

    def _ta_update_device_list(self):
        self.ta_device_list.setRowCount(0)
        sorted_devs = sorted(self._ta_device_stats.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_devs:
            row = self.ta_device_list.rowCount()
            self.ta_device_list.insertRow(row)
            label = self._resolve_ip_label(ip)
            self.ta_device_list.setItem(row, 0, QTableWidgetItem(label))
            count_item = QTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.ta_device_list.setItem(row, 1, count_item)

    def _ta_filter_by_device(self, item):
        row = item.row()
        ip_cell = self.ta_device_list.item(row, 0)
        if ip_cell:
            label = ip_cell.text()
            ip = label.split(" ")[0]
            self.ta_filter.setText(ip)

    def _ta_apply_filter(self, text):
        text = text.lower()
        for row in range(self.ta_table.rowCount()):
            visible = not text or any(
                text in (self.ta_table.item(row, col).text().lower() if self.ta_table.item(row, col) else "")
                for col in range(self.ta_table.columnCount())
            )
            self.ta_table.setRowHidden(row, not visible)
        visible_count = sum(
            1 for r in range(self.ta_table.rowCount())
            if not self.ta_table.isRowHidden(r)
        )
        if hasattr(self, '_ta_packet_count'):
            self.ta_status.setText(
                f"// showing {visible_count} of {self._ta_packet_count} packets"
                if text else
                f"// {self._ta_packet_count} packets captured"
            )


    def _ta_on_finished(self):
        self.btn_start_capture.setEnabled(True)
        self.btn_stop_capture.setEnabled(False)


    def _build_table(self):
        self.table = QTableWidget()
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_menu)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["IP", "MAC", "VENDOR", "HOSTNAME"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_device_selected)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        return self.table
    
    def _show_menu(self, pos):
        item = self.table.itemAt(pos)

        if item is None:
            return
        
        row = item.row()
        ip = self.table.item(row,0).text()

        menu = QMenu()

        portScan_action = QAction("Send to port scan", self)
        ta_action = QAction("Send to Traffic Analyzer", self)
        as_action = QAction("Send to Attack Surface", self)

        portScan_action.triggered.connect(lambda: (self.stack.setCurrentIndex(1), self.scan_target.setText(ip), self._set_active_nav(1)))
        ta_action.triggered.connect(lambda: (self.stack.setCurrentIndex(4), self.ta_filter.setText(ip), self._set_active_nav(4)))
        as_action.triggered.connect(lambda: (self.stack.setCurrentIndex(3), self.as_target.setText(ip), self._set_active_nav(3)))

        menu.addAction(portScan_action)
        menu.addAction(as_action)
        menu.addAction(ta_action)
        
        menu.exec(self.table.viewport().mapToGlobal(pos))


    def _build_detail_panel(self):
        self.detail_panel = QWidget()
        self.detail_panel.setStyleSheet("background-color: #0a0a0a; border-left: 1px solid #1a1a1a;")
        layout = QVBoxLayout(self.detail_panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        title = QLabel("DEVICE INFO")
        title.setStyleSheet("color: #00ff99; font-size: 11px; letter-spacing: 2px;")
        layout.addWidget(title)

        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #1a1a1a;")
        layout.addWidget(sep)
        layout.addSpacing(8)

        self.detail_ip = QLabel("IP: —")
        self.detail_mac = QLabel("MAC: —")
        self.detail_hostname= QLabel("HOSTNAME: —")
        self.detail_vendor  = QLabel("VENDOR: —")

        for label in [self.detail_ip, self.detail_mac,
                      self.detail_hostname, self.detail_vendor]:
            label.setStyleSheet("color: #cccccc; font-size: 12px;")
            label.setWordWrap(True)
            layout.addWidget(label)

        layout.addSpacing(10)

        sep2 = QWidget()
        sep2.setFixedHeight(1)
        sep2.setStyleSheet("background-color: #1a1a1a;")
        layout.addWidget(sep2)
        layout.addSpacing(8)

        actions_label = QLabel("ACTIONS")
        actions_label.setStyleSheet("color: #00ff99; font-size: 11px; letter-spacing: 2px;")
        layout.addWidget(actions_label)
        layout.addSpacing(4)

        self.btn_ping      = QPushButton("[ PING ]")
        self.btn_portscan  = QPushButton("[ PORT SCAN ]")
        self.btn_traceroute = QPushButton("[ TRACEROUTE ]")

        self.btn_ping.clicked.connect(self._run_ping)
        self.btn_traceroute.clicked.connect(self._run_traceroute)
        self.btn_portscan.clicked.connect(self._go_to_scan)

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        self.output_box.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a0a;
                color: #00ff99;
                border: 1px solid #1a1a1a;
                font-family: 'JetBrains Mono', monospace;
                font-size: 11px;
                padding: 8px;
            }
        """)
        self.output_box.setPlaceholderText("// output here")
        layout.addWidget(self.output_box, stretch=1)

        for btn in [self.btn_ping, self.btn_traceroute,self.btn_portscan]:
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            btn.setEnabled(False)
            layout.addWidget(btn)

        layout.addStretch()
        return self.detail_panel

    def _on_device_selected(self):
        selected = self.table.selectedItems()
        if not selected:
            return

        row = self.table.currentRow()
        ip       = self.table.item(row, 0).text()
        mac      = self.table.item(row, 1).text()
        vendor   = self.table.item(row, 2).text()
        hostname = self.table.item(row, 3).text()

        self.detail_ip.setText(f"IP: {ip}")
        self.detail_mac.setText(f"MAC: {mac}")
        self.detail_vendor.setText(f"VENDOR: {vendor}")
        self.detail_hostname.setText(f"HOSTNAME: {hostname}")

        for btn in [self.btn_ping, self.btn_portscan, self.btn_traceroute]:
            btn.setStyleSheet("""
                QPushButton {
                    
                    color: #00ff99;
                    border: 1px solid #00ff99;
                    padding: 6px 18px;
                    font-weight: bold;
                    letter-spacing: 1px;
                }
                QPushButton:hover {
                    font-size: 14px;
                }
                QPushButton:pressed {
                    font-size: 11px;
                }
            """)
            btn.setEnabled(True)

    def _start_scan(self):
        self.scan_button.setEnabled(False)
        self.btn_export_graph.setEnabled(False)
        self.statusBar().showMessage("Scanning...")
        self.table.setRowCount(0)

        iface = self.iface_selector.currentData()
        subnet = get_local_subnet(iface["name"])
        self.subnet_label.setText(f"subnet: {subnet}")

        self.worker = ScanWorker(subnet)
        self.worker.finished.connect(self._on_scan_finished)
        self.worker.start()

    def _populate_table(self, hosts):
        for d in hosts:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(d["ip"]))
            self.table.setItem(row, 1, QTableWidgetItem(d["mac"]))
            self.table.setItem(row, 2, QTableWidgetItem(d["vendor"]))
            self.table.setItem(row, 3, QTableWidgetItem(d["hostname"]))

    def _on_scan_finished(self, hosts):
        self._populate_table(hosts)
        self.last_hosts = hosts
        self.statusBar().showMessage(f"{len(hosts)} device found.")
        self.scan_button.setEnabled(True)
        self._update_graph(hosts)
        self.btn_export_graph.setDisabled(False)

    def _update_graph(self, hosts):
        if not hasattr(self, 'graph_view'):
            return
        if not self.graph_ready:
            self._pending_graph_data = hosts
            return
        data = json.dumps(hosts)
        data = data.replace("'", "\\'")
        self.graph_view.page().runJavaScript(f"updateGraph('{data}')")

    def _go_to_scan(self):
        self._set_active_nav(1)
        row = self.table.currentRow()
        if row < 0:
            return
        self.current_target_ip = self.table.item(row, 0).text()
        self.scan_target.setText(self.current_target_ip)
        self.stack.setCurrentIndex(1)

    def _run_ping(self):
        row = self.table.currentRow()
        if row < 0:
            return
        ip = self.table.item(row, 0).text()

        self.output_box.clear()
        self.output_box.append(f"// ping {ip}\n")

        self.action_worker = ActionWorker(["ping", "-c", "4", ip])
        self.action_worker.output.connect(self.output_box.append)
        self.action_worker.finished.connect(
            lambda: self.output_box.append("\n// done.")
        )
        self.action_worker.start()

    def _run_traceroute(self):
        row = self.table.currentRow()
        if row < 0:
            return
        ip = self.table.item(row, 0).text()

        self.output_box.clear()
        self.output_box.append(f"// traceroute {ip}\n")

        self.btn_traceroute.setText("[ STOP ]")
        self.btn_traceroute.clicked.disconnect()
        self.btn_traceroute.clicked.connect(self._stop_action)

        self.action_worker = ActionWorker(["traceroute", "-I", ip])
        self.action_worker.output.connect(self.output_box.append)
        self.action_worker.finished.connect(self._on_action_finished)
        self.action_worker.start()

    def _stop_action(self):
        if hasattr(self, 'action_worker') and self.action_worker.isRunning():
            self.action_worker.finished.disconnect()
            self.action_worker.terminate()
        self.output_box.append("\n// interrupted.")
        self.btn_traceroute.setText("[ TRACEROUTE ]")
        self.btn_traceroute.clicked.disconnect()
        self.btn_traceroute.clicked.connect(self._run_traceroute)

    def _on_action_finished(self):
        self.output_box.append("\n// done.")
        self.btn_traceroute.setText("[ TRACEROUTE ]")
        self.btn_traceroute.clicked.disconnect()
        self.btn_traceroute.clicked.connect(self._run_traceroute)

    # SEZIONE ATTACK SURFACE (Beta)
    def _build_attackSurface_page(self):
        self.scanning = False
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        left = QWidget()
        left.setFixedWidth(240)
        left.setStyleSheet("background-color: #080808; border-right: 1px solid #1a1a1a;")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(10, 10, 10, 10)
        left_layout.setSpacing(6)

        as_label = QLabel("TARGET")
        as_label.setStyleSheet("color: #00ff99; font-size: 11px; letter-spacing: 2px;")
        left_layout.addWidget(as_label)

        self.as_target = QLineEdit()
        self.as_target.setPlaceholderText("192.168.1.1")
        self.as_target.setStyleSheet("""
            QLineEdit {
                background-color: #111111;
                color: #e0e0e0;
                border: 1px solid #1a1a1a;
                padding: 6px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 11px;
            }
            QLineEdit:focus { border-color: #00ff99; }
        """)
        left_layout.addWidget(self.as_target)

        self.as_scan_btn = QPushButton("[ ANALYZE ]")
        self.as_scan_btn.setDisabled(True)
        self.as_scan_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.as_scan_btn.setStyleSheet("""
            QPushButton {
                border: 1px solid #00ff99 !important;                           
            }
            QPushButton:hover { 
                color: #00ff99; 
                font-size: 14px; 
            }
            QPushButton:pressed { font-size: 12px; }                          
        """)
        self.as_scan_btn.clicked.connect(self._as_start_scan)
        left_layout.addWidget(self.as_scan_btn)
        
        self.as_target.textChanged.connect(lambda: self.as_scan_btn.setDisabled(True) if self.as_target.text() == "" else self.as_scan_btn.setDisabled(self.scanning))

        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #1a1a1a; margin-top: 4px; margin-bottom: 4px;")
        left_layout.addWidget(sep)

        history_label = QLabel("HISTORY")
        history_label.setStyleSheet("color: #444444; font-size: 10px; letter-spacing: 2px;")
        left_layout.addWidget(history_label)

        self.as_history = QTableWidget()
        self.as_history.setColumnCount(2)
        self.as_history.setHorizontalHeaderLabels(["TARGET", "RISK"])
        self.as_history.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.as_history.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.as_history.setColumnWidth(1, 60)
        self.as_history.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.as_history.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.as_history.verticalHeader().setVisible(False)
        self.as_history.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.as_history.itemClicked.connect(self._as_load_from_history)
        self.as_history.setStyleSheet("""
            QTableWidget { background-color: #080808; border: none; }
            QTableWidget::item:selected { color: #00ff99; }
        """)
        left_layout.addWidget(self.as_history, stretch=1)

        self._as_results = {}

        layout.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self.as_header = QLabel("// attack surface — select a target")
        self.as_header.setFixedHeight(36)
        self.as_header.setStyleSheet("""
            background-color: #080808;
            color: #444444;
            font-size: 11px;
            padding: 0px 12px;
            border-bottom: 1px solid #1a1a1a;
        """)
        right_layout.addWidget(self.as_header)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet("QSplitter::handle { background-color: #1a1a1a; }")

        ports_container = QWidget()
        ports_layout = QVBoxLayout(ports_container)
        ports_layout.setContentsMargins(0, 0, 0, 0)
        ports_layout.setSpacing(0)

        ports_label = QLabel("  OPEN PORTS")
        ports_label.setFixedHeight(24)
        ports_label.setStyleSheet("background-color: #0a0a0a; color: #555555; font-size: 10px; letter-spacing: 2px; border-bottom: 1px solid #111;")
        ports_layout.addWidget(ports_label)

        self.as_ports_table = QTableWidget()
        self.as_ports_table.setColumnCount(5)
        self.as_ports_table.setHorizontalHeaderLabels(["PORT", "PROTO", "SERVICE", "VERSION", "RISK"])
        self.as_ports_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.as_ports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.as_ports_table.setColumnWidth(0, 70)
        self.as_ports_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.as_ports_table.setColumnWidth(1, 60)
        self.as_ports_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.as_ports_table.setColumnWidth(2, 100)
        self.as_ports_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.as_ports_table.setColumnWidth(4, 80)
        self.as_ports_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.as_ports_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.as_ports_table.verticalHeader().setVisible(False)
        self.as_ports_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        ports_layout.addWidget(self.as_ports_table)
        splitter.addWidget(ports_container)

        cve_container = QWidget()
        cve_layout = QVBoxLayout(cve_container)
        cve_layout.setContentsMargins(0, 0, 0, 0)
        cve_layout.setSpacing(0)

        cve_label = QLabel("  VULNERABILITIES / CVE")
        cve_label.setFixedHeight(24)
        cve_label.setStyleSheet("background-color: #0a0a0a; color: #555555; font-size: 10px; letter-spacing: 2px; border-bottom: 1px solid #111; border-top: 1px solid #111;")
        cve_layout.addWidget(cve_label)

        self.as_cve_table = QTableWidget()
        self.as_cve_table.setColumnCount(5)
        self.as_cve_table.setHorizontalHeaderLabels(["CVE ID", "CVSS", "PORT", "SERVICE", "DETAIL"])
        self.as_cve_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.as_cve_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.as_cve_table.setColumnWidth(0, 140)
        self.as_cve_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.as_cve_table.setColumnWidth(1, 60)
        self.as_cve_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.as_cve_table.setColumnWidth(2, 60)
        self.as_cve_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.as_cve_table.setColumnWidth(3, 100)
        self.as_cve_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.as_cve_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.as_cve_table.verticalHeader().setVisible(False)
        self.as_cve_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.as_cve_table.itemDoubleClicked.connect(self._as_open_cve)
        cve_layout.addWidget(self.as_cve_table)
        splitter.addWidget(cve_container)

        splitter.setSizes([300, 200])
        right_layout.addWidget(splitter, stretch=1)


        self.as_status = QLabel("// ready")
        self.as_status.setStyleSheet("""
            background-color: #080808;
            color: #333333;
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #1a1a1a;
        """)
        right_layout.addWidget(self.as_status)
        layout.addWidget(right, stretch=1)
        return page
    
    def _as_start_scan(self):
        self.scanning = True
        self.as_target.setDisabled(True)
        target = self.as_target.text().strip()
        if not target:
            return

        self.as_scan_btn.setEnabled(False)
        self.as_scan_btn.setText("[ SCANNING... ]")
        self.as_ports_table.setRowCount(0)
        self.as_cve_table.setRowCount(0)
        self.as_status.setText(f"// scanning {target}...")
        self.as_status.setStyleSheet("""
            background-color: #080808;
            color: #00ff99;
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #1a1a1a;
        """)

        self.as_worker = AttackSurfaceWorker(target)
        self.as_worker.status_update.connect(self.as_status.setText)
        self.as_worker.port_found.connect(self._as_add_port_realtime)
        self.as_worker.finished.connect(self._as_on_finished)
        self.as_worker.start()

    def _as_add_port_realtime(self, port: dict):
        risk_colors = {"CRITICAL":"#ff0000","HIGH": "#ff4444", "MEDIUM": "#ff9900", "LOW": "#00ff99"}
        row = self.as_ports_table.rowCount()
        self.as_ports_table.insertRow(row)
        self.as_ports_table.setItem(row, 0, QTableWidgetItem(port["port"]))
        self.as_ports_table.setItem(row, 1, QTableWidgetItem(port["protocol"]))
        self.as_ports_table.setItem(row, 2, QTableWidgetItem(port["service"]))
        self.as_ports_table.setItem(row, 3, QTableWidgetItem(port["version"]))
        risk_item = QTableWidgetItem(port["risk"])
        risk_item.setForeground(QColor(risk_colors.get(port["risk"], "#aaaaaa")))
        self.as_ports_table.setItem(row, 4, risk_item)

    def _as_on_finished(self, result: dict):
        self.scanning = False
        self.as_target.setDisabled(False)
        self.as_scan_btn.setEnabled(True)
        self.as_scan_btn.setText("[ ANALYZE ]")
        self.as_ports_table.setRowCount(0)
        target = result["target"]
        self._as_results[target] = result
        self._as_display(result)
        self._as_update_history(target, result)

    def _as_display(self, result: dict):
        target = result["target"]
        os_info = result["os"]
        port_count = len(result["ports"])
        cve_count = len(result["cves"])

        self.as_header.setText(
            f"// {target}  —  OS: {os_info}  —  {port_count} ports  —  {cve_count} CVE"
        )
        self.as_header.setStyleSheet("""
            background-color: #080808;
            color: #00ff99;
            font-size: 11px;
            padding: 0px 12px;
            border-bottom: 1px solid #1a1a1a;
        """)

        risk_colors = {"CRITICAL":"#ff2222","HIGH": "#ff4444", "MEDIUM": "#ff9900", "LOW": "#00ff99"}
        self.as_ports_table.setRowCount(0)
        for p in result["ports"]:
            row = self.as_ports_table.rowCount()
            self.as_ports_table.insertRow(row)
            self.as_ports_table.setItem(row, 0, QTableWidgetItem(p["port"]))
            self.as_ports_table.setItem(row, 1, QTableWidgetItem(p["protocol"]))
            self.as_ports_table.setItem(row, 2, QTableWidgetItem(p["service"]))
            self.as_ports_table.setItem(row, 3, QTableWidgetItem(p["version"]))
            risk_item = QTableWidgetItem(p["risk"])
            risk_item.setForeground(QColor(risk_colors.get(p["risk"], "#aaaaaa")))
            self.as_ports_table.setItem(row, 4, risk_item)

        self.as_cve_table.setRowCount(0)
        for c in result["cves"]:
            row = self.as_cve_table.rowCount()
            self.as_cve_table.insertRow(row)
            cve_item = QTableWidgetItem(c["id"])
            cve_item.setForeground(QColor("#4488ff"))
            cve_item.setData(Qt.ItemDataRole.UserRole, f"https://nvd.nist.gov/vuln/detail/{c['id']}")
            self.as_cve_table.setItem(row,0,cve_item)
            cvss = c["cvss"]
            cvss_item = QTableWidgetItem(str(cvss))
            if cvss >= 9.0:
                cvss_item.setForeground(QColor("#ff2222"))
            elif cvss >= 7.0:
                cvss_item.setForeground(QColor("#ff6600"))
            elif cvss >= 4.0:
                cvss_item.setForeground(QColor("#ffaa00"))
            else:
                cvss_item.setForeground(QColor("#888888"))
            self.as_cve_table.setItem(row, 1, cvss_item)
            self.as_cve_table.setItem(row, 2, QTableWidgetItem(c["port"]))
            self.as_cve_table.setItem(row, 3, QTableWidgetItem(c["service"]))
            self.as_cve_table.setItem(row, 4, QTableWidgetItem(c["detail"]))

        if result["cves"]:
            max_cvss = result["cves"][0]["cvss"]
            if max_cvss >= 9.0:
                risk_summary = "CRITICAL"
                color = "#ff2222"
            elif max_cvss >= 7.0:
                risk_summary = "HIGH"
                color = "#ff6600"
            elif max_cvss >= 4.0:
                risk_summary = "MEDIUM"
                color = "#ffaa00"
            else:
                risk_summary = "LOW"
                color = "#00ff99"
        elif result["ports"]:
            high_ports = [p for p in result["ports"] if p["risk"] == "HIGH"]
            risk_summary = "HIGH" if high_ports else "LOW"
            color = "#ff4444" if high_ports else "#00ff99"
        else:
            risk_summary = "CLEAN"
            color = "#00ff99"

        self.as_status.setText(f"// scan complete — max risk: {risk_summary}")
        self.as_status.setStyleSheet(f"""
            background-color: #080808;
            color: {color};
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #1a1a1a;
        """)

    def _as_open_cve(self, item):
        if item.column() != 0: 
            return
        url = item.data(Qt.ItemDataRole.UserRole)
        if not url:
            return
        real_user = os.environ.get("SUDO_USER") or os.environ.get("USER", "")
        if real_user and real_user != "root":
            subprocess.Popen(
                ["sudo", "-u", real_user, "xdg-open", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            ) 
        else:
            QDesktopServices.openUrl(QtUrl(url))

    def _as_update_history(self, target: str, result: dict):
        for row in range(self.as_history.rowCount()):
            if self.as_history.item(row, 0).text() == target:
                self.as_history.removeRow(row)
                break

        row = 0
        self.as_history.insertRow(row)
        self.as_history.setItem(row, 0, QTableWidgetItem(target))

        if result["cves"]:
            max_cvss = result["cves"][0]["cvss"]
            risk = "CRIT" if max_cvss >= 9 else "HIGH" if max_cvss >= 7 else "MED"
            color = "#ff2222" if max_cvss >= 9 else "#ff6600" if max_cvss >= 7 else "#ffaa00"
        elif any(p["risk"] == "HIGH" for p in result["ports"]):
            risk, color = "HIGH", "#ff4444"
        else:
            risk, color = "LOW", "#00ff99"

        risk_item = QTableWidgetItem(risk)
        risk_item.setForeground(QColor(color))
        risk_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.as_history.setItem(row, 1, risk_item)

    def _as_load_from_history(self, item):
        row = item.row()
        target = self.as_history.item(row, 0).text()
        if target in self._as_results:
            self._as_display(self._as_results[target])

if __name__ == "__main__":
    check_root()
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--no-sandbox --disable-gpu --disable-software-rasterizer"
    os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"
    app = QApplication(sys.argv)
    logo = LogoIniziale()
    logo.show()
    app.processEvents()
    window = MainWindow()
    QTimer.singleShot(2500, lambda: (logo.finish(window), window.show()))
    sys.exit(app.exec())
