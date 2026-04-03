import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit,
    QComboBox, QStackedWidget, QCheckBox, QLineEdit, QScrollArea,
    QFileDialog
)

from PyQt6.QtWebEngineWidgets import QWebEngineView
import json

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl, QSize
from PyQt6.QtGui import QFont, QColor, QIcon, QPixmap, QPainter
from PyQt6.QtSvg import QSvgRenderer
import subprocess
import sys
import os
import csv
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from core.scanner import scan_network, get_local_subnet, check_root, get_network_interfaces

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

        self.nav_btns = [
            (btn_home,  path_home),
            (btn_scan,  path_scan),
            (btn_graph, path_graph),
        ]

        def navigate(index):
            self.stack.setCurrentIndex(index)
            self._set_active_nav(index)

        btn_home.clicked.connect(lambda: navigate(0))
        btn_scan.clicked.connect(lambda: navigate(1))
        btn_graph.clicked.connect(lambda: navigate(2))

        for btn, path in self.nav_btns:
            layout.addWidget(btn)

        self._set_active_nav(0)

        layout.addStretch()
        return sidebar
    

    def _active_nav_btn(self):
        return self.nav_btns[self.stack.currentIndex()][0]

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
        contenuto_output = self.output_box.toPlainText()
        self.btn_export_scan.setDisabled(True)
        self.btn_export_scan.clicked.connect(self._export_scan)

        layout.addSpacing(10)
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
        #header_layout.addStretch()
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
        

    def _build_table(self):
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["IP", "MAC", "VENDOR", "HOSTNAME"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_device_selected)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        return self.table

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

        self.detail_ip       = QLabel("IP: —")
        self.detail_mac      = QLabel("MAC: —")
        self.detail_hostname = QLabel("HOSTNAME: —")
        self.detail_vendor   = QLabel("VENDOR: —")

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

        for btn in [self.btn_ping, self.btn_portscan, self.btn_traceroute]:
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
                    background-color: #1a1a2e;
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


if __name__ == "__main__":
    check_root()
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--no-sandbox --disable-gpu --disable-software-rasterizer"
    os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
