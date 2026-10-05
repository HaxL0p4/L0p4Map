"""Windows prerequisite diagnostics without administrator rights or network scans."""

import ctypes
import importlib
import json
import os
import shutil
import subprocess
import sys


def find_nmap():
    binary = shutil.which("nmap")
    if binary:
        return binary
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        base = os.environ.get(variable)
        if not base:
            continue
        for relative in ("Nmap", os.path.join("Programs", "Nmap")):
            candidate = os.path.join(base, relative, "nmap.exe")
            if os.path.isfile(candidate):
                return candidate
    return None


def npcap_version():
    directory = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
    library = ctypes.CDLL(os.path.join(directory, "wpcap.dll"))
    library.pcap_lib_version.restype = ctypes.c_char_p
    version = library.pcap_lib_version()
    if not version:
        raise OSError("Npcap library returned no version")
    return version.decode("utf-8", errors="replace")


def check_windows_requirements():
    checks = [{"name": "Python", "ok": sys.version_info >= (3, 11),
               "detail": sys.version.split()[0]}]
    missing = []
    for module in ("scapy.all", "psutil", "requests", "PyQt6.QtWidgets", "PyQt6.QtWebEngineWidgets"):
        try:
            importlib.import_module(module)
        except (ImportError, OSError) as exc:
            missing.append(f"{module}: {exc}")
    checks.append({"name": "Python packages", "ok": not missing,
                   "detail": "; ".join(missing) or "All required modules imported"})

    binary = find_nmap()
    nmap = {"name": "Nmap", "ok": False, "path": binary, "detail": "nmap.exe not found"}
    if binary:
        try:
            result = subprocess.run([binary, "--version"], check=True, capture_output=True,
                                    text=True, timeout=10)
            nmap["ok"] = result.stdout.startswith("Nmap version")
            nmap["detail"] = result.stdout.splitlines()[0] if result.stdout else "No version returned"
        except (OSError, subprocess.SubprocessError) as exc:
            nmap["detail"] = str(exc)
    checks.append(nmap)
    try:
        checks.append({"name": "Npcap", "ok": True, "detail": npcap_version()})
    except (AttributeError, OSError) as exc:
        checks.append({"name": "Npcap", "ok": False, "detail": str(exc)})
    return {"ready": all(check["ok"] for check in checks), "checks": checks}


def require_windows_dependencies():
    if os.name != "nt":
        return
    report = check_windows_requirements()
    if not report["ready"]:
        missing = "; ".join(f"{check['name']}: {check['detail']}"
                            for check in report["checks"] if not check["ok"])
        raise RuntimeError(f"Windows prerequisites missing: {missing}\n"
                           "Run .\\setup-windows.ps1 in PowerShell as Administrator.")
    binary = next(check["path"] for check in report["checks"] if check["name"] == "Nmap")
    directory = os.path.dirname(binary)
    current = os.environ.get("PATH", "")
    if os.path.normcase(directory) not in [os.path.normcase(p) for p in current.split(os.pathsep)]:
        os.environ["PATH"] = directory + os.pathsep + current


if __name__ == "__main__":
    if os.name != "nt":
        print("This diagnostic is for Windows.", file=sys.stderr)
        sys.exit(1)
    report = check_windows_requirements()
    if "--json" in sys.argv:
        print(json.dumps(report))
    else:
        for check in report["checks"]:
            print(f"{'OK' if check['ok'] else 'MISSING'} {check['name']}: {check['detail']}")
    sys.exit(0 if report["ready"] else 1)
