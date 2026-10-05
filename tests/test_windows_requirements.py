import os
import io
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from contextlib import redirect_stderr

from core import windows_requirements as requirements


class WindowsRequirementsTests(unittest.TestCase):
    def test_missing_dependencies_are_reported_together(self):
        with patch.object(requirements, "find_nmap", return_value=None), \
                patch.object(requirements, "npcap_version", side_effect=OSError("missing DLL")), \
                patch.object(requirements.importlib, "import_module", side_effect=ImportError("missing package")):
            report = requirements.check_windows_requirements()
        self.assertFalse(report["ready"])
        self.assertEqual({c["name"] for c in report["checks"] if not c["ok"]},
                         {"Python packages", "Nmap", "Npcap"})

    def test_working_dependencies_are_ready(self):
        with patch.object(requirements, "find_nmap", return_value="C:/Nmap/nmap.exe"), \
                patch.object(requirements, "npcap_version", return_value="Npcap version 1.89"), \
                patch.object(requirements.importlib, "import_module", return_value=object()), \
                patch.object(requirements.subprocess, "run", return_value=SimpleNamespace(stdout="Nmap version 7.991\n")):
            report = requirements.check_windows_requirements()
        self.assertTrue(report["ready"])

    def test_broken_nmap_is_not_ready(self):
        with patch.object(requirements, "find_nmap", return_value="C:/Nmap/nmap.exe"), \
                patch.object(requirements, "npcap_version", return_value="Npcap"), \
                patch.object(requirements.importlib, "import_module", return_value=object()), \
                patch.object(requirements.subprocess, "run", side_effect=subprocess.TimeoutExpired("nmap", 10)):
            report = requirements.check_windows_requirements()
        self.assertFalse(next(c for c in report["checks"] if c["name"] == "Nmap")["ok"])

    def test_installed_nmap_is_found_outside_path(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "Nmap" / "nmap.exe"
            binary.parent.mkdir()
            binary.touch()
            with patch.object(requirements.shutil, "which", return_value=None), \
                    patch.dict(os.environ, {"ProgramFiles": directory}, clear=True):
                self.assertEqual(requirements.find_nmap(), str(binary))

    def test_startup_adds_verified_nmap_to_process_path(self):
        report = {"ready": True, "checks": [
            {"name": "Nmap", "ok": True, "path": "C:/Nmap/nmap.exe", "detail": "Nmap version 7.991"}
        ]}
        with patch.object(requirements.os, "name", "nt"), \
                patch.object(requirements, "check_windows_requirements", return_value=report), \
                patch.dict(os.environ, {"PATH": "existing"}):
            requirements.require_windows_dependencies()
            self.assertEqual(os.environ["PATH"], os.path.dirname("C:/Nmap/nmap.exe") + os.pathsep + "existing")

    def test_startup_explains_how_to_install_missing_components(self):
        report = {"ready": False, "checks": [{"name": "Nmap", "ok": False, "detail": "not installed"}]}
        with patch.object(requirements.os, "name", "nt"), \
                patch.object(requirements, "check_windows_requirements", return_value=report):
            with self.assertRaisesRegex(RuntimeError, "setup-windows.ps1"):
                requirements.require_windows_dependencies()

    def test_unix_startup_is_unchanged(self):
        with patch.object(requirements.os, "name", "posix"), \
                patch.object(requirements, "check_windows_requirements", side_effect=AssertionError("Windows-only check")):
            requirements.require_windows_dependencies()

    def test_npcap_library_version_is_queried(self):
        version_api = Mock(return_value=b"Npcap version 1.89")
        with patch.object(requirements.ctypes, "CDLL", return_value=SimpleNamespace(pcap_lib_version=version_api)):
            self.assertEqual(requirements.npcap_version(), "Npcap version 1.89")

    def test_gui_stops_before_loading_ui_when_prerequisites_are_missing(self):
        entry = runpy.run_path(str(Path(__file__).resolve().parents[1] / "__main__.py"))
        output = io.StringIO()
        with patch.dict(entry["cmd_gui"].__globals__, {"_check_root": lambda: None}), \
                patch.object(requirements.os, "name", "nt"), \
                patch.object(requirements, "check_windows_requirements", return_value={
                    "ready": False, "checks": [{"name": "Nmap", "ok": False, "detail": "not installed"}]
                }), redirect_stderr(output):
            with self.assertRaises(SystemExit) as caught:
                entry["cmd_gui"](None)
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("Nmap", output.getvalue())
        self.assertIn("setup-windows.ps1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
