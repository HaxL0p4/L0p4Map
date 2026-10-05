import runpy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.modules["__main__"].__version__ = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "__main__.py"))["__version__"]

from PyQt6.QtWidgets import QApplication, QMainWindow
from ui.app import MainWindow


class NmapUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([sys.argv[0]])

    def setUp(self):
        # Exercise the real scan panel without creating WebEngine or scanning.
        self.window = MainWindow.__new__(MainWindow)
        QMainWindow.__init__(self.window)
        self.panel = self.window._build_scan_options()
        self.output = self.window._build_scan_output()
        self.window.scan_target.setText("192.0.2.10")

    def tearDown(self):
        self.panel.deleteLater()
        self.output.deleteLater()
        self.window.deleteLater()
        self.app.processEvents()

    def test_tcp_methods_are_mutually_exclusive(self):
        for flag in ("-sS", "-sT", "-sN", "-sX"):
            self.window._scan_checks[flag].click()
            selected = [f for f in ("-sS", "-sT", "-sN", "-sX") if self.window._scan_checks[f].isChecked()]
            self.assertEqual(selected, [flag])

    def test_udp_can_be_selected_with_tcp(self):
        self.window._scan_checks["-sU"].click()
        self.assertTrue(self.window._scan_checks["-sT"].isChecked())
        self.assertTrue(self.window._scan_checks["-sU"].isChecked())

    def test_only_one_timing_level_is_selected(self):
        self.window._scan_checks["-T5"].click()
        self.assertFalse(self.window._scan_checks["-T3"].isChecked())
        self.assertTrue(self.window._scan_checks["-T5"].isChecked())

    def test_port_ranges_include_a_default_choice(self):
        self.window._scan_checks["-p-"].click()
        self.assertFalse(self.window._scan_checks["-F"].isChecked())
        self.window._scan_checks[""].click()
        self.assertFalse(self.window._scan_checks["-p-"].isChecked())

    def test_complete_button_selects_tcp_udp_and_all_ports(self):
        self.window._scan_preset_buttons["complete"].click()
        for flag in ("-sS", "-sU", "-p-", "-sV", "-O", "-sC"):
            self.assertTrue(self.window._scan_checks[flag].isChecked(), flag)
        self.assertFalse(self.window._scan_checks["-F"].isChecked())

    def test_basic_button_clears_complete_and_custom_flags(self):
        self.window._apply_scan_preset("complete")
        self.window.custom_flags.setText("--script http-title")
        self.window._scan_preset_buttons["basic"].click()
        self.assertEqual(self.window.custom_flags.text(), "")
        self.assertFalse(self.window._scan_checks["-sU"].isChecked())
        self.assertTrue(self.window._scan_checks["-F"].isChecked())

    def test_os_guess_requires_detection(self):
        guess = self.window._scan_checks["--osscan-guess"]
        self.assertFalse(guess.isEnabled())
        self.window._scan_checks["-O"].click()
        self.assertTrue(guess.isEnabled())
        guess.click()
        self.window._scan_checks["-O"].click()
        self.assertFalse(guess.isEnabled())
        self.assertFalse(guess.isChecked())

    def test_aggressive_disables_redundant_options(self):
        self.window._scan_checks["-A"].click()
        for flag in ("-sV", "-O", "-sC"):
            self.assertFalse(self.window._scan_checks[flag].isEnabled())
        self.assertTrue(self.window._scan_checks["--osscan-guess"].isEnabled())

    def test_conflicting_custom_flags_disable_run_and_do_not_launch_worker(self):
        self.window.custom_flags.setText("-sS")
        self.assertFalse(self.window.btn_run_scan.isEnabled())
        with patch("ui.app.ActionWorker") as worker:
            self.window._run_nmap_scan()
        worker.assert_not_called()
        self.assertIn("TCP", self.window.scan_output.toPlainText())

    def test_custom_port_range_can_be_used_after_selecting_default(self):
        self.window._scan_checks[""].click()
        self.window.custom_flags.setText("-p 80,443")
        self.assertTrue(self.window.btn_run_scan.isEnabled())
        self.assertIn("80,443", self.window.scan_cmd_label.text())

    def test_valid_complete_command_starts_one_worker(self):
        self.window._apply_scan_preset("complete")
        expected = self.window._scan_command("192.0.2.10")
        with patch("ui.app.ActionWorker") as worker:
            self.window.btn_run_scan.click()
            worker.assert_called_once_with(expected)
            worker.return_value.start.assert_called_once()
        self.assertEqual(self.window.btn_run_scan.text(), "[ STOP ]")

    def test_stop_remains_available_when_flags_are_edited_during_scan(self):
        self.window._apply_scan_preset("complete")
        with patch("ui.app.ActionWorker"):
            self.window.btn_run_scan.click()
            self.window.custom_flags.setText("-sT")
            self.assertTrue(self.window.btn_run_scan.isEnabled())
            self.window.btn_run_scan.click()
        self.assertFalse(self.window._scan_busy)
        self.assertFalse(self.window.btn_run_scan.isEnabled())


if __name__ == "__main__":
    unittest.main()
