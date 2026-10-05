import unittest

from core.nmap_options import SCAN_PRESETS, build_scan_command


class NmapOptionsTests(unittest.TestCase):
    def test_basic_preset_is_fast_tcp_only(self):
        cmd = build_scan_command(SCAN_PRESETS["basic"], "", "192.0.2.10")
        self.assertIn("-sT", cmd)
        self.assertIn("-F", cmd)
        self.assertNotIn("-sU", cmd)
        self.assertNotIn("-p-", cmd)

    def test_complete_preset_combines_tcp_udp_and_detection(self):
        cmd = build_scan_command(SCAN_PRESETS["complete"], "", "192.0.2.10")
        for flag in ("-sS", "-sU", "-p-", "-sV", "-O", "-sC"):
            self.assertIn(flag, cmd)

    def test_multiple_tcp_methods_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "TCP"):
            build_scan_command(["-sS", "-sT"], "", "192.0.2.10")

    def test_custom_flags_cannot_add_conflicting_tcp_methods(self):
        for custom in ("-sT", "-sTX", "-s T", "-sI 192.0.2.20"):
            with self.subTest(custom=custom), self.assertRaisesRegex(ValueError, "TCP"):
                build_scan_command(["-sS"], custom, "192.0.2.10")

    def test_combined_syn_udp_is_allowed(self):
        self.assertIn("-sSU", build_scan_command([], "-sSU", "192.0.2.10"))

    def test_multiple_port_ranges_are_rejected(self):
        for selected, custom in ((["-F", "-p-"], ""), (["-F"], "-p 80,443"),
                                 (["-p-"], "--top-ports 20"), (["-F"], "--top-ports=20")):
            with self.subTest(selected=selected, custom=custom), self.assertRaisesRegex(ValueError, "port range"):
                build_scan_command(selected, custom, "192.0.2.10")

    def test_custom_ports_work_with_default_port_range(self):
        self.assertIn("80,443", build_scan_command(["", "-sT"], "-p 80,443", "192.0.2.10"))

    def test_multiple_timing_levels_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "timing"):
            build_scan_command(["-T3"], "-T4", "192.0.2.10")

    def test_multiple_script_options_are_combined(self):
        cmd = build_scan_command(["-sC", "--script banner", "--script ssl-cert"],
                                 "--script http-title", "192.0.2.10")
        self.assertEqual(cmd.count("--script"), 1)
        self.assertEqual(cmd[cmd.index("--script") + 1], "default,banner,ssl-cert,http-title")
        self.assertNotIn("-sC", cmd)

    def test_os_guess_requires_os_detection(self):
        with self.assertRaisesRegex(ValueError, "OS detection"):
            build_scan_command(["--osscan-guess"], "", "192.0.2.10")

    def test_aggressive_includes_os_detection(self):
        self.assertIn("--osscan-guess", build_scan_command(["-A", "--osscan-guess"], "", "192.0.2.10"))

    def test_missing_script_value_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "script"):
            build_scan_command([], "--script", "192.0.2.10")

    def test_quoted_arguments_remain_single_arguments(self):
        cmd = build_scan_command([], '--script-args "http.useragent=Test Agent"', "192.0.2.10")
        self.assertIn("http.useragent=Test Agent", cmd)

    def test_unclosed_quotes_are_rejected(self):
        with self.assertRaises(ValueError):
            build_scan_command([], '--script "http-title', "192.0.2.10")

    def test_no_target_does_not_produce_a_command(self):
        with self.assertRaisesRegex(ValueError, "target"):
            build_scan_command([], "", "")

    def test_value_of_script_arguments_is_not_treated_as_a_scan_flag(self):
        cmd = build_scan_command(["-sS"], '--script-args "-sT"', "192.0.2.10")
        self.assertIn("--script-args", cmd)

    def test_value_of_script_arguments_does_not_enable_os_detection(self):
        with self.assertRaisesRegex(ValueError, "OS detection"):
            build_scan_command(["--osscan-guess"], '--script-args "-O"', "192.0.2.10")

    def test_attached_bounce_scan_conflicts_with_tcp(self):
        with self.assertRaisesRegex(ValueError, "TCP"):
            build_scan_command(["-sS"], "-b192.0.2.20", "192.0.2.10")

    def test_script_option_value_is_preserved_when_scripts_are_combined(self):
        cmd = build_scan_command(["--script banner"], '--script-args "-sC"', "192.0.2.10")
        self.assertEqual(cmd[cmd.index("--script-args") + 1], "-sC")
        self.assertEqual(cmd[cmd.index("--script") + 1], "banner")


if __name__ == "__main__":
    unittest.main()
