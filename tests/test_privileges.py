import ctypes
import io
import os
import runpy
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core.scanner import check_root


ENTRY = runpy.run_path(str(Path(__file__).resolve().parents[1] / "__main__.py"))


class PrivilegeTests(unittest.TestCase):
    def check_both(self, allowed, message):
        for check, error in ((ENTRY["_check_root"], SystemExit), (check_root, PermissionError)):
            with self.subTest(check=check.__name__):
                output = io.StringIO()
                with redirect_stderr(output):
                    if allowed:
                        check()
                    else:
                        with self.assertRaises(error) as caught:
                            check()
                        text = output.getvalue() if error is SystemExit else str(caught.exception)
                        self.assertIn(message.lower(), text.lower())
                        if error is SystemExit:
                            self.assertEqual(caught.exception.code, 1)

    def windows_case(self, result=None, failure=None):
        api = Mock(return_value=result, side_effect=failure)
        windows = SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=api))
        with patch.object(os, "name", "nt"), patch.object(ctypes, "windll", windows, create=True), \
                patch.object(os, "getuid", side_effect=AssertionError("Unix API used on Windows"), create=True):
            self.check_both(bool(result) and failure is None, "Administrator")

    def test_windows_administrator_is_allowed(self):
        self.windows_case(result=1)

    def test_windows_standard_user_is_rejected(self):
        self.windows_case(result=0)

    def test_windows_api_failure_is_rejected(self):
        self.windows_case(failure=OSError("privilege query failed"))

    def test_unix_root_is_allowed(self):
        with patch.object(os, "name", "posix"), patch.object(os, "getuid", return_value=0, create=True):
            self.check_both(True, "sudo")

    def test_unix_standard_user_is_rejected(self):
        with patch.object(os, "name", "posix"), patch.object(os, "getuid", return_value=1000, create=True):
            self.check_both(False, "sudo")


if __name__ == "__main__":
    unittest.main()
