import os
import runpy
import unittest
from pathlib import Path
from unittest.mock import patch

from core.gui_runtime import configure_gui_environment


class GuiRuntimeTests(unittest.TestCase):
    def test_windows_uses_qt_graphics_selection(self):
        with patch.object(os, "name", "nt"), patch.dict(os.environ, {}, clear=True):
            configure_gui_environment()
            flags = os.environ["QTWEBENGINE_CHROMIUM_FLAGS"].split()
            self.assertNotIn("--disable-gpu", flags)
            self.assertNotIn("--disable-software-rasterizer", flags)
            self.assertNotIn("QT_OPENGL", os.environ)
            self.assertNotIn("QT_QUICK_BACKEND", os.environ)

    def test_explicit_user_graphics_flags_are_preserved(self):
        with patch.object(os, "name", "nt"), patch.dict(os.environ, {
            "QTWEBENGINE_CHROMIUM_FLAGS": "--disable-gpu",
            "QTWEBENGINE_DISABLE_SANDBOX": "0"
        }, clear=True):
            configure_gui_environment()
            self.assertEqual(os.environ["QTWEBENGINE_CHROMIUM_FLAGS"], "--disable-gpu")
            self.assertEqual(os.environ["QTWEBENGINE_DISABLE_SANDBOX"], "0")

    def test_unix_legacy_defaults_are_preserved(self):
        with patch.object(os, "name", "posix"), patch.dict(os.environ, {}, clear=True):
            configure_gui_environment()
            self.assertIn("--disable-gpu", os.environ["QTWEBENGINE_CHROMIUM_FLAGS"])

    def test_cli_configures_graphics_before_dependency_imports(self):
        entry = runpy.run_path(str(Path(__file__).resolve().parents[1] / "__main__.py"))
        events = []

        def dependencies():
            events.append("dependencies")
            raise RuntimeError("stop before Qt imports")

        with patch.dict(entry["cmd_gui"].__globals__, {
            "_check_root": lambda: events.append("privileges"),
            "configure_gui_environment": lambda: events.append("graphics"),
            "_check_dependencies": dependencies
        }):
            with self.assertRaisesRegex(RuntimeError, "stop before Qt imports"):
                entry["cmd_gui"](None)
        self.assertEqual(events, ["privileges", "graphics", "dependencies"])


if __name__ == "__main__":
    unittest.main()
