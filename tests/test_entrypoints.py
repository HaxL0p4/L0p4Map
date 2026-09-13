import subprocess
import sys
import tomllib
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]


class EntrypointSmokeTests(unittest.TestCase):
    def run_entrypoint(self, *arguments):
        return subprocess.run(
            [sys.executable, *arguments],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_windows_compatibility_launcher_has_help(self):
        result = self.run_entrypoint("L0p4Map.py", "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("network monitoring & visualization tool", result.stdout)

    def test_main_script_reports_project_version(self):
        result = self.run_entrypoint("main.py", "--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "l0p4map 1.0.2")

    def test_directory_entrypoint_reports_project_version(self):
        result = self.run_entrypoint(".", "--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "l0p4map 1.0.2")

    def test_runtime_version_matches_project_metadata(self):
        from main import __version__

        with (REPO_ROOT / "pyproject.toml").open("rb") as project_file:
            project_version = tomllib.load(project_file)["project"]["version"]
        self.assertEqual(__version__, project_version)

    def test_debian_package_includes_main_module(self):
        install_manifest = (REPO_ROOT / "debian" / "install").read_text()
        self.assertIn("main.py usr/share/l0p4map", install_manifest.splitlines())

    def test_windows_privilege_error_is_actionable(self):
        import main

        stderr = StringIO()
        with (
            patch.object(main, "is_admin", return_value=False),
            patch.object(main.platform, "system", return_value="Windows"),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as exit_context,
        ):
            main._check_root()

        self.assertEqual(exit_context.exception.code, 1)
        self.assertIn("run terminal as Administrator", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
