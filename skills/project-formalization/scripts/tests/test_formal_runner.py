from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "formal_runner.py"
SPEC = importlib.util.spec_from_file_location("formal_runner", SCRIPT)
assert SPEC and SPEC.loader
formal_runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(formal_runner)


class FormalRunnerTests(unittest.TestCase):
    def test_probe_reports_native_formal_backend(self) -> None:
        with mock.patch.object(formal_runner.shutil, "which", side_effect=lambda name: "/usr/bin/cbmc" if name == "cbmc" else None), mock.patch.object(formal_runner, "version_from", return_value="CBMC test"):
            result = formal_runner.probe(distros=[])
        cbmc = next(item for item in result["native"]["formal_tools"] if item["name"] == "cbmc")
        self.assertTrue(cbmc["available"])
        self.assertEqual("CBMC test", cbmc["version"])
        self.assertEqual([], result["wsl"])

    def test_run_records_output_hashes_and_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            code = formal_runner.run_recorded(
                "cbmc",
                "bounded_model_checking",
                [sys.executable, "-c", "print('formal output')"],
                output,
                "native",
                None,
                None,
            )
            self.assertEqual(0, code)
            receipt = json.loads((output / "receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(0, receipt["exit_code"])
            self.assertEqual("formal output\n", (output / "stdout.log").read_text(encoding="utf-8"))
            self.assertEqual(formal_runner.sha256_file(output / "stdout.log"), receipt["stdout"]["sha256"])

    def test_failed_formal_command_preserves_nonzero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            code = formal_runner.run_recorded(
                "cbmc",
                "bounded_model_checking",
                [sys.executable, "-c", "raise SystemExit(7)"],
                Path(temp),
                "native",
                None,
                None,
            )
            self.assertEqual(7, code)

    def test_wsl_command_has_explicit_distro_and_linux_cwd(self) -> None:
        with mock.patch.object(formal_runner.shutil, "which", return_value="C:/Windows/System32/wsl.exe"):
            command = formal_runner.effective_command(["cbmc", "harness.c"], "wsl", "Ubuntu", "/work/exp")
        self.assertEqual("Ubuntu", command[2])
        self.assertEqual(["--cd", "/work/exp"], command[3:5])
        self.assertEqual(["--", "cbmc", "harness.c"], command[5:])

    def test_frama_c_accepts_deductive_family(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            code = formal_runner.run_recorded(
                "frama-c",
                "deductive_verification",
                [sys.executable, "-c", "print('wp')"],
                Path(temp),
                "native",
                None,
                None,
            )
            self.assertEqual(0, code)


if __name__ == "__main__":
    unittest.main()
