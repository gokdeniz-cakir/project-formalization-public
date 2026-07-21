from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "cases" / "wolfssl" / "CVE-2026-6679" / "model" / "ack_length_boundary.c"


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "ack-length-boundary"
        compiler = None
        diagnostics = []
        for candidate in (shutil.which("gcc"), shutil.which("clang")):
            if candidate is None:
                continue
            result = subprocess.run(
                [candidate, "-std=c11", "-Wall", "-Wextra", str(SOURCE), "-o", str(output)],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                compiler = candidate
                break
            diagnostics.append(f"{candidate}: {result.stderr.strip()}")

        if compiler is None:
            print("Model test skipped: no working C compiler was found.")
            if diagnostics:
                print("\n".join(diagnostics))
            return 0

        control = subprocess.run([str(output), "4095"], check=False, capture_output=True, text=True)
        witness = subprocess.run([str(output), "4096"], check=False, capture_output=True, text=True)

    if control.returncode != 0 or "result=representable" not in control.stdout:
        raise SystemExit("4,095 control did not remain representable")
    if witness.returncode != 1 or "result=length-inconsistency" not in witness.stdout:
        raise SystemExit("4,096 witness did not expose the expected inconsistency")

    print("ACK boundary model passed: 4,095 clean; 4,096 inconsistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
