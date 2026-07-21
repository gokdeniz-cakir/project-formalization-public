from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKS = (
    ("publication audit", [sys.executable, "scripts/audit-publication.py"]),
    ("boundary model", [sys.executable, "scripts/test-model.py"]),
    ("skill integrity", [sys.executable, "scripts/test-skills.py"]),
    (
        "formal skill tests",
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "skills/project-formalization/scripts/tests",
            "-p",
            "test_*.py",
        ],
    ),
    (
        "raw skill tests",
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "skills/project-formalization-raw/scripts/tests",
            "-p",
            "test_*.py",
        ],
    ),
)


def main() -> int:
    for label, command in CHECKS:
        print(f"\n==> {label}", flush=True)
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode != 0:
            print(f"\nCheck failed: {label}", file=sys.stderr)
            return result.returncode

    print("\nAll public repository checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
