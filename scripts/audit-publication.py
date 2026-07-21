from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_CVES = {
    "CVE-2026-10536",
    "CVE-2026-6679",
    "CVE-2026-5460",
    "CVE-2026-7531",
}
TEXT_EXTENSIONS = {
    ".c", ".css", ".html", ".json", ".md", ".py", ".svg", ".toml", ".txt", ".yml", ".yaml",
}
SKIP_PARTS = {".git", ".wrangler", "node_modules", "__pycache__"}
PRIVATE_MARKERS = (
    ".coordinator" + "-private",
    "pending private " + "triage",
    "apparently " + "novel",
    "zero" + "-day",
    "0-" + "day",
    "verify-" + "experiments",
)
WINDOWS_PATH = re.compile(r"[A-Za-z]:[\\/]Users[\\/]", re.IGNORECASE)
CVE = re.compile(r"CVE-\d{4}-\d{4,}")


def is_skipped(path: Path) -> bool:
    return any(part in SKIP_PARTS for part in path.parts)


def main() -> int:
    failures: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or is_skipped(path) or path.suffix.lower() not in TEXT_EXTENSIONS:
            continue

        relative = path.relative_to(ROOT).as_posix()
        content = path.read_text(encoding="utf-8", errors="replace")
        lowered = content.lower()
        is_skill = relative.startswith("skills/")

        if WINDOWS_PATH.search(content):
            failures.append(f"{relative}: contains a local Windows path")
        for marker in PRIVATE_MARKERS:
            if is_skill:
                continue
            if marker in lowered:
                failures.append(f"{relative}: contains a private-research marker")
        for identifier in CVE.findall(content):
            if identifier not in ALLOWED_CVES:
                failures.append(f"{relative}: unapproved identifier {identifier}")

    if failures:
        print("Publication audit failed:", file=sys.stderr)
        print("\n".join(f"- {failure}" for failure in failures), file=sys.stderr)
        return 1

    print("Publication audit passed: public allowlist only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
