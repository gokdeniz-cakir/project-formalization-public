from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILLS = {
    "project-formalization": "C-focused formal verification and replay",
    "project-formalization-raw": "general-purpose experiment harness",
}
LEGACY_NAMES = (
    "formal-vulnerability-harness",
    "vulnerability-experiment-harness",
)


def main() -> int:
    failures: list[str] = []
    for name in SKILLS:
        root = ROOT / "skills" / name
        skill_file = root / "SKILL.md"
        if not skill_file.is_file():
            failures.append(f"{name}: missing SKILL.md")
            continue

        if f"name: {name}" not in skill_file.read_text(encoding="utf-8"):
            failures.append(f"{name}: front matter does not declare its directory name")

        for path in root.rglob("*"):
            if path.is_dir() and path.name == "__pycache__":
                # Unit-test execution creates these locally. They are excluded from Git.
                continue
            if not path.is_file():
                continue

            relative = path.relative_to(ROOT).as_posix()
            content = path.read_text(encoding="utf-8", errors="replace")
            for legacy_name in LEGACY_NAMES:
                if legacy_name in content:
                    failures.append(f"{relative}: references legacy skill name {legacy_name}")
            if path.suffix == ".py":
                try:
                    compile(content, str(path), "exec")
                except SyntaxError as error:
                    failures.append(f"{relative}: {error.msg}")

    if failures:
        print("Skill checks failed:", file=sys.stderr)
        print("\n".join(f"- {failure}" for failure in failures), file=sys.stderr)
        return 1

    print("Skill checks passed: current names, complete manifests, and valid Python.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
