#!/usr/bin/env python3
"""Probe C formal-verification tools and record reproducible tool invocations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FORMAL_TOOLS: dict[str, dict[str, Any]] = {
    "cbmc": {"family": "bounded_model_checking", "commands": ["cbmc"]},
    "esbmc": {"family": "bounded_model_checking", "commands": ["esbmc"]},
    "frama-c": {"family": "abstract_interpretation", "alternate_families": ["deductive_verification"], "commands": ["frama-c"]},
    "cpachecker": {"family": "configurable_program_analysis", "commands": ["cpachecker", "cpa.sh"]},
    "symbiotic": {"family": "configurable_program_analysis", "commands": ["symbiotic"]},
    "ultimate": {"family": "configurable_program_analysis", "commands": ["Ultimate.py", "Ultimate"]},
    "seahorn": {"family": "horn_clause_verification", "commands": ["sea"]},
    "2ls": {"family": "configurable_program_analysis", "commands": ["2ls"]},
}

SUPPORT_TOOLS = (
    "gcc",
    "clang",
    "cmake",
    "ninja",
    "z3",
    "cvc5",
    "alt-ergo",
    "why3",
    "valgrind",
)


def decode_output(raw: bytes) -> str:
    if b"\x00" in raw[:64]:
        for encoding in ("utf-16-le", "utf-16", "utf-8"):
            try:
                return raw.decode(encoding).replace("\x00", "")
            except UnicodeDecodeError:
                continue
    return raw.decode("utf-8", errors="replace")


def command_output(command: list[str], timeout: float = 10.0) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    except (FileNotFoundError, OSError) as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        stdout = decode_output(exc.stdout or b"") if isinstance(exc.stdout, bytes) else str(exc.stdout or "")
        stderr = decode_output(exc.stderr or b"") if isinstance(exc.stderr, bytes) else str(exc.stderr or "")
        return 124, stdout, stderr or "command timed out"
    return completed.returncode, decode_output(completed.stdout), decode_output(completed.stderr)


def version_from(command: list[str], timeout: float = 10.0) -> str | None:
    code, stdout, stderr = command_output(command + ["--version"], timeout)
    if code != 0:
        code, stdout, stderr = command_output(command + ["-version"], timeout)
    text = (stdout or stderr).strip()
    return text.splitlines()[0] if text else None


def wsl_version(wsl: str, distro: str, candidate: str) -> str | None:
    command = [wsl, "--distribution", distro, "--", "bash", "-lc", f"{shlex.quote(candidate)} --version"]
    code, stdout, stderr = command_output(command)
    if code != 0:
        code, stdout, stderr = command_output([wsl, "--distribution", distro, "--", "bash", "-lc", f"{shlex.quote(candidate)} -version"])
    text = (stdout or stderr).strip()
    return text.splitlines()[0] if text else None


def native_tool(name: str) -> dict[str, Any]:
    spec = FORMAL_TOOLS[name]
    for candidate in spec["commands"]:
        path = shutil.which(candidate)
        if path:
            command = [path]
            return {
                "name": name,
                "family": spec["family"],
                "available": True,
                "path": path,
                "version": version_from(command),
            }
    return {"name": name, "family": spec["family"], "available": False, "path": None, "version": None}


def wsl_distros() -> list[str]:
    wsl = shutil.which("wsl.exe") or shutil.which("wsl")
    if not wsl:
        return []
    code, stdout, _ = command_output([wsl, "--list", "--quiet"])
    if code != 0:
        return []
    return [line.strip() for line in stdout.splitlines() if line.strip()]


def wsl_tool(distro: str, name: str) -> dict[str, Any]:
    wsl = shutil.which("wsl.exe") or shutil.which("wsl")
    spec = FORMAL_TOOLS[name]
    if not wsl:
        return {"name": name, "family": spec["family"], "available": False, "path": None, "version": None}
    for candidate in spec["commands"]:
        lookup = [wsl, "--distribution", distro, "--", "bash", "-lc", f"command -v {shlex.quote(candidate)}"]
        code, stdout, _ = command_output(lookup)
        path = stdout.strip().splitlines()[0] if code == 0 and stdout.strip() else None
        if path:
            version = wsl_version(wsl, distro, candidate)
            return {
                "name": name,
                "family": spec["family"],
                "available": True,
                "path": path,
                "version": version,
                "distro": distro,
            }
    return {"name": name, "family": spec["family"], "available": False, "path": None, "version": None, "distro": distro}


def support_inventory(environment: str, distro: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in SUPPORT_TOOLS:
        if environment == "native":
            path = shutil.which(name)
            result[name] = {"available": bool(path), "path": path, "version": version_from([path]) if path else None}
        else:
            wsl = shutil.which("wsl.exe") or shutil.which("wsl")
            if not wsl or not distro:
                result[name] = {"available": False, "path": None, "version": None}
                continue
            code, stdout, _ = command_output([wsl, "--distribution", distro, "--", "bash", "-lc", f"command -v {shlex.quote(name)}"])
            path = stdout.strip().splitlines()[0] if code == 0 and stdout.strip() else None
            result[name] = {"available": bool(path), "path": path, "version": wsl_version(wsl, distro, name) if path else None}
    return result


def probe(distros: list[str] | None = None) -> dict[str, Any]:
    selected = distros if distros is not None else wsl_distros()
    result: dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "host": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "cwd": str(Path.cwd()),
        },
        "native": {"formal_tools": [native_tool(name) for name in FORMAL_TOOLS], "support_tools": support_inventory("native")},
        "wsl": [],
    }
    for distro in selected:
        result["wsl"].append({
            "distro": distro,
            "formal_tools": [wsl_tool(distro, name) for name in FORMAL_TOOLS],
            "support_tools": support_inventory("wsl", distro),
        })
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def shell_command(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def effective_command(args: list[str], environment: str, distro: str | None, cwd: str | None) -> list[str]:
    if environment == "native":
        return args
    if not distro:
        raise ValueError("--distro is required for --environment wsl")
    wsl = shutil.which("wsl.exe") or shutil.which("wsl")
    if not wsl:
        raise ValueError("wsl.exe is not available")
    prefix = [wsl, "--distribution", distro]
    if cwd:
        prefix += ["--cd", cwd]
    return prefix + ["--"] + args


def run_recorded(tool: str, family: str, args: list[str], output_dir: Path, environment: str, distro: str | None, cwd: str | None) -> int:
    if tool not in FORMAL_TOOLS:
        raise ValueError(f"unknown formal tool: {tool}")
    allowed_families = {FORMAL_TOOLS[tool]["family"], *FORMAL_TOOLS[tool].get("alternate_families", [])}
    if family not in allowed_families:
        raise ValueError(f"tool {tool} supports {', '.join(sorted(allowed_families))}, not {family}")
    if not args:
        raise ValueError("a formal command is required after --")
    output_dir.mkdir(parents=True, exist_ok=True)
    command = effective_command(args, environment, distro, cwd)
    start = time.monotonic()
    completed = subprocess.run(command, capture_output=True, text=False, check=False, cwd=cwd if environment == "native" else None)
    duration = time.monotonic() - start
    stdout_path = output_dir / "stdout.log"
    stderr_path = output_dir / "stderr.log"
    stdout_path.write_bytes(completed.stdout)
    stderr_path.write_bytes(completed.stderr)
    receipt = {
        "schema_version": "1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "family": family,
        "environment": environment,
        "distro": distro,
        "cwd": cwd,
        "command": args,
        "effective_command": command,
        "exit_code": completed.returncode,
        "duration_seconds": round(duration, 3),
        "stdout": {"path": stdout_path.name, "sha256": sha256_file(stdout_path)},
        "stderr": {"path": stderr_path.name, "sha256": sha256_file(stderr_path)},
    }
    (output_dir / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return completed.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    probe_parser = sub.add_parser("probe", help="discover formal and supporting C tools")
    probe_parser.add_argument("--distro", action="append", help="probe only this WSL distro; repeatable")
    probe_parser.add_argument("--json", action="store_true", help="emit JSON")

    run_parser = sub.add_parser("run", help="run a formal command and write a receipt")
    run_parser.add_argument("--tool", required=True, choices=sorted(FORMAL_TOOLS))
    run_parser.add_argument("--family", required=True, choices=sorted({spec["family"] for spec in FORMAL_TOOLS.values()}))
    run_parser.add_argument("--environment", choices=("native", "wsl"), default="native")
    run_parser.add_argument("--distro")
    run_parser.add_argument("--cwd")
    run_parser.add_argument("--output-dir", type=Path, required=True)
    run_parser.add_argument("command_args", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "probe":
            data = probe(args.distro)
            print(json.dumps(data, indent=2, sort_keys=True))
            return 0
        command_args = list(args.command_args)
        if command_args and command_args[0] == "--":
            command_args = command_args[1:]
        return run_recorded(args.tool, args.family, command_args, args.output_dir, args.environment, args.distro, args.cwd)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
