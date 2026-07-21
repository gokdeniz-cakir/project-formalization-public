#!/usr/bin/env python3
"""Deterministic helpers for independent general-purpose experiment harnesses."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by the host environment
    raise SystemExit("PyYAML is required: python -m pip install PyYAML") from exc


SKILL_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_ROOT = SKILL_ROOT / "assets" / "templates"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
SUPPORTED_SCHEMAS = {"1.0", "1.1"}
FORBIDDEN_BASELINE_KEYS = {
    "advisory",
    "advisory_url",
    "cve",
    "cve_id",
    "expected_bug",
    "fix_commit",
    "known_mechanism",
    "known_reproducer",
    "known_vulnerability",
    "patch",
    "patch_url",
    "retrospective_ground_truth",
}
VERDICTS = {
    "confirmed_violation",
    "formal_only_candidate",
    "bounded_satisfaction",
    "unknown",
}
CAUSES = {
    "production_defect",
    "harness_fidelity_artifact",
    "contract_misuse_unresolved",
    "not_applicable",
    "unknown",
}
SOURCE_DIRS = {"subject", "upstream", "source", "vendor"}
ARCHIVE_SUFFIXES = (
    ".7z",
    ".bz2",
    ".gz",
    ".rar",
    ".tar",
    ".tar.bz2",
    ".tar.gz",
    ".tar.xz",
    ".tgz",
    ".xz",
    ".zip",
)


class HarnessError(RuntimeError):
    pass


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HarnessError(f"file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise HarnessError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise HarnessError(f"YAML root must be a mapping: {path}")
    return data


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=False),
        encoding="utf-8",
        newline="\n",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def nested(data: dict[str, Any], dotted: str, default: Any = None) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def require_nonempty(errors: list[str], data: dict[str, Any], dotted: str) -> None:
    value = nested(data, dotted)
    if value is None or value == "" or value == [] or value == {}:
        errors.append(f"missing or empty field: {dotted}")


def require_bool_true(errors: list[str], data: dict[str, Any], dotted: str) -> None:
    if nested(data, dotted) is not True:
        errors.append(f"field must be true: {dotted}")


def validate_hash(errors: list[str], value: Any, label: str) -> None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        errors.append(f"{label} must be a lowercase SHA-256 digest")


def safe_relative_path(value: str, label: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or str(path) in {"", "."}:
        raise HarnessError(f"{label} must be a non-empty relative path without '..': {value}")
    return path


def iter_keys(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            name = str(key)
            dotted = f"{prefix}.{name}" if prefix else name
            yield dotted, child
            yield from iter_keys(child, dotted)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_keys(child, f"{prefix}[{index}]")


def workflow_profile(data: dict[str, Any]) -> str:
    default = "audit" if str(data.get("schema_version")) == "1.0" else "agile"
    return str(nested(data, "workflow.profile", default))


def validate_freeze(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if str(data.get("schema_version")) not in SUPPORTED_SCHEMAS:
        errors.append("schema_version must be '1.0' or '1.1'")
    profile = workflow_profile(data)
    if profile not in {"production", "agile", "audit"}:
        errors.append("workflow.profile must be production, agile, or audit")
    if profile == "audit":
        require_bool_true(errors, data, "freeze.confirmed")
        require_nonempty(errors, data, "freeze.confirmed_at")
        require_nonempty(errors, data, "freeze.confirmed_by")
    for field in (
        "experiment.id",
        "experiment.mode",
        "project.name",
        "project.upstream_url",
        "project.version",
        "project.commit",
        "source.cache_key",
        "target.component",
        "target.production_boundary",
        "target.included_files",
        "properties",
        "tooling.formal.name",
        "tooling.runtime.oracle",
        "agents.model",
        "agents.knowledge_cutoff",
        "agents.reasoning_effort",
        "agents.framing",
        "network.policy",
        "network.forbidden_sources",
        "repository.destination",
        "repository.remote_policy",
        "repository.source_policy",
    ):
        require_nonempty(errors, data, field)

    if nested(data, "experiment.expected_verdict", "missing") is not None:
        errors.append("experiment.expected_verdict must be null")
    if nested(data, "experiment.mode") not in {"prospective", "retrospective"}:
        errors.append("experiment.mode must be prospective or retrospective")
    network_policy = nested(data, "network.policy")
    if network_policy not in {"asymmetric", "open_unmonitored", "broad_audited", "offline"}:
        errors.append("network.policy must be asymmetric, open_unmonitored, broad_audited, or offline")
    audit_required = nested(data, "network.audit_required")
    if audit_required not in {True, False}:
        errors.append("network.audit_required must be boolean")
    elif profile == "production":
        if network_policy != "asymmetric" or not audit_required:
            errors.append("production profile requires asymmetric network with audit_required=true")
        if nested(data, "network.arm_policies.investigator_a") != "target_restricted_audited":
            errors.append("production investigator A must use target_restricted_audited")
        if nested(data, "network.arm_policies.investigator_b") != "open_unmonitored":
            errors.append("production investigator B must use open_unmonitored")
        if nested(data, "experiment.mode") != "prospective":
            errors.append("production profile requires experiment.mode=prospective")
    elif network_policy in {"asymmetric", "open_unmonitored"}:
        errors.append("asymmetric and open_unmonitored policies are reserved for production arm configuration")
    elif not audit_required:
        errors.append("agile and audit profiles require network.audit_required=true")
    if nested(data, "repository.remote_policy") not in {"local_only", "private_baseline_once"}:
        errors.append("repository.remote_policy must be local_only or private_baseline_once")
    if nested(data, "repository.source_policy") not in {"exact_commit", "pins_only"}:
        errors.append("repository.source_policy must be exact_commit or pins_only")

    commit = nested(data, "project.commit")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        errors.append("project.commit must be an exact 40-character commit hash")
    if commit == "0" * 40:
        errors.append("project.commit is still the template placeholder")
    archive_url = nested(data, "source.archive_url")
    archive_hash = nested(data, "source.archive_sha256")
    if archive_url or archive_hash:
        if not archive_url:
            errors.append("source.archive_url is required when archive_sha256 is set")
        validate_hash(errors, archive_hash, "source.archive_sha256")
        if archive_hash == "0" * 64:
            errors.append("source.archive_sha256 is still the template placeholder")

    placeholder_values = {
        "project.upstream_url": ("example.invalid",),
        "source.archive_url": ("example.invalid",),
        "target.component": ("bounded component",),
        "agents.model": ("exact-model-id",),
        "agents.knowledge_cutoff": ("yyyy-mm",),
        "agents.reasoning_effort": ("exact-effort",),
        "repository.destination": ("absolute/path/to/new-harness",),
    }
    for field, markers in placeholder_values.items():
        value = str(nested(data, field, "")).lower()
        if any(marker in value for marker in markers):
            errors.append(f"{field} is still a template placeholder")
    for field in ("tooling.formal.build_command", "tooling.formal.analyze_command"):
        value = nested(data, field)
        if value and "replace with" in str(value).lower():
            errors.append(f"{field} is still a template placeholder")

    commands = nested(data, "source.acquisition_commands")
    if not isinstance(commands, dict):
        errors.append("source.acquisition_commands must be a mapping")
    else:
        usable_shells: list[str] = []
        for shell in ("powershell", "posix"):
            items = commands.get(shell, [])
            if items is None:
                items = []
            if not isinstance(items, list) or not all(isinstance(item, str) and item.strip() for item in items):
                errors.append(f"source.acquisition_commands.{shell} must be a string list")
            elif items:
                usable_shells.append(shell)
                if any("replace with" in item.lower() for item in items):
                    errors.append(f"source.acquisition_commands.{shell} still contains a template placeholder")
        if not usable_shells:
            errors.append("source.acquisition_commands needs one usable host shell")
        setup_shell = nested(data, "repository.setup_shell")
        if setup_shell and setup_shell not in usable_shells:
            errors.append(f"repository.setup_shell={setup_shell} has no acquisition commands")

    receipt = nested(data, "source.verification_receipt")
    if receipt:
        try:
            safe_relative_path(str(receipt), "source.verification_receipt")
        except HarnessError as exc:
            errors.append(str(exc))

    inventory = nested(data, "source.scope_inventory")
    if not isinstance(inventory, list):
        errors.append("source.scope_inventory must be a list")
    else:
        for index, item in enumerate(inventory):
            if not isinstance(item, dict):
                errors.append(f"source.scope_inventory[{index}] must be a mapping")
                continue
            try:
                safe_relative_path(str(item.get("path", "")), f"source.scope_inventory[{index}].path")
            except HarnessError as exc:
                errors.append(str(exc))
            if item.get("sha256"):
                validate_hash(errors, item.get("sha256"), f"source.scope_inventory[{index}].sha256")

    properties = data.get("properties")
    if isinstance(properties, list):
        for index, item in enumerate(properties):
            if not isinstance(item, dict):
                errors.append(f"properties[{index}] must be a mapping")
                continue
            for key in ("id", "statement"):
                if not item.get(key):
                    errors.append(f"properties[{index}].{key} is required")

    baseline_files = data.get("baseline_files", [])
    if not isinstance(baseline_files, list):
        errors.append("baseline_files must be a list")
    else:
        for index, item in enumerate(baseline_files):
            if not isinstance(item, dict):
                errors.append(f"baseline_files[{index}] must be a mapping")
                continue
            source = Path(str(item.get("source", "")))
            if not source.is_absolute():
                errors.append(f"baseline_files[{index}].source must be absolute")
            try:
                destination = safe_relative_path(
                    str(item.get("destination", "")), f"baseline_files[{index}].destination"
                )
                if destination.parts[0].lower() in SOURCE_DIRS:
                    errors.append(f"baseline_files[{index}] may not place source bytes under {destination.parts[0]}/")
            except HarnessError as exc:
                errors.append(str(exc))
            validate_hash(errors, item.get("sha256"), f"baseline_files[{index}].sha256")
            if not item.get("role"):
                errors.append(f"baseline_files[{index}].role is required")
            elif item.get("role") not in {"specification", "license", "harness_input"}:
                errors.append(f"baseline_files[{index}].role must be specification, license, or harness_input")

    forbidden_text = " ".join(str(item).lower() for item in nested(data, "network.forbidden_sources", []))
    required_forbidden_concepts = ("sibling",) if profile == "production" else ("cve", "advis", "patch", "sibling")
    for concept in required_forbidden_concepts:
        if concept not in forbidden_text:
            errors.append(f"network.forbidden_sources must explicitly cover {concept}")

    remote_policy = nested(data, "repository.remote_policy")
    remote_url = nested(data, "repository.remote_url")
    if remote_policy == "local_only" and remote_url:
        errors.append("repository.remote_url must be null for local_only")
    if remote_policy == "private_baseline_once" and not remote_url:
        errors.append("repository.remote_url is required for private_baseline_once")
    if remote_policy == "private_baseline_once" and nested(data, "repository.push_lock_required") is not True:
        errors.append("private_baseline_once requires repository.push_lock_required=true")

    serialized = yaml.safe_dump(data, sort_keys=True)
    if CVE_RE.search(serialized):
        errors.append("freeze manifest contains a CVE identifier")
    for dotted, _ in iter_keys(data):
        key = dotted.rsplit(".", 1)[-1].split("[", 1)[0].lower().replace("-", "_")
        if key in FORBIDDEN_BASELINE_KEYS:
            errors.append(f"coordinator ground-truth key is forbidden: {dotted}")
    return sorted(set(errors))


def sanitized_baseline(freeze: dict[str, Any], copied_pins: list[dict[str, str]]) -> dict[str, Any]:
    source = freeze["source"]
    acquisition_scripts: dict[str, str] = {}
    commands = source.get("acquisition_commands", {})
    if commands.get("powershell"):
        acquisition_scripts["powershell"] = "scripts/acquire-source.ps1"
    if commands.get("posix"):
        acquisition_scripts["posix"] = "scripts/acquire-source.sh"
    profile = workflow_profile(freeze)
    baseline_workflow = dict(freeze.get("workflow", {"profile": profile}))
    baseline_network = dict(freeze["network"])
    if profile == "production":
        # Do not reveal that the revision is current production or expose the
        # other arm's framing. Each investigator receives its policy by prompt.
        baseline_workflow["profile"] = "prospective"
        baseline_network = {
            "policy": "per_prompt",
            "forbidden_sources": list(freeze["network"]["forbidden_sources"]),
        }
    return {
        "schema_version": str(freeze.get("schema_version", "1.1")),
        "workflow": baseline_workflow,
        "experiment": {
            "id": freeze["experiment"]["id"],
            "mode": freeze["experiment"]["mode"],
            "expected_verdict": None,
        },
        "project": dict(freeze["project"]),
        "source": {
            "archive_url": source.get("archive_url"),
            "archive_sha256": source.get("archive_sha256"),
            "signature_url": source.get("signature_url"),
            "signer_fingerprint": source.get("signer_fingerprint"),
            "provenance_note": source.get("provenance_note", source.get("provenance_limitation")),
            "cache_key": source["cache_key"],
            "verification_receipt": source.get("verification_receipt"),
            "acquisition_scripts": acquisition_scripts,
            "scope_inventory": source.get("scope_inventory", []),
        },
        "target": freeze["target"],
        "properties": freeze["properties"],
        "tooling": freeze["tooling"],
        "agents": {
            "model": freeze["agents"]["model"],
            "knowledge_cutoff": freeze["agents"]["knowledge_cutoff"],
            "reasoning_effort": freeze["agents"]["reasoning_effort"],
            "tool_environment": freeze["agents"]["tool_environment"],
            "prompt_delivery": "coordinator_out_of_band",
            "direct_spawn": True,
            "fork_turns": "none",
        },
        "network": baseline_network,
        "repository": {
            "remote_policy": freeze["repository"]["remote_policy"],
            "source_policy": freeze["repository"].get("source_policy", "exact_commit"),
            "push_lock_required": bool(freeze["repository"].get("push_lock_required", False)),
        },
        "isolation": {
            "separate_workspaces": True,
            "no_sibling_access": True,
            "prompts_out_of_band": True,
            "ground_truth_post_result_only": True,
        },
        "pins": {"files": copied_pins},
    }


def template_text(relative: str) -> str:
    return (TEMPLATE_ROOT / relative).read_text(encoding="utf-8")


def replace_tokens(text: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def render_acquisition_script(commands: list[str], shell: str) -> str:
    if shell == "powershell":
        header = (
            "param(\n"
            "  [Parameter(Mandatory=$true)][string]$SourceRoot,\n"
            "  [Parameter(Mandatory=$true)][string]$CacheRoot\n"
            ")\n"
            "$ErrorActionPreference = 'Stop'\n"
            "$env:FVH_SOURCE_ROOT = $SourceRoot\n"
            "$env:FVH_CACHE_ROOT = $CacheRoot\n"
        )
    else:
        header = (
            "#!/bin/sh\n"
            "set -eu\n"
            "FVH_SOURCE_ROOT=${1:?source root required}\n"
            "FVH_CACHE_ROOT=${2:?cache root required}\n"
            "export FVH_SOURCE_ROOT FVH_CACHE_ROOT\n"
        )
    return header + "\n".join(commands) + "\n"


def render_baseline(freeze_path: Path, destination: Path) -> dict[str, Any]:
    freeze = load_yaml(freeze_path)
    errors = validate_freeze(freeze)
    if errors:
        raise HarnessError("freeze validation failed:\n- " + "\n- ".join(errors))

    expected_destination = Path(str(nested(freeze, "repository.destination"))).resolve()
    if destination.resolve() != expected_destination:
        raise HarnessError(
            f"destination does not match experiment brief: {destination.resolve()} != {expected_destination}"
        )
    if destination.exists() and any(destination.iterdir()):
        raise HarnessError(f"destination must not exist or must be empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "scripts").mkdir()

    copied_pins: list[dict[str, str]] = []
    for item in freeze.get("baseline_files", []):
        source = Path(item["source"])
        if not source.is_file():
            raise HarnessError(f"baseline input is missing: {source}")
        actual = sha256_file(source)
        if actual != item["sha256"]:
            raise HarnessError(f"baseline input hash mismatch: {source}")
        relative = safe_relative_path(item["destination"], "baseline file destination")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied_pins.append(
            {"path": relative.as_posix(), "sha256": actual, "role": str(item["role"])}
        )

    project = freeze["project"]
    target = freeze["target"]
    tokens = {
        "PROJECT": str(project["name"]),
        "VERSION": str(project["version"]),
        "COMMIT": str(project["commit"]),
        "COMPONENT": str(target["component"]),
    }
    (destination / "README.md").write_text(
        replace_tokens(template_text("baseline/README.md.tmpl"), tokens), encoding="utf-8", newline="\n"
    )
    (destination / "AGENTS.md").write_text(
        template_text("baseline/AGENTS.md.tmpl"), encoding="utf-8", newline="\n"
    )
    (destination / ".gitignore").write_text(
        template_text("baseline/gitignore.tmpl"), encoding="utf-8", newline="\n"
    )
    (destination / "scripts" / "pre-push").write_text(
        template_text("baseline/pre-push.tmpl"), encoding="utf-8", newline="\n"
    )
    acquisition = freeze["source"]["acquisition_commands"]
    powershell_commands = acquisition.get("powershell") or []
    if powershell_commands:
        (destination / "scripts" / "acquire-source.ps1").write_text(
            render_acquisition_script(powershell_commands, "powershell"), encoding="utf-8", newline="\n"
        )
    posix_script = destination / "scripts" / "acquire-source.sh"
    posix_commands = acquisition.get("posix") or []
    if posix_commands:
        posix_script.write_text(
            render_acquisition_script(posix_commands, "posix"), encoding="utf-8", newline="\n"
        )
    try:
        if posix_script.exists():
            posix_script.chmod(0o755)
        (destination / "scripts" / "pre-push").chmod(0o755)
    except OSError:
        pass

    baseline = sanitized_baseline(freeze, copied_pins)
    write_yaml(destination / "experiment.yml", baseline)
    return {"destination": str(destination.resolve()), "files": sorted(str(p.relative_to(destination)) for p in destination.rglob("*") if p.is_file())}


def tracked_or_present_files(repo: Path) -> list[Path]:
    if (repo / ".git").exists():
        result = run(["git", "-C", str(repo), "ls-files", "-z"], check=False)
        if result.returncode == 0:
            return [repo / item for item in result.stdout.split("\0") if item]
    return [path for path in repo.rglob("*") if path.is_file() and ".git" not in path.parts]


def validate_baseline(repo: Path) -> list[str]:
    errors: list[str] = []
    manifest_path = repo / "experiment.yml"
    try:
        data = load_yaml(manifest_path)
    except HarnessError as exc:
        return [str(exc)]

    if str(data.get("schema_version")) not in SUPPORTED_SCHEMAS:
        errors.append("schema_version must be '1.0' or '1.1'")
    profile = workflow_profile(data)
    if profile not in {"prospective", "agile", "audit"}:
        errors.append("workflow.profile must be prospective, agile, or audit")
    for field in (
        "experiment.id",
        "experiment.mode",
        "project.name",
        "project.upstream_url",
        "project.version",
        "project.commit",
        "source.cache_key",
        "target.component",
        "target.production_boundary",
        "target.included_files",
        "properties",
        "tooling.formal.name",
        "tooling.runtime.oracle",
        "agents.model",
        "agents.knowledge_cutoff",
        "agents.reasoning_effort",
        "network.forbidden_sources",
        "repository.remote_policy",
    ):
        require_nonempty(errors, data, field)
    if not isinstance(nested(data, "pins.files"), list):
        errors.append("pins.files must be a list")
    if nested(data, "experiment.expected_verdict", "missing") is not None:
        errors.append("experiment.expected_verdict must be null")
    if nested(data, "experiment.mode") not in {"prospective", "retrospective"}:
        errors.append("experiment.mode must be prospective or retrospective")
    if nested(data, "repository.source_policy") not in {"exact_commit", "pins_only"}:
        errors.append("repository.source_policy must be exact_commit or pins_only")
    for field in (
        "agents.direct_spawn",
        "isolation.no_sibling_access",
        "isolation.prompts_out_of_band",
    ):
        require_bool_true(errors, data, field)
    network_policy = nested(data, "network.policy")
    audit_required = nested(data, "network.audit_required")
    if network_policy not in {"per_prompt", "broad_audited", "offline"}:
        errors.append("baseline network.policy must be per_prompt, broad_audited, or offline")
    if profile == "prospective":
        if nested(data, "experiment.mode") != "prospective":
            errors.append("prospective profile requires experiment.mode=prospective")
        if network_policy != "per_prompt":
            errors.append("prospective profile requires network.policy=per_prompt")
    else:
        if audit_required not in {True, False}:
            errors.append("network.audit_required must be boolean")
        elif not audit_required:
            errors.append("historically blind profiles require network.audit_required=true")
    forbidden_text = " ".join(str(item).lower() for item in nested(data, "network.forbidden_sources", []))
    required_forbidden_concepts = ("sibling",) if profile == "prospective" else ("cve", "advis", "patch", "sibling")
    for concept in required_forbidden_concepts:
        if concept not in forbidden_text:
            errors.append(f"network.forbidden_sources must explicitly cover {concept}")
    ground_truth_locked = nested(data, "isolation.ground_truth_post_result_only") is True or nested(
        data, "isolation.ground_truth_post_seal_only"
    ) is True
    if not ground_truth_locked:
        errors.append("ground truth must remain hidden until both results finish")
    if nested(data, "agents.fork_turns") != "none":
        errors.append("agents.fork_turns must be 'none'")
    if nested(data, "agents.prompt_delivery") != "coordinator_out_of_band":
        errors.append("agents.prompt_delivery must be coordinator_out_of_band")

    archive_hash = nested(data, "source.archive_sha256")
    if archive_hash:
        validate_hash(errors, archive_hash, "source.archive_sha256")
    commit = nested(data, "project.commit")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        errors.append("project.commit must be an exact 40-character commit hash")
    elif commit == "0" * 40:
        errors.append("project.commit may not be the all-zero placeholder")
    if archive_hash == "0" * 64:
        errors.append("source.archive_sha256 may not be the all-zero placeholder")

    for dotted, _ in iter_keys(data):
        key = dotted.rsplit(".", 1)[-1].split("[", 1)[0].lower().replace("-", "_")
        if key in FORBIDDEN_BASELINE_KEYS:
            errors.append(f"ground-truth key is forbidden in baseline: {dotted}")
    if CVE_RE.search(yaml.safe_dump(data, sort_keys=True)):
        errors.append("baseline contains a CVE identifier")

    inventory = nested(data, "source.scope_inventory", [])
    if isinstance(inventory, list):
        for index, item in enumerate(inventory):
            if not isinstance(item, dict):
                errors.append(f"source.scope_inventory[{index}] must be a mapping")
                continue
            try:
                safe_relative_path(str(item.get("path", "")), f"source.scope_inventory[{index}].path")
            except HarnessError as exc:
                errors.append(str(exc))
            if item.get("sha256"):
                validate_hash(errors, item.get("sha256"), f"source.scope_inventory[{index}].sha256")

    for path in tracked_or_present_files(repo):
        try:
            relative = path.relative_to(repo)
        except ValueError:
            continue
        lowered = relative.as_posix().lower()
        if relative.parts and relative.parts[0].lower() in SOURCE_DIRS:
            errors.append(f"upstream source bytes may not be committed: {relative.as_posix()}")
        if lowered.endswith(ARCHIVE_SUFFIXES):
            errors.append(f"upstream archives may not be committed: {relative.as_posix()}")
        if path.stat().st_size <= 2 * 1024 * 1024:
            try:
                content = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            match = CVE_RE.search(content)
            if match:
                errors.append(f"CVE identifier found in baseline file {relative.as_posix()}: {match.group(0)}")
    return sorted(set(errors))


def verify_pins(repo: Path, source_root: Path | None) -> dict[str, Any]:
    baseline_errors = validate_baseline(repo)
    if baseline_errors:
        raise HarnessError("baseline validation failed:\n- " + "\n- ".join(baseline_errors))
    data = load_yaml(repo / "experiment.yml")
    checked: list[dict[str, str]] = []

    for index, item in enumerate(nested(data, "pins.files", [])):
        relative = safe_relative_path(str(item.get("path", "")), f"pins.files[{index}].path")
        path = repo / relative
        if not path.is_file():
            raise HarnessError(f"pinned baseline file missing: {relative.as_posix()}")
        actual = sha256_file(path)
        if actual != item.get("sha256"):
            raise HarnessError(f"pinned baseline file hash mismatch: {relative.as_posix()}")
        checked.append({"path": relative.as_posix(), "sha256": actual, "kind": "baseline"})

    source_checked = False
    if source_root is not None:
        source_root = source_root.resolve()
        if not source_root.is_dir():
            raise HarnessError(f"source root does not exist: {source_root}")
        expected_commit = str(nested(data, "project.commit")).lower()
        git_result = run(["git", "-C", str(source_root), "rev-parse", "HEAD"], check=False)
        git_commit_verified = git_result.returncode == 0 and git_result.stdout.strip().lower() == expected_commit

        receipt = None
        receipt_name = nested(data, "source.verification_receipt")
        if receipt_name:
            receipt_relative = safe_relative_path(str(receipt_name), "source.verification_receipt")
            receipt_path = source_root / receipt_relative
            if receipt_path.is_file():
                receipt = load_yaml(receipt_path)
        if receipt is None and not git_commit_verified:
            raise HarnessError("source must be an exact Git checkout or contain a verification receipt")
        if receipt is not None:
            if receipt.get("acquisition_completed") is not True:
                raise HarnessError("source verification receipt is incomplete")
            if str(receipt.get("project_commit", "")).lower() != expected_commit:
                raise HarnessError("source verification receipt commit does not match project.commit")
            archive_hash = nested(data, "source.archive_sha256")
            if archive_hash and receipt.get("archive_sha256") != archive_hash:
                raise HarnessError("source verification receipt archive digest does not match the baseline")
            signature_url = nested(data, "source.signature_url")
            signer = nested(data, "source.signer_fingerprint")
            if signature_url and signer:
                if receipt.get("signature_verified") is not True:
                    raise HarnessError("source verification receipt does not confirm the required signature")
                actual_signer = str(receipt.get("signer_fingerprint", "")).replace(" ", "").lower()
                expected_signer = str(signer).replace(" ", "").lower()
                if actual_signer != expected_signer:
                    raise HarnessError("source verification receipt signer fingerprint does not match")
        for index, item in enumerate(nested(data, "source.scope_inventory", [])):
            relative = safe_relative_path(str(item.get("path", "")), f"source.scope_inventory[{index}].path")
            path = source_root / relative
            if not path.is_file():
                raise HarnessError(f"pinned source file missing: {relative.as_posix()}")
            actual = sha256_file(path)
            expected_hash = item.get("sha256")
            if expected_hash and actual != expected_hash:
                raise HarnessError(f"pinned source file hash mismatch: {relative.as_posix()}")
            checked.append({"path": relative.as_posix(), "sha256": actual, "kind": "source"})
        if git_result.returncode == 0 and not git_commit_verified:
            raise HarnessError("materialized source commit does not match project.commit")
        source_checked = True
    return {"ok": True, "source_checked": source_checked, "checked": checked}


def validate_artifacts(data: dict[str, Any], root: Path, errors: list[str], require_hash: bool = False) -> None:
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("artifacts must be a list")
        return
    for index, item in enumerate(artifacts):
        if not isinstance(item, dict):
            errors.append(f"artifacts[{index}] must be a mapping")
            continue
        try:
            relative = safe_relative_path(str(item.get("path", "")), f"artifacts[{index}].path")
        except HarnessError as exc:
            errors.append(str(exc))
            continue
        declared_hash = item.get("sha256")
        if require_hash or declared_hash:
            validate_hash(errors, declared_hash, f"artifacts[{index}].sha256")
        path = root / relative
        try:
            path.resolve().relative_to(root.resolve())
        except ValueError:
            errors.append(f"artifact escapes result root: {relative.as_posix()}")
            continue
        if not path.is_file():
            errors.append(f"artifact file missing: {relative.as_posix()}")
        elif SHA256_RE.fullmatch(str(declared_hash or "")) and sha256_file(path) != declared_hash:
            errors.append(f"artifact hash mismatch: {relative.as_posix()}")


def validate_artifact_references(data: dict[str, Any], errors: list[str]) -> None:
    inventory = {
        item.get("path")
        for item in data.get("artifacts", [])
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    references: list[tuple[str, Any]] = []
    for index, value in enumerate(nested(data, "formal.logs", [])):
        references.append((f"formal.logs[{index}]", value))
    if nested(data, "formal.trace"):
        references.append(("formal.trace", nested(data, "formal.trace")))
    if nested(data, "replay.witness.oracle_output"):
        references.append(("replay.witness.oracle_output", nested(data, "replay.witness.oracle_output")))
    for label, value in references:
        if value not in inventory:
            errors.append(f"{label} must reference a hashed artifact entry: {value}")


def mechanism_requirements(kind: str) -> set[str]:
    return {
        "uaf": {"allocation", "free", "use"},
        "oob": {"allocation", "bounds", "access"},
        "leak": {"allocation", "lost_reachability"},
        "double_free": {"allocation", "free", "second_free"},
        "invalid_free": {"invalid_free"},
    }.get(kind, set())


def validate_result(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    if str(data.get("schema_version")) not in SUPPORTED_SCHEMAS:
        errors.append("schema_version must be '1.0' or '1.1'")
    if data.get("investigator") not in {"a", "b"}:
        errors.append("investigator must be a or b")
    baseline_commit = data.get("baseline_commit")
    if not isinstance(baseline_commit, str) or not COMMIT_RE.fullmatch(baseline_commit):
        errors.append("baseline_commit must be an exact 40-character commit hash")
    elif baseline_commit == "0" * 40:
        errors.append("baseline_commit may not be the all-zero placeholder")
    snapshot_digest = data.get("snapshot_digest")
    if snapshot_digest:
        validate_hash(errors, snapshot_digest, "snapshot_digest")
        if snapshot_digest == "0" * 64:
            errors.append("snapshot_digest may not be the all-zero placeholder")
    verdict = data.get("verdict")
    if verdict not in VERDICTS:
        errors.append("verdict must be confirmed_violation, formal_only_candidate, bounded_satisfaction, or unknown")
    if data.get("cause_assessment") not in CAUSES:
        errors.append("cause_assessment is invalid")
    for field in (
        "claim_scope",
        "formal.status",
        "limitations",
        "independence.declaration",
    ):
        require_nonempty(errors, data, field)
    for field in ("formal.commands", "formal.exit_codes", "formal.property_ids", "formal.logs", "formal.production_units", "formal.models", "formal.stubs", "formal.assumptions", "residuals", "independence.incidents"):
        if not isinstance(nested(data, field, []), list):
            errors.append(f"{field} must be a list")
    network_accesses = nested(data, "independence.relevant_network_accesses", nested(data, "independence.network_accesses", []))
    if not isinstance(network_accesses, list):
        errors.append("independence.relevant_network_accesses must be a list")
    require_bool_true(errors, data, "independence.no_sibling_access")
    forbidden_access = nested(data, "independence.forbidden_source_access")
    isolation_status = nested(data, "independence.isolation_status")
    incidents = nested(data, "independence.incidents", [])
    if forbidden_access not in {True, False}:
        errors.append("independence.forbidden_source_access must be boolean")
    elif forbidden_access:
        if isolation_status != "compromised" or not incidents:
            errors.append("forbidden source access requires isolation_status=compromised and a recorded incident")
    elif isolation_status != "clean":
        errors.append("clean forbidden-source declaration requires isolation_status=clean")
    if not isinstance(data.get("artifacts", []), list):
        errors.append("artifacts must be a list")

    formal_status = nested(data, "formal.status")
    replay_status = nested(data, "replay.status")
    limitations = data.get("limitations")
    residuals = data.get("residuals")
    if formal_status not in {"violated", "satisfied", "unknown", "tool_failure"}:
        errors.append("formal.status must be violated, satisfied, unknown, or tool_failure")
    if replay_status not in {"confirmed", "failed", "not_attempted", "unresolved"}:
        errors.append("replay.status must be confirmed, failed, not_attempted, or unresolved")
    commands = nested(data, "formal.commands", [])
    exit_codes = nested(data, "formal.exit_codes", [])
    if isinstance(commands, list) and isinstance(exit_codes, list) and len(commands) != len(exit_codes):
        errors.append("formal.commands and formal.exit_codes must have equal lengths")
    placeholder_fields = {
        "claim_scope": "concise statement",
    }
    for field, marker in placeholder_fields.items():
        if marker in str(nested(data, field, "")).lower():
            errors.append(f"{field} is still a template placeholder")
    if isinstance(limitations, list) and any("state the decisive" in str(item).lower() for item in limitations):
        errors.append("limitations still contains a template placeholder")

    if verdict == "confirmed_violation":
        for field in (
            "snapshot_digest",
            "formal.tool",
            "formal.version",
            "formal.commands",
            "formal.exit_codes",
            "formal.property_ids",
            "formal.logs",
            "formal.production_units",
            "formal.bounds",
        ):
            require_nonempty(errors, data, field)
        if formal_status != "violated":
            errors.append("confirmed_violation requires formal.status=violated")
        if replay_status != "confirmed":
            errors.append("confirmed_violation requires replay.status=confirmed")
        for field in ("replay.fresh_unmodified_build", "replay.pin_check", "replay.checker_sanity.passed", "mechanism.complete"):
            require_bool_true(errors, data, field)
        for field in (
            "formal.trace",
            "replay.build_command",
            "replay.linkage_evidence",
            "replay.source_hashes",
            "replay.witness.command",
            "replay.witness.oracle_output",
            "replay.checker_sanity.command",
            "replay.checker_sanity.evidence",
            "mechanism.kind",
            "mechanism.rationale",
            "mechanism.events",
        ):
            require_nonempty(errors, data, field)
        if nested(data, "replay.witness.successful_runs", 0) < 1:
            errors.append("confirmed_violation requires at least one successful witness run")
        controls = nested(data, "replay.negative_controls", [])
        if not isinstance(controls, list) or not any(
            isinstance(item, dict) and item.get("closest_match") is True and item.get("passed") is True and item.get("command")
            for item in controls
        ):
            errors.append("confirmed_violation requires a passing closest matched negative control")
        events = nested(data, "mechanism.events", [])
        event_kinds = {item.get("kind") for item in events if isinstance(item, dict)}
        kind = str(nested(data, "mechanism.kind", ""))
        required = mechanism_requirements(kind)
        if required and not required.issubset(event_kinds):
            errors.append(f"mechanism {kind} requires events: {', '.join(sorted(required))}")
        if not required and (len(event_kinds) < 2 or not nested(data, "mechanism.rationale")):
            errors.append("other mechanisms require at least two event kinds and a rationale")
        for index, event in enumerate(events if isinstance(events, list) else []):
            if not isinstance(event, dict) or not event.get("kind") or not event.get("location"):
                errors.append(f"mechanism.events[{index}] requires kind and location")
        if data.get("cause_assessment") != "production_defect":
            errors.append("confirmed_violation requires cause_assessment=production_defect")
        validate_artifacts(data, root, errors, require_hash=True)
        validate_artifact_references(data, errors)

    elif verdict == "formal_only_candidate":
        for field in ("formal.tool", "formal.version", "formal.commands", "formal.property_ids", "formal.trace"):
            require_nonempty(errors, data, field)
        if formal_status != "violated":
            errors.append("formal_only_candidate requires formal.status=violated")
        if replay_status == "confirmed":
            errors.append("formal_only_candidate may not have replay.status=confirmed")
        if data.get("cause_assessment") == "production_defect":
            errors.append("formal_only_candidate may not claim cause_assessment=production_defect")
        if not limitations or not residuals:
            errors.append("formal_only_candidate requires limitations and residual checks")
        validate_artifacts(data, root, errors, require_hash=True)
        validate_artifact_references(data, errors)

    elif verdict == "bounded_satisfaction":
        for field in ("formal.tool", "formal.version", "formal.commands", "formal.property_ids", "formal.bounds"):
            require_nonempty(errors, data, field)
        if formal_status != "satisfied":
            errors.append("bounded_satisfaction requires formal.status=satisfied")
        if nested(data, "formal.completeness_declared") is not True:
            errors.append("bounded_satisfaction requires formal.completeness_declared=true")
        if not limitations:
            errors.append("bounded_satisfaction requires explicit limitations")
        if "bound" not in str(data.get("claim_scope", "")).lower():
            errors.append("bounded_satisfaction claim_scope must explicitly say bounded")
        if data.get("cause_assessment") != "not_applicable":
            errors.append("bounded_satisfaction requires cause_assessment=not_applicable")
        validate_artifacts(data, root, errors, require_hash=False)

    elif verdict == "unknown":
        if not limitations:
            errors.append("unknown requires a concise limitation")
        if data.get("cause_assessment") not in {"unknown", "harness_fidelity_artifact", "contract_misuse_unresolved"}:
            errors.append("unknown has an incompatible cause_assessment")
        validate_artifacts(data, root, errors, require_hash=False)
    return sorted(set(errors))


def run(args: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, encoding="utf-8", errors="replace")
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise HarnessError(f"command failed ({result.returncode}): {' '.join(args)}\n{detail}")
    return result


def github_slug(url: str) -> str | None:
    patterns = (
        r"^https?://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$",
        r"^git@github\.com:([^/]+/[^/]+?)(?:\.git)?$",
        r"^ssh://git@github\.com/([^/]+/[^/]+?)(?:\.git)?/?$",
    )
    for pattern in patterns:
        match = re.match(pattern, url, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def github_visibility(url: str) -> str:
    slug = github_slug(url)
    if not slug:
        raise HarnessError("only a positively verified GitHub remote is supported")
    if shutil.which("gh") is None:
        raise HarnessError("gh is required to verify GitHub repository visibility")
    result = run(["gh", "repo", "view", slug, "--json", "visibility", "--jq", ".visibility"], check=False)
    if result.returncode != 0 or not result.stdout.strip():
        raise HarnessError("GitHub repository visibility could not be verified")
    return result.stdout.strip().upper()


def git_remotes(repo: Path) -> dict[str, str]:
    if not (repo / ".git").exists():
        return {}
    names = run(["git", "-C", str(repo), "remote"], check=False)
    if names.returncode != 0:
        return {}
    remotes: dict[str, str] = {}
    for name in (line.strip() for line in names.stdout.splitlines()):
        if not name:
            continue
        result = run(["git", "-C", str(repo), "remote", "get-url", name], check=False)
        if result.returncode == 0 and result.stdout.strip():
            remotes[name] = result.stdout.strip()
    return remotes


def git_remote(repo: Path) -> str | None:
    return git_remotes(repo).get("origin")


def push_lock_status(repo: Path) -> tuple[bool, str]:
    remotes = git_remotes(repo)
    if set(remotes) != {"origin"}:
        return False, "exactly one origin remote is required before confidential work"
    remote = remotes.get("origin")
    if not remote:
        return False, "origin remote is missing"
    push = run(["git", "-C", str(repo), "remote", "get-url", "--push", "origin"], check=False)
    if push.returncode != 0 or not push.stdout.strip().lower().startswith("disabled://"):
        return False, "origin push URL is not disabled"
    hook_path_result = run(["git", "-C", str(repo), "rev-parse", "--git-path", "hooks/pre-push"], check=False)
    if hook_path_result.returncode != 0:
        return False, "pre-push hook path could not be resolved"
    hook_path = Path(hook_path_result.stdout.strip())
    if not hook_path.is_absolute():
        hook_path = repo / hook_path
    if not hook_path.is_file():
        return False, "pre-push hook is missing"
    content = hook_path.read_text(encoding="utf-8", errors="replace")
    if "exit 1" not in content or "Push disabled" not in content:
        return False, "pre-push hook is not the blocking harness hook"
    return True, "push URL and pre-push hook are locked"


def preflight(repo: Path, remote_policy: str, remote_url: str | None, allow_existing: bool, expect_push_lock: bool) -> dict[str, Any]:
    if sys.version_info < (3, 10):
        raise HarnessError("Python 3.10 or newer is required")
    if shutil.which("git") is None:
        raise HarnessError("git is required")
    if repo.exists() and any(repo.iterdir()) and not allow_existing:
        raise HarnessError(f"destination exists and is not empty: {repo}")

    actual_remotes = git_remotes(repo) if repo.exists() else {}
    if set(actual_remotes) - {"origin"}:
        raise HarnessError("only a single origin remote is permitted")
    actual_remote = actual_remotes.get("origin")
    if actual_remote and remote_url and actual_remote != remote_url:
        raise HarnessError("configured origin does not match the confirmed remote URL")
    candidate_remote = actual_remote or remote_url
    visibility = None
    if remote_policy == "local_only":
        if candidate_remote:
            raise HarnessError("local_only policy forbids configured or proposed remotes")
    elif remote_policy == "private_baseline_once":
        if not candidate_remote:
            raise HarnessError("private_baseline_once requires a GitHub remote URL")
        visibility = github_visibility(candidate_remote)
        if visibility != "PRIVATE":
            raise HarnessError(f"GitHub remote is not private: {visibility}")
    else:
        raise HarnessError("remote policy must be local_only or private_baseline_once")

    lock = None
    if expect_push_lock:
        locked, detail = push_lock_status(repo)
        if not locked:
            raise HarnessError(detail)
        lock = detail
    return {
        "ok": True,
        "python": sys.version.split()[0],
        "pyyaml": yaml.__version__,
        "git": shutil.which("git"),
        "repo": str(repo.resolve()),
        "remote_policy": remote_policy,
        "remote": candidate_remote,
        "configured_remotes": actual_remotes,
        "visibility": visibility,
        "push_lock": lock,
    }


def shell_quote(value: str, shell: str) -> str:
    if shell == "posix":
        return shlex.quote(value)
    return "'" + value.replace("'", "''") + "'"


def command(parts: Iterable[str], shell: str) -> str:
    rendered = " ".join(shell_quote(str(part), shell) for part in parts)
    return rendered if shell == "posix" else "& " + rendered


def plan_output(steps: list[dict[str, str]], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps({"execute_automatically": False, "steps": steps}, indent=2))
        return
    print("Review the commands before execution. Routine local steps may be run together; never automate pushes or destructive steps.\n")
    for index, step in enumerate(steps, 1):
        print(f"{index}. {step['id']}")
        print(f"   {step['command']}")
        print(f"   Expected: {step['checkpoint']}\n")


def cli_parts() -> list[str]:
    return [sys.executable, str(Path(__file__).resolve())]


def plan_setup(freeze_path: Path, shell: str) -> list[dict[str, str]]:
    freeze = load_yaml(freeze_path)
    errors = validate_freeze(freeze)
    if errors:
        raise HarnessError("freeze validation failed:\n- " + "\n- ".join(errors))
    if not nested(freeze, f"source.acquisition_commands.{shell}"):
        raise HarnessError(f"the experiment brief has no {shell} acquisition path")
    destination = str(Path(freeze["repository"]["destination"]).resolve())
    policy = freeze["repository"]["remote_policy"]
    remote_url = freeze["repository"].get("remote_url")
    steps: list[dict[str, str]] = []

    preflight_parts = cli_parts() + ["preflight", "--repo", destination, "--remote-policy", policy]
    if remote_url:
        preflight_parts += ["--remote-url", remote_url]
    steps.append({"id": "preflight", "command": command(preflight_parts, shell), "checkpoint": "All dependencies and remote visibility pass."})
    steps.append({
        "id": "render-neutral-baseline",
        "command": command(cli_parts() + ["render-baseline", "--freeze", str(freeze_path.resolve()), "--dest", destination], shell),
        "checkpoint": "The rendered baseline contains no ground truth or source bytes.",
    })
    steps.append({"id": "initialize-git", "command": command(["git", "-C", destination, "init"], shell), "checkpoint": "A fresh local Git repository exists."})
    steps.append({"id": "name-baseline-branch", "command": command(["git", "-C", destination, "branch", "-M", "codex/baseline"], shell), "checkpoint": "Current branch is codex/baseline."})
    steps.append({
        "id": "validate-neutral-baseline",
        "command": command(cli_parts() + ["validate-baseline", "--repo", destination], shell),
        "checkpoint": "Manifest, leakage, pin policy, and source-byte checks pass.",
    })
    steps.append({"id": "stage-baseline", "command": command(["git", "-C", destination, "add", "--", "."], shell), "checkpoint": "The neutral baseline is staged."})
    steps.append({
        "id": "commit-baseline",
        "command": command(["git", "-C", destination, "commit", "-m", "Create neutral vulnerability-experiment baseline"], shell),
        "checkpoint": "The neutral baseline is immutable and contains no confidential result.",
    })

    if policy == "private_baseline_once":
        steps.append({"id": "add-private-origin", "command": command(["git", "-C", destination, "remote", "add", "origin", remote_url], shell), "checkpoint": "Origin exactly matches the confirmed private GitHub URL."})
        steps.append({
            "id": "reverify-private-origin",
            "command": command(cli_parts() + ["preflight", "--repo", destination, "--remote-policy", policy, "--allow-existing"], shell),
            "checkpoint": "GitHub reports PRIVATE immediately before the only push.",
        })
        steps.append({"id": "push-neutral-baseline-once", "command": command(["git", "-C", destination, "push", "-u", "origin", "codex/baseline"], shell), "checkpoint": "Only the neutral baseline was pushed."})
        steps.append({"id": "disable-push-url", "command": command(["git", "-C", destination, "remote", "set-url", "--push", "origin", "disabled://project-formalization-raw"], shell), "checkpoint": "Origin push URL begins with disabled://."})
        hook_source = str(Path(destination) / "scripts" / "pre-push")
        hook_target = str(Path(destination) / ".git" / "hooks" / "pre-push")
        if shell == "powershell":
            hook_command = command(["Copy-Item", "-LiteralPath", hook_source, "-Destination", hook_target, "-Force"], shell)
        else:
            hook_command = command(["cp", hook_source, hook_target], shell)
        steps.append({"id": "install-pre-push-hook", "command": hook_command, "checkpoint": "The blocking pre-push hook exists in .git/hooks."})
        steps.append({
            "id": "verify-push-lock",
            "command": command(cli_parts() + ["preflight", "--repo", destination, "--remote-policy", policy, "--allow-existing", "--expect-push-lock"], shell),
            "checkpoint": "Both the invalid push URL and blocking hook validate.",
        })

    worktree_root = str(Path(destination).parent / f"{Path(destination).name}-worktrees")
    steps.append({
        "id": "generate-worktree-plan",
        "command": command(cli_parts() + ["plan-worktrees", "--repo", destination, "--root", worktree_root, "--shell", shell], shell),
        "checkpoint": "The investigator workspace plan is ready for coordinator review.",
    })
    return steps


def ensure_git_repo(repo: Path) -> str:
    result = run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=False)
    if result.returncode != 0 or not COMMIT_RE.fullmatch(result.stdout.strip()):
        raise HarnessError(f"not a committed Git repository: {repo}")
    return result.stdout.strip()


def plan_worktrees(repo: Path, root: Path, shell: str) -> list[dict[str, str]]:
    baseline_errors = validate_baseline(repo)
    if baseline_errors:
        raise HarnessError("baseline validation failed:\n- " + "\n- ".join(baseline_errors))
    baseline = ensure_git_repo(repo)
    data = load_yaml(repo / "experiment.yml")
    project_slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(nested(data, "project.name"))).strip("-") or "project"
    cache_key = str(nested(data, "source.cache_key"))
    cache_root = root.parent / ".fvh-cache" / cache_key
    acquisition_scripts = nested(data, "source.acquisition_scripts", {})
    if shell not in acquisition_scripts:
        raise HarnessError(f"the experiment brief has no {shell} acquisition path")
    steps: list[dict[str, str]] = []
    for arm in ("a", "b"):
        worktree = root / f"investigator-{arm}"
        branch = f"codex/investigator-{arm}"
        source_root = worktree / "subject" / project_slug
        acquire = worktree / "scripts" / ("acquire-source.ps1" if shell == "powershell" else "acquire-source.sh")
        steps.append({
            "id": f"create-investigator-{arm}-worktree",
            "command": command(["git", "-C", str(repo), "worktree", "add", "-b", branch, str(worktree), baseline], shell),
            "checkpoint": f"Investigator {arm.upper()} starts at exact baseline {baseline}.",
        })
        if shell == "powershell":
            acquire_command = command(["powershell", "-NoProfile", "-File", str(acquire), "-SourceRoot", str(source_root), "-CacheRoot", str(cache_root)], shell)
        else:
            acquire_command = command(["sh", str(acquire), str(source_root), str(cache_root)], shell)
        steps.append({
            "id": f"materialize-investigator-{arm}-source",
            "command": acquire_command,
            "checkpoint": "Acquisition command verifies archive/commit provenance before materializing ignored source.",
        })
        steps.append({
            "id": f"verify-investigator-{arm}-pins",
            "command": command(cli_parts() + ["verify-pins", "--repo", str(worktree), "--source-root", str(source_root)], shell),
            "checkpoint": "Every scoped source file and committed baseline input matches its frozen digest.",
        })
    return steps


def commit_exists(repo: Path, commit: str) -> bool:
    if not COMMIT_RE.fullmatch(commit):
        return False
    return run(["git", "-C", str(repo), "cat-file", "-e", f"{commit}^{{commit}}"], check=False).returncode == 0


def plan_seal(repo: Path, a_commit: str, b_commit: str, root: Path, shell: str) -> list[dict[str, str]]:
    baseline_errors = validate_baseline(repo)
    if baseline_errors:
        raise HarnessError("baseline validation failed:\n- " + "\n- ".join(baseline_errors))
    baseline = ensure_git_repo(repo)
    if a_commit == b_commit:
        raise HarnessError("investigator commits must be distinct")
    for label, commit in (("A", a_commit), ("B", b_commit)):
        if not commit_exists(repo, commit):
            raise HarnessError(f"Investigator {label} commit does not exist: {commit}")
        ancestry = run(["git", "-C", str(repo), "merge-base", "--is-ancestor", baseline, commit], check=False)
        if ancestry.returncode != 0:
            raise HarnessError(f"Investigator {label} commit does not descend from baseline {baseline}")
    if git_remote(repo):
        locked, detail = push_lock_status(repo)
        if not locked:
            raise HarnessError(f"refusing to create confidential results branch: {detail}")

    results_path = root / "coordinator-results"
    summary_source = TEMPLATE_ROOT / "coordinator-summary.yml"
    summary_target = results_path / "coordinator-summary.yml"
    steps = [
        {
            "id": "create-local-results-worktree",
            "command": command(["git", "-C", str(repo), "worktree", "add", "-b", "codex/coordinator-results", str(results_path), baseline], shell),
            "checkpoint": "The results branch is local, starts at the neutral baseline, and the push lock remains active.",
        }
    ]
    if shell == "powershell":
        copy_command = command(["Copy-Item", "-LiteralPath", str(summary_source), "-Destination", str(summary_target), "-Force"], shell)
    else:
        copy_command = command(["cp", str(summary_source), str(summary_target)], shell)
    steps.append({"id": "copy-coordinator-summary", "command": copy_command, "checkpoint": "Populate exact commits, prompt digests, critic reviews, reruns, and audit evidence before committing."})
    steps.append({
        "id": "record-sealed-investigator-commits",
        "command": f"Investigator A: {a_commit}\nInvestigator B: {b_commit}",
        "checkpoint": "Verify these hashes against sealed result manifests; do not merge either investigator branch.",
    })
    return steps


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="subcommand", required=True)

    preflight_parser = sub.add_parser("preflight", help="check dependencies, destination, remotes, and push lock")
    preflight_parser.add_argument("--repo", type=Path, required=True)
    preflight_parser.add_argument("--remote-policy", choices=("local_only", "private_baseline_once"), required=True)
    preflight_parser.add_argument("--remote-url")
    preflight_parser.add_argument("--allow-existing", action="store_true")
    preflight_parser.add_argument("--expect-push-lock", action="store_true")

    setup_parser = sub.add_parser("plan-setup", help="emit a non-executing setup plan")
    setup_parser.add_argument("--freeze", type=Path, required=True)
    setup_parser.add_argument("--shell", choices=("powershell", "posix"), required=True)
    setup_parser.add_argument("--format", choices=("text", "json"), default="text")

    render_parser = sub.add_parser("render-baseline", help="render a neutral baseline from an experiment brief")
    render_parser.add_argument("--freeze", type=Path, required=True)
    render_parser.add_argument("--dest", type=Path, required=True)

    baseline_parser = sub.add_parser("validate-baseline", help="validate a neutral experiment baseline")
    baseline_parser.add_argument("--repo", type=Path, required=True)

    pin_parser = sub.add_parser("verify-pins", help="verify baseline and materialized source hashes")
    pin_parser.add_argument("--repo", type=Path, required=True)
    pin_parser.add_argument("--source-root", type=Path)

    worktree_parser = sub.add_parser("plan-worktrees", help="emit isolated investigator worktree commands")
    worktree_parser.add_argument("--repo", type=Path, required=True)
    worktree_parser.add_argument("--root", type=Path, required=True)
    worktree_parser.add_argument("--shell", choices=("powershell", "posix"), required=True)
    worktree_parser.add_argument("--format", choices=("text", "json"), default="text")

    result_parser = sub.add_parser("validate-result", help="validate one investigator result manifest")
    result_parser.add_argument("--manifest", type=Path, required=True)
    result_parser.add_argument("--root", type=Path)

    seal_parser = sub.add_parser("plan-seal", help="emit local coordinator-results branch commands")
    seal_parser.add_argument("--repo", type=Path, required=True)
    seal_parser.add_argument("--a-commit", required=True)
    seal_parser.add_argument("--b-commit", required=True)
    seal_parser.add_argument("--root", type=Path, required=True)
    seal_parser.add_argument("--shell", choices=("powershell", "posix"), required=True)
    seal_parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.subcommand == "preflight":
            print_json(preflight(args.repo, args.remote_policy, args.remote_url, args.allow_existing, args.expect_push_lock))
        elif args.subcommand == "plan-setup":
            plan_output(plan_setup(args.freeze, args.shell), args.format)
        elif args.subcommand == "render-baseline":
            print_json(render_baseline(args.freeze, args.dest))
        elif args.subcommand == "validate-baseline":
            errors = validate_baseline(args.repo)
            if errors:
                raise HarnessError("baseline validation failed:\n- " + "\n- ".join(errors))
            print_json({"ok": True, "repo": str(args.repo.resolve())})
        elif args.subcommand == "verify-pins":
            print_json(verify_pins(args.repo, args.source_root))
        elif args.subcommand == "plan-worktrees":
            plan_output(plan_worktrees(args.repo, args.root, args.shell), args.format)
        elif args.subcommand == "validate-result":
            data = load_yaml(args.manifest)
            root = args.root or args.manifest.parent
            errors = validate_result(data, root)
            if errors:
                raise HarnessError("result validation failed:\n- " + "\n- ".join(errors))
            print_json({"ok": True, "manifest": str(args.manifest.resolve()), "verdict": data["verdict"]})
        elif args.subcommand == "plan-seal":
            plan_output(plan_seal(args.repo, args.a_commit, args.b_commit, args.root, args.shell), args.format)
        return 0
    except HarnessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
