from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml


SCRIPT = Path(__file__).resolve().parents[1] / "harness.py"
SPEC = importlib.util.spec_from_file_location("formal_vulnerability_harness", SCRIPT)
assert SPEC and SPEC.loader
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout.strip()


class HarnessFixture:
    def __init__(self, root: Path):
        self.root = root
        self.destination = root / "experiment"
        self.source_root = root / "materialized-source"
        self.source_file = self.source_root / "src" / "component.c"
        self.source_file.parent.mkdir(parents=True)
        self.source_file.write_text("int component(void) { return 0; }\n", encoding="utf-8")
        self.spec_file = root / "valid-deref.prp"
        self.spec_file.write_text("CHECK( init(main()), LTL(G valid-deref) )\n", encoding="utf-8")

        self.freeze = yaml.safe_load((harness.TEMPLATE_ROOT / "freeze.yml").read_text(encoding="utf-8"))
        self.freeze["freeze"] = {
            "confirmed": True,
            "confirmed_at": "2026-07-19T12:00:00+03:00",
            "confirmed_by": "test-user",
        }
        self.freeze["experiment"]["id"] = "fixture-component-prospective-01"
        self.freeze["project"].update(
            {
                "name": "fixture",
                "upstream_url": "https://github.com/example/fixture",
                "version": "1.0.0",
                "release_tag": "v1.0.0",
                "commit": "1" * 40,
                "license": "MIT",
            }
        )
        self.freeze["source"].update(
            {
                "archive_url": "https://github.com/example/fixture/releases/download/v1.0.0/fixture-1.0.0.tar.gz",
                "archive_sha256": "2" * 64,
                "signature_url": None,
                "signer_fingerprint": None,
                "provenance_note": "Fixture has no signed release; the exact commit and archive hash are recorded.",
                "cache_key": "fixture-1.0.0-" + "2" * 12,
                "acquisition_commands": {
                    "powershell": ["New-Item -ItemType Directory -Force $env:FVH_SOURCE_ROOT | Out-Null"],
                    "posix": ["mkdir -p \"$FVH_SOURCE_ROOT\""],
                },
                "scope_inventory": [
                    {"path": "src/component.c", "sha256": digest(self.source_file)}
                ],
            }
        )
        self.freeze["target"].update(
            {
                "language": "c",
                "component": "component lifecycle",
                "production_boundary": "component() and its owned state",
                "included_files": ["src/component.c"],
                "excluded_files": ["tests"],
                "safety_rationale": "Small state, independent memory property, and stock replay.",
            }
        )
        self.freeze["tooling"] = {
            "formal": {
                "required": True,
                "name": "CBMC",
                "family": "bounded_model_checking",
                "execution_environment": "wsl:Ubuntu",
                "version_command": "cbmc --version",
                "build_command": "cc -c harness.c",
                "analyze_command": "cbmc harness.c --bounds-check --pointer-check",
                "completeness_command": "cbmc harness.c --unwinding-assertions",
                "property_mapping": "CBMC pointer checks map to valid-deref.",
                "witness_format": "CBMC trace",
                "secondary": {
                    "name": None,
                    "family": None,
                    "execution_environment": None,
                    "version_command": None,
                    "analyze_command": None,
                },
            },
            "runtime": {
                "oracle": "AddressSanitizer",
                "version_command": "clang --version",
                "build_command": "clang -fsanitize=address production.c",
                "witness_command": "./witness",
                "control_command": "./witness --control",
                "checker_sanity_command": "./checker-sanity",
            },
        }
        self.freeze["agents"].update(
            {
                "model": "gpt-fixture",
                "knowledge_cutoff": "2025-01",
                "reasoning_effort": "high",
                "tool_environment": "shell and formal tool adapters",
                "framing": "default",
            }
        )
        self.freeze["workflow"]["profile"] = "agile"
        self.freeze["workflow"]["method_policy"] = "formal_required"
        self.freeze["network"] = {
            "policy": "broad_audited",
            "audit_required": True,
            "forbidden_sources": [
                "target CVEs and vulnerability advisories",
                "later fixes and patches",
                "sibling branches, worktrees, prompts, reviews, and results",
            ],
        }
        self.freeze["repository"].update(
            {
                "destination": str(self.destination.resolve()),
                "remote_policy": "local_only",
                "remote_url": None,
                "source_policy": "pins_only",
                "push_lock_required": True,
            }
        )
        self.freeze["baseline_files"] = [
            {
                "source": str(self.spec_file.resolve()),
                "destination": "spec/valid-deref.prp",
                "sha256": digest(self.spec_file),
                "role": "specification",
            }
        ]
        self.receipt = {
            "schema_version": "1.0",
            "acquisition_completed": True,
            "project_commit": "1" * 40,
            "archive_sha256": "2" * 64,
            "signature_verified": False,
            "signer_fingerprint": None,
        }
        (self.source_root / ".fvh-provenance.yml").write_text(
            yaml.safe_dump(self.receipt, sort_keys=False), encoding="utf-8"
        )
        self.freeze_path = root / "freeze.yml"
        self.write_freeze()

    def write_freeze(self) -> None:
        self.freeze_path.write_text(yaml.safe_dump(self.freeze, sort_keys=False), encoding="utf-8")

    def render(self) -> None:
        harness.render_baseline(self.freeze_path, self.destination)

    def init_git(self) -> str:
        git(self.destination, "init")
        git(self.destination, "config", "user.email", "fixture@example.invalid")
        git(self.destination, "config", "user.name", "Fixture")
        git(self.destination, "add", ".")
        git(self.destination, "commit", "-m", "baseline")
        git(self.destination, "branch", "-M", "codex/baseline")
        return git(self.destination, "rev-parse", "HEAD")


class FreezeAndBaselineTests(unittest.TestCase):
    def test_unconfirmed_agile_brief_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.freeze["freeze"]["confirmed"] = False
            errors = harness.validate_freeze(fixture.freeze)
            self.assertEqual([], errors)
            fixture.write_freeze()
            fixture.render()
            self.assertTrue((fixture.destination / "experiment.yml").is_file())

    def test_unconfirmed_audit_freeze_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.freeze["workflow"]["profile"] = "audit"
            fixture.freeze["freeze"]["confirmed"] = False
            errors = harness.validate_freeze(fixture.freeze)
            self.assertIn("field must be true: freeze.confirmed", errors)

    def test_runtime_oracle_cannot_be_declared_as_formal_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.freeze["tooling"]["formal"]["name"] = "AddressSanitizer"
            errors = harness.validate_freeze(fixture.freeze)
            self.assertTrue(any("machine-checking backend" in error for error in errors))

    def test_production_profile_renders_hidden_asymmetric_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.freeze["workflow"]["profile"] = "production"
            fixture.freeze["agents"]["framing"] = "positive_restricted_vs_neutral_open"
            fixture.freeze["network"] = {
                "policy": "asymmetric",
                "audit_required": True,
                "arm_policies": {
                    "investigator_a": "target_restricted_audited",
                    "investigator_b": "open_unmonitored",
                },
                "forbidden_sources": [
                    "sibling branches, worktrees, prompts, reviews, and results"
                ],
            }
            self.assertEqual([], harness.validate_freeze(fixture.freeze))
            fixture.write_freeze()
            fixture.render()
            self.assertEqual([], harness.validate_baseline(fixture.destination))
            baseline = yaml.safe_load(
                (fixture.destination / "experiment.yml").read_text(encoding="utf-8")
            )
            self.assertEqual("prospective", baseline["workflow"]["profile"])
            self.assertEqual("per_prompt", baseline["network"]["policy"])
            self.assertNotIn("arm_policies", baseline["network"])
            self.assertNotIn("audit_required", baseline["network"])

    def test_production_profile_still_requires_sibling_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.freeze["workflow"]["profile"] = "production"
            fixture.freeze["network"] = {
                "policy": "asymmetric",
                "audit_required": True,
                "arm_policies": {
                    "investigator_a": "target_restricted_audited",
                    "investigator_b": "open_unmonitored",
                },
                "forbidden_sources": ["coordinator-private artifacts"],
            }
            errors = harness.validate_freeze(fixture.freeze)
            self.assertIn(
                "network.forbidden_sources must explicitly cover sibling", errors
            )

    def test_open_unmonitored_network_is_rejected_for_agile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.freeze["network"]["policy"] = "open_unmonitored"
            fixture.freeze["network"]["audit_required"] = False
            errors = harness.validate_freeze(fixture.freeze)
            self.assertIn(
                "asymmetric and open_unmonitored policies are reserved for production arm configuration",
                errors,
            )

    def test_production_profile_requires_asymmetric_arm_policies(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.freeze["workflow"]["profile"] = "production"
            fixture.freeze["network"] = {
                "policy": "asymmetric",
                "audit_required": True,
                "arm_policies": {
                    "investigator_a": "open_unmonitored",
                    "investigator_b": "open_unmonitored",
                },
                "forbidden_sources": [
                    "sibling branches, worktrees, prompts, reviews, and results"
                ],
            }
            errors = harness.validate_freeze(fixture.freeze)
            self.assertIn(
                "production investigator A must use target_restricted_audited",
                errors,
            )

    def test_confirmed_untouched_template_is_rejected(self) -> None:
        data = yaml.safe_load((harness.TEMPLATE_ROOT / "freeze.yml").read_text(encoding="utf-8"))
        data["freeze"] = {
            "confirmed": True,
            "confirmed_at": "2026-07-19T12:00:00+03:00",
            "confirmed_by": "test-user",
        }
        errors = harness.validate_freeze(data)
        self.assertTrue(any("template placeholder" in error for error in errors))

    def test_exact_commit_does_not_require_signature_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.freeze["source"]["provenance_note"] = None
            errors = harness.validate_freeze(fixture.freeze)
            self.assertEqual([], errors)

    def test_render_validate_and_verify_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            self.assertEqual([], harness.validate_freeze(fixture.freeze))
            fixture.render()
            self.assertEqual([], harness.validate_baseline(fixture.destination))
            result = harness.verify_pins(fixture.destination, fixture.source_root)
            self.assertTrue(result["source_checked"])
            self.assertEqual(2, len(result["checked"]))
            baseline = yaml.safe_load((fixture.destination / "experiment.yml").read_text(encoding="utf-8"))
            self.assertNotIn("framing", baseline["agents"])
            self.assertIsNone(baseline["experiment"]["expected_verdict"])

    def test_tampered_source_pin_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.render()
            fixture.source_file.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(harness.HarnessError, "hash mismatch"):
                harness.verify_pins(fixture.destination, fixture.source_root)

    def test_missing_provenance_receipt_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.render()
            (fixture.source_root / ".fvh-provenance.yml").unlink()
            with self.assertRaisesRegex(harness.HarnessError, "exact Git checkout or contain a verification receipt"):
                harness.verify_pins(fixture.destination, fixture.source_root)

    def test_cve_identifier_leak_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.render()
            (fixture.destination / "notes.txt").write_text("Known result: CVE-" + "2026-12345\n", encoding="utf-8")
            errors = harness.validate_baseline(fixture.destination)
            self.assertTrue(any("CVE identifier" in error for error in errors))

    def test_tracked_source_bytes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.render()
            fixture.init_git()
            leaked = fixture.destination / "subject" / "fixture" / "src.c"
            leaked.parent.mkdir(parents=True)
            leaked.write_text("int leaked;\n", encoding="utf-8")
            git(fixture.destination, "add", "-f", "subject/fixture/src.c")
            errors = harness.validate_baseline(fixture.destination)
            self.assertTrue(any("source bytes" in error for error in errors))

    def test_setup_plans_are_non_executing_and_shell_specific(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            posix = harness.plan_setup(fixture.freeze_path, "posix")
            powershell = harness.plan_setup(fixture.freeze_path, "powershell")
            self.assertFalse(fixture.destination.exists())
            self.assertEqual("preflight", posix[0]["id"])
            self.assertTrue(powershell[0]["command"].startswith("& "))
            self.assertIn("plan-worktrees", posix[-1]["command"])


class RemotePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        git(self.repo, "init")
        git(self.repo, "remote", "add", "origin", "https://github.com/example/private-repo.git")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_local_only_rejects_remote(self) -> None:
        with self.assertRaisesRegex(harness.HarnessError, "forbids"):
            harness.preflight(self.repo, "local_only", None, True, False)

    def test_public_remote_is_rejected(self) -> None:
        with mock.patch.object(harness, "github_visibility", return_value="PUBLIC"):
            with self.assertRaisesRegex(harness.HarnessError, "not private"):
                harness.preflight(self.repo, "private_baseline_once", None, True, False)

    def test_private_remote_passes_and_push_lock_is_verified(self) -> None:
        with mock.patch.object(harness, "github_visibility", return_value="PRIVATE"):
            result = harness.preflight(self.repo, "private_baseline_once", None, True, False)
            self.assertEqual("PRIVATE", result["visibility"])
            git(self.repo, "remote", "set-url", "--push", "origin", "disabled://project-formalization")
            hook = self.repo / ".git" / "hooks" / "pre-push"
            hook.write_text("#!/bin/sh\necho 'Push disabled'\nexit 1\n", encoding="utf-8")
            locked = harness.preflight(self.repo, "private_baseline_once", None, True, True)
            self.assertIn("locked", locked["push_lock"])

    def test_additional_remote_is_rejected(self) -> None:
        git(self.repo, "remote", "add", "backup", "https://github.com/example/backup.git")
        with self.assertRaisesRegex(harness.HarnessError, "single origin"):
            harness.preflight(self.repo, "private_baseline_once", None, True, False)


class ResultTests(unittest.TestCase):
    def make_result(self, root: Path) -> dict:
        result = yaml.safe_load((harness.TEMPLATE_ROOT / "result.yml").read_text(encoding="utf-8"))
        result["baseline_commit"] = "a" * 40
        result["snapshot_digest"] = "b" * 64
        result["claim_scope"] = "The analysis is inconclusive within the declared bounds."
        result["formal"].update(
            {
                "tool": "CBMC",
                "family": "bounded_model_checking",
                "version": "6.0.1",
                "execution_environment": "wsl:Ubuntu",
                "compiler": "clang 18",
                "solver": "minisat",
                "commands": ["cbmc harness.c --pointer-check"],
                "exit_codes": [1],
                "property_ids": ["valid-deref"],
                "production_units": ["src/component.c"],
                "models": ["production definitions and bounded allocator model"],
                "assumptions": ["formal_entry receives a valid fixture state"],
                "bounds": {"description": "One bounded input and complete loop unwinding."},
            }
        )
        result["limitations"] = ["The external allocator model remains incomplete."]
        result["residuals"] = ["Model and rerun the external allocator."]
        return result

    def make_confirmed(self, root: Path) -> dict:
        result = self.make_result(root)
        for name, content in (
            ("formal.log", "VERIFICATION FAILED\n"),
            ("trace.json", "{}\n"),
            ("asan.log", "heap-use-after-free\n"),
        ):
            (root / name).write_text(content, encoding="utf-8")
        result.update(
            {
                "verdict": "confirmed_violation",
                "cause_assessment": "production_defect",
                "claim_scope": "A production UAF occurs within the frozen boundary.",
            }
        )
        result["formal"].update({"status": "violated", "logs": ["formal.log"], "trace": "trace.json", "completeness_checks": ["unwinding assertions passed for the one loop"]})
        result["replay"].update(
            {
                "status": "confirmed",
                "fresh_unmodified_build": True,
                "pin_check": True,
                "build_command": "clang -fsanitize=address production.c",
                "linkage_evidence": "linked exact pinned static library",
                "source_hashes": {"src/component.c": "c" * 64},
                "witness": {
                    "command": "./witness",
                    "successful_runs": 1,
                    "oracle_output": "asan.log",
                },
                "negative_controls": [
                    {
                        "name": "omit invalidating transition",
                        "command": "./witness --control",
                        "closest_match": True,
                        "passed": True,
                    }
                ],
                "checker_sanity": {
                    "command": "./checker-sanity",
                    "passed": True,
                    "evidence": "ASan reports the injected sanity fault",
                },
            }
        )
        result["mechanism"] = {
            "kind": "uaf",
            "complete": True,
            "rationale": "The same object is allocated, freed, and dereferenced.",
            "events": [
                {"kind": "allocation", "object": "obj", "location": "component.c:10"},
                {"kind": "free", "object": "obj", "location": "component.c:20"},
                {"kind": "use", "object": "obj", "location": "component.c:30"},
            ],
        }
        result["artifacts"] = [
            {"path": name, "sha256": digest(root / name)}
            for name in ("formal.log", "trace.json", "asan.log")
        ]
        return result

    def test_unknown_template_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "formal.log").write_text("tool failed\n", encoding="utf-8")
            result = yaml.safe_load((harness.TEMPLATE_ROOT / "result.yml").read_text(encoding="utf-8"))
            result["baseline_commit"] = "a" * 40
            result["claim_scope"] = "No target verdict was established."
            result["limitations"] = ["The selected tool failed before analysis."]
            result["formal"]["logs"] = ["formal.log"]
            result["residuals"] = []
            result["artifacts"] = [{"path": "formal.log", "sha256": None}]
            self.assertEqual([], harness.validate_result(result, root))

    def test_confirmed_violation_gate_passes_complete_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.make_confirmed(root)
            self.assertEqual([], harness.validate_result(result, root))

    def test_confirmed_violation_requires_closest_control(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.make_confirmed(root)
            result["replay"]["negative_controls"] = []
            errors = harness.validate_result(result, root)
            self.assertTrue(any("closest matched negative control" in error for error in errors))

    def test_bounded_satisfaction_must_be_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "formal.log").write_text("VERIFICATION SUCCESSFUL\n", encoding="utf-8")
            result = self.make_result(root)
            result.update(
                {
                    "verdict": "bounded_satisfaction",
                    "cause_assessment": "not_applicable",
                    "claim_scope": "All checked properties hold.",
                }
            )
            result["formal"].update({
                "status": "satisfied",
                "logs": ["formal.log"],
                "completeness_checks": ["unwinding assertions passed"],
                "completeness_declared": True,
            })
            result["artifacts"] = [{"path": "formal.log", "sha256": digest(root / "formal.log")}]
            errors = harness.validate_result(result, root)
            self.assertTrue(any("explicitly say bounded" in error for error in errors))

    def test_proved_under_contracts_accepts_complete_formal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "formal.log").write_text("ALL PROOF OBLIGATIONS DISCHARGED\n", encoding="utf-8")
            result = self.make_result(root)
            result.update(
                {
                    "verdict": "proved_under_contracts",
                    "cause_assessment": "not_applicable",
                    "claim_scope": "The selected C properties are proved under the listed contracts and assumptions.",
                }
            )
            result["formal"].update(
                {
                    "status": "proved",
                    "logs": ["formal.log"],
                    "proof_obligations": ["all ACSL obligations discharged"],
                    "completeness_checks": ["all loops have reviewed invariants"],
                    "completeness_declared": True,
                }
            )
            result["artifacts"] = [{"path": "formal.log", "sha256": digest(root / "formal.log")}]
            self.assertEqual([], harness.validate_result(result, root))

    def test_tampered_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.make_confirmed(root)
            (root / "asan.log").write_text("changed\n", encoding="utf-8")
            errors = harness.validate_result(result, root)
            self.assertTrue(any("artifact hash mismatch" in error for error in errors))

    def test_unhashed_referenced_log_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.make_confirmed(root)
            result["artifacts"] = [item for item in result["artifacts"] if item["path"] != "formal.log"]
            errors = harness.validate_result(result, root)
            self.assertTrue(any("formal.logs[0] must reference" in error for error in errors))

    def test_isolation_incident_can_be_recorded_without_laundering_it(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "formal.log").write_text("tool failed\n", encoding="utf-8")
            result = self.make_result(root)
            result["formal"]["logs"] = ["formal.log"]
            result["artifacts"] = [{"path": "formal.log", "sha256": digest(root / "formal.log")}]
            result["independence"].update(
                {
                    "forbidden_source_access": True,
                    "isolation_status": "compromised",
                    "incidents": ["A forbidden advisory URL was opened accidentally."],
                }
            )
            self.assertEqual([], harness.validate_result(result, root))


class GitPlanTests(unittest.TestCase):
    def test_worktree_and_seal_plans_reference_immutable_commits(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = HarnessFixture(Path(temp))
            fixture.render()
            baseline = fixture.init_git()
            worktree_plan = harness.plan_worktrees(fixture.destination, Path(temp) / "worktrees", "posix")
            self.assertEqual(6, len(worktree_plan))
            self.assertIn(baseline, worktree_plan[0]["command"])

            git(fixture.destination, "checkout", "-b", "codex/investigator-a")
            (fixture.destination / "a.txt").write_text("a\n", encoding="utf-8")
            git(fixture.destination, "add", "a.txt")
            git(fixture.destination, "commit", "-m", "A result")
            a_commit = git(fixture.destination, "rev-parse", "HEAD")
            git(fixture.destination, "checkout", "codex/baseline")
            git(fixture.destination, "checkout", "-b", "codex/investigator-b")
            (fixture.destination / "b.txt").write_text("b\n", encoding="utf-8")
            git(fixture.destination, "add", "b.txt")
            git(fixture.destination, "commit", "-m", "B result")
            b_commit = git(fixture.destination, "rev-parse", "HEAD")
            git(fixture.destination, "checkout", "codex/baseline")

            seal_plan = harness.plan_seal(
                fixture.destination,
                a_commit,
                b_commit,
                Path(temp) / "sealed",
                "powershell",
            )
            self.assertEqual(3, len(seal_plan))
            self.assertIn("codex/coordinator-results", seal_plan[0]["command"])
            self.assertIn(a_commit, seal_plan[-1]["command"])


if __name__ == "__main__":
    unittest.main()
