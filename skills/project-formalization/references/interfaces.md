# Formal Harness Interfaces

The Python CLI validates the formal experiment contract and plans repository
operations. It does not replace the verifier. `formal_runner.py` discovers
backends and records actual tool invocations.

## Brief Requirements

The formal brief uses schema `1.2` and requires:

- `workflow.method_policy: formal_required`
- `target.language: c`
- `tooling.formal.required: true`
- A concrete formal backend, family, execution environment, version command,
  analysis command, and property mapping
- At least one declared safety property and a runtime replay oracle

The brief may select `production`, `agile`, or `audit`. It must retain
`expected_verdict: null` and no ground truth.

## Result Requirements

The result template supports:

- `formal_only_candidate`
- `bounded_satisfaction`
- `proved_under_contracts`
- `confirmed_violation`
- `unknown`

All positive formal results require tool/version/commands/property IDs and model
metadata. Bounded satisfaction additionally requires explicit completeness. A
confirmed violation additionally requires fresh replay, a closest control,
checker sanity, and a complete mechanism.

## Formal Runner

Probe available tools:

```powershell
python scripts/formal_runner.py probe --json
```

Record one invocation and its outputs:

```powershell
python scripts/formal_runner.py run --tool cbmc --environment wsl `
  --distro Ubuntu --output-dir artifacts/formal/cbmc-01 -- `
  cbmc harness.c production.c --pointer-check --bounds-check --trace
```

The runner writes `receipt.json`, `stdout.log`, `stderr.log`, and SHA-256 hashes.
It returns the verifier's exit code and never converts a failed check into a
successful result.

## CLI

- `preflight --repo PATH --remote-policy POLICY [--allow-existing] [--expect-push-lock]`
- `plan-setup --freeze FILE --shell powershell|posix [--format text|json]`
- `render-baseline --freeze FILE --dest PATH`
- `validate-baseline --repo PATH`
- `verify-pins --repo PATH [--source-root PATH]`
- `plan-worktrees --repo PATH --root PATH --shell powershell|posix [--format text|json]`
- `validate-result --manifest FILE [--root PATH]`
- `plan-seal --repo PATH --a-commit HASH --b-commit HASH --root PATH --shell powershell|posix [--format text|json]`

Planning commands emit reviewable commands. Never automatically push, publish,
contact a maintainer, or run a destructive command.
