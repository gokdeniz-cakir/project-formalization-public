# Interfaces

The Python CLI is optional infrastructure, not a workflow engine. Use it when deterministic rendering or validation saves time.

## Experiment Brief

`assets/templates/freeze.yml` retains its filename for compatibility. Schema `1.1` supports `workflow.profile` values `production`, `agile`, and `audit`.

In `production` mode:

- `experiment.mode` is prospective.
- The coordinator freeze uses `network.policy: asymmetric` with an audited,
  history-restricted A and an open, unmonitored B.
- The rendered investigator baseline exposes only `workflow.profile:
  prospective` and `network.policy: per_prompt`.
- `network.forbidden_sources` must cover sibling artifacts; public sources are allowed.
- Freeze confirmation is optional.

In `agile` mode:

- `freeze.confirmed` may be false.
- Exact project commit, target, properties, model configuration, leakage policy, and destination remain required.
- Exact formal and replay commands may be filled later.
- One host acquisition path is enough.
- Archive hashes, signatures, per-file scope hashes, and push locks are optional when an exact Git commit and local-only repository are used.

In `audit` mode, confirmation metadata, stronger provenance, immutable artifacts, and full review gates may be required.

The rendered `experiment.yml` must retain `expected_verdict: null` and contain no advisory, CVE, patch, known mechanism, or arm-specific prompt.

## Result Manifest

Schema `1.1` uses proportional validation:

- `unknown` needs concise attempted-method and limitation information; artifact hashes and residual-work inventories are optional.
- `bounded_satisfaction` needs selected properties and bounds.
- `formal_only_candidate` needs a formal violation and counterexample evidence.
- `confirmed_violation` retains the full production replay, control, checker-sanity, mechanism, and cited-artifact hash gates.

## CLI

- `preflight --repo PATH --remote-policy POLICY [--allow-existing] [--expect-push-lock]`
- `plan-setup --freeze FILE --shell powershell|posix [--format text|json]`
- `render-baseline --freeze FILE --dest PATH`
- `validate-baseline --repo PATH`
- `verify-pins --repo PATH [--source-root PATH]`
- `plan-worktrees --repo PATH --root PATH --shell powershell|posix [--format text|json]`
- `validate-result --manifest FILE [--root PATH]`
- `plan-seal --repo PATH --a-commit HASH --b-commit HASH --root PATH --shell powershell|posix [--format text|json]`

Planning commands do not execute by themselves. Review them, then run routine local steps together or separately as appropriate. Never automatically execute a push or destructive command.
