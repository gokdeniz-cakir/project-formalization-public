---
name: project-formalization-raw
description: Plan, create, run, resume, and audit independent method-agnostic vulnerability experiments against bounded components of open-source systems. Use when Codex must choose a target, create isolated investigator workspaces, preserve cross-agent and historical-source controls, validate static-analysis, formal-analysis, fuzzing, sanitizer, or runtime evidence, replay candidates against pinned production code, or perform a post-result novelty and severity audit.
---

# Project Formalization Raw

Be strict about claim quality and cross-agent independence. Apply historical and
source blindness only when the selected profile requires it.

## Choose The Target

The user chooses the upstream project. When the user also supplies a plausible component and asks to begin, proceed without another confirmation. When the component is omitted, inspect a disposable checkout and use this selection funnel:

1. Map bounded lifecycle, ownership, parser, serialization, and protocol-state candidates. Prefer interactions between individually legal operations and disagreements between sizing/writing, validation/use, or setup/cleanup over raw code complexity.
2. Rank candidates by **opportunity** (attacker influence, ownership transitions, narrowing, cross-operation state), **evidence yield** (fresh production replay, deterministic oracle, adjacent negative control), and **tractability** (bounded state, controllable inputs, modest dependency closure).
3. Record a compact target card: component, production entry, controlled input, independently meaningful invariant, replay oracle, closest control, and main modeling risk.
4. Apply a lightweight rejection check to the strongest candidates: inspect the smallest production entry and dependency closure, and confirm that a plausible replay and oracle exist. Compile or measure a formal model only when it is quick and likely to change the choice.
5. Recommend one target and two alternatives, then wait only for the target choice.

Do not pass the coordinator's suspicious operation sequence, code location, or ranking rationale to investigators. Give them only the selected component, neutral claim boundary, and independently stated properties. Narrow the target or change methods when the rejection check exposes a material mismatch.

In retrospective work, the coordinator may inspect CVEs, advisories, and fixes before target selection only when the user explicitly authorizes CVE-informed reconnaissance. Keep that material coordinator-only. It may inform the component boundary, but investigator-visible scope and properties must remain independently stated and must not encode or hint at the known mechanism, suspected location, patch, identifier, or verdict.

For prospective research against the current production release, use the
`production` coordinator profile. Public CVE history may inform coordinator
target selection, but the investigator-visible brief must describe the run only
as prospective and must not label the pin as current or production.

Read [target-selection.md](references/target-selection.md) when selecting or replacing a target.

## Create A Neutral Baseline

Write a compact experiment brief from [freeze.yml](assets/templates/freeze.yml). Despite the legacy filename, it is a working brief in the default `agile` profile, not an immutable contract. It needs only:

- Exact upstream project and revision
- Target claim boundary and initial safety properties
- Common model and tool environment
- Network leakage rules and sibling isolation
- Local repository destination

Keep `expected_verdict: null`. Keep CVEs, advisories, patches, known mechanisms, and retrospective ground truth out of the shared baseline.

When pre-run retrospective reconnaissance is authorized, store its notes only in an ignored coordinator-private directory that is absent from investigator worktrees. Record the user's authorization there. Never commit those notes to the neutral baseline.

Create a separate local harness repository and isolated investigator directories or worktrees. Keep upstream source ignored. An exact upstream commit is the primary pin; add archive hashes or signatures when readily available, without turning missing release signatures into an approval gate.

Use the CLI when it saves work. Review generated commands for destructive or external effects, then execute routine local setup without returning to the user for approval at every step. Validate only the shell and acquisition path used on the current host. Do not configure a remote unless the user asks; never push confidential work.

Read [experiment-protocol.md](references/experiment-protocol.md) for setup, isolation, and resumption.

## Run The Investigation

Default to two independent investigators, A and B, spawned directly with `fork_turns=none`, identical models, effort, tools, pins, and time budgets.

For `agile` retrospective experiments:

- A is told that an in-scope violation exists, without a mechanism, location, class, option, patch, advisory, or CVE.
- B receives no expected verdict.

For `production` prospective experiments:

- A is told that an in-scope violation exists. Do not tell A that the revision
  is the current production release. A may not search target CVEs, advisories,
  vulnerability writeups, later fixes, patches, fix-selected commits, release
  catalogs, or whether the pin is current/latest; audit A's target-specific web
  access through the tool transcript.
- B receives no expected verdict and may browse any public history, CVEs,
  advisories, fixes, or other external material without access logging.
- Do not seed A with historical CVEs. The asymmetry is positive-premise,
  history-restricted A versus neutral, open-research B.

Do not require design commits, step-by-step ledgers, or critic approval before implementation. The coordinator reviews progress and final results. Add one rotating critic only when an arm has a credible positive candidate, the coordinator sees a material modeling ambiguity, or the user requests stronger review. Use paired persistent critics only in the optional `audit` profile.

Investigators may choose and combine suitable methods, inspect transitive source dependencies, revise harnesses, tune solver options, change resource limits, select properties, and decompose proofs. Freeze source identity and property meaning, not performance knobs. Record the final material configuration and important limitations, not every discarded command.

Use a soft 90-minute budget per investigator unless the user chooses another budget. Near the limit, tell the investigator to stop expanding scope, preserve the strongest artifacts, run the most discriminating remaining check, and finish honestly. Serialize memory-heavy solvers when they share a constrained host.

The claim boundary limits what may be called a finding; it does not forbid reading dependency code needed to compile or understand that boundary.

Both arms may otherwise use arbitrary local tools, methods, build
configurations, readable source dependencies, package installations, and
generic technical resources. Isolation is not a reason to constrain legitimate
analysis inside the assigned workspace.

## Preserve Independence

These controls remain mandatory in every profile:

- No sibling branches, worktrees, prompts, reviews, results, or coordinator-private artifacts.
- Use separate workspaces and out-of-band prompts. Treat any cross-agent access
  through the filesystem or Git as an isolation incident.
- Do not use one arm's findings to coach the other before both results seal.

For retrospective `agile` and `audit` experiments, also preserve historical blindness:

- Investigators must never access target CVEs, advisories, vulnerability writeups, later fixes, patches, fix-selected commits, or coordinator ground truth before they finish.
- By default, the coordinator also avoids those sources until both arms finish. The sole exception is explicit user authorization for CVE-informed retrospective reconnaissance before target selection.
- Under that exception, keep all ground truth coordinator-only. Do not pass identifiers, affected-version facts, mechanisms, vulnerability classes, suspected files or use sites, exploit conditions, patches, or expected outcomes to investigators. Do not turn a known mechanism into a tailored property or harness assertion.
- No ground truth in the baseline or investigator prompts.
- Use the tool-call transcript as the primary access audit. Require a short final declaration plus disclosure of relevant URLs and any accidental access; do not make agents maintain a duplicate command diary.

Broad generic technical web access is allowed unless the user chooses offline mode. Generic compiler, solver, API, and build documentation is not contamination.

For `production` experiments, use asymmetric per-arm network policy. Monitor A
for target-specific historical-source access and require its short final access
declaration. Do not audit B's URLs or require a network declaration from B.
Only cross-agent and coordinator-private access is forbidden for both arms.

## Judge Evidence Proportionally

Accept `confirmed_violation`, `formal_only_candidate`, `bounded_satisfaction`, and `unknown`.

A confirmed production violation still requires a convincing trace, a successful replay against a fresh unmodified pinned build, the closest useful negative control, checker sanity, and mechanism-specific evidence. This is where rigor matters most.

For `unknown` or tool failure, require only the attempted method, decisive log or diagnostic when available, and a concise account of limitations. Do not demand proof-grade artifact inventories, exhaustive hashes, critic acceptance, or coordinator reruns for an inconclusive result.

For bounded satisfaction, state the checked properties and meaningful bounds without implying general safety. For a non-replaying counterexample, preserve it as a candidate or harness-fidelity question rather than forcing a binary verdict.

Read [evidence-standard.md](references/evidence-standard.md) when reviewing a result.

## Finish And Audit

Have each arm commit or otherwise snapshot its final result before cross-arm comparison. A design checkpoint is optional. Treat convergence as corroboration of one mechanism, not two findings.

After both arms finish, the coordinator may inspect or revisit advisories, CVEs, later commits, and patches and compare them with sealed results. When authorized retrospective reconnaissance happened earlier, do not use it to coach, redirect, or critique either arm before sealing. In production work, perform a fresh novelty audit even when investigators used public sources; absence from the sources they happened to read is not novelty evidence. In retrospective work, compare the actual object and use site against the advisory and fix. Never infer code execution from a UAF alone.

Keep research and draft reports local. Never contact maintainers, submit, publish, merge confidential branches, or push results without a separate explicit user request.

Read [post-seal-audit.md](references/post-seal-audit.md) for novelty and severity work and [interfaces.md](references/interfaces.md) for the optional CLI and schemas.

## Profiles

- `production` is the default for prospective current-release research:
  positive-premise history-restricted A, neutral open-research B, a visible
  `prospective` brief, and strict cross-agent repository isolation.
- `agile` is the default for retrospective work: compact brief, historical
  blindness, autonomous local setup, two investigators, flexible methods,
  proportional evidence, and a conditional critic.
- `audit` is opt-in: explicit freeze confirmation, paired design/final critics, immutable checkpoints, complete artifact hashing, and independent coordinator reruns.

Do not silently escalate an experiment from `agile` to `audit`.
