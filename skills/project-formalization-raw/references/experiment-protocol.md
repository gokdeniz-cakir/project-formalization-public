# Experiment Protocol

## Agile Brief

Use `assets/templates/freeze.yml` as a compact working brief. The default `agile` profile does not require `freeze.confirmed: true`. If the user supplied the project and target and asked to begin, that request authorizes routine local setup.

Use `production` for prospective current-release research unless the user asks
for stricter historical blindness. It also does not require freeze confirmation.

Record the project revision, claim boundary, initial properties, common agent configuration, leakage rules, and destination. Exact formal commands, bounds, dependency lists, replay commands, and solver settings may evolve during investigation. Keep expected verdict and retrospective ground truth out of the brief.

If the user authorizes CVE-informed retrospective reconnaissance, record the authorization and source notes in an ignored coordinator-private directory that is not present in investigator worktrees. The neutral brief must still look the same as one produced from source-only target selection.

Require an explicit user decision only when:

- The coordinator selected or materially replaces the target
- Setup would push, publish, contact a third party, or modify an existing unrelated repository
- The user explicitly requested the `audit` profile

## Repository

Create a separate local harness repository. Keep upstream source and large build artifacts ignored. Prefer an exact upstream Git commit as the source pin; independently materialized source directories are useful but a content-addressed cache and per-file scope hashes are optional in `agile` mode.

Use separate worktrees or directories for investigators. They may read transitive upstream dependencies but may not inspect sibling workspaces or results. Do not configure a remote by default. If the user explicitly requests a shared private baseline, verify privacy and install a push lock before confidential work.

The setup CLI produces reviewable commands. Routine local commands may be executed in sequence after review; they do not each need a user checkpoint. Validate the acquisition path for the current host, not every supported platform.

## Roles

Spawn A and B directly with `fork_turns=none` and equal resources. Save their exact prompt text and digest in a coordinator-only location before launch so it can be audited later without exposing it to investigators.

In `production`, tell A that an in-scope violation exists but do not label the
pin current or production. Restrict and monitor A's target-specific CVE,
advisory, disclosure, later-fix, release-catalog, and current-version lookup
access. Give B no expected verdict and allow unmonitored public research,
including prior CVEs. Do not pass the coordinator's historical target rationale
to either arm.

In `agile` mode the coordinator is the normal reviewer. Do not block implementation on design review. Add one critic when a credible candidate needs adversarial review or a modeling decision remains genuinely ambiguous. The critic may inspect a stable snapshot or commit and should report only material problems.

The `audit` profile may use Critic A and Critic B at design and final checkpoints, but only when the user explicitly chooses that cost.

## Technical Freedom

Investigators may revise harness structure, bounds, solver flags, property selection, decomposition, compiler profiles, and runtime experiments. They may use generic technical documentation. Ask them to preserve property meaning and disclose material assumptions in the final result.

Do not impose a one-attempt rule. A solver diagnostic that recommends a resource option, such as object-bit width, is a reason to tune and rerun, not a reason to stop. Use staged checks: wrapper sanity, compile, selected properties, then broader coverage if resources allow.

Schedule only one heavyweight solver at a time when investigators share a memory-constrained VM. Analysis, harness writing, and lightweight tests can remain concurrent.

## Network

In the coordinator freeze for `production`, set `network.policy: asymmetric`
with A `target_restricted_audited` and B `open_unmonitored`. Render the shared
investigator brief as `workflow.profile: prospective` with
`network.policy: per_prompt`, so A is not told the pin's production status or
B's framing. A reports relevant web access; B does not. Forbid sibling
workspaces, branches, prompts, reviews, results, and coordinator-private
artifacts for both.

In retrospective `agile` or `audit`, forbid investigators from target-specific advisories, CVE searches, later fixes, patches, fix-selected commits, coordinator ground truth, and sibling artifacts. Apply the same restriction to the coordinator until both arms finish unless the user explicitly authorized CVE-informed retrospective reconnaissance. Under that exception, coordinator access must not alter investigator framing, prompts, properties, harness assertions, or interim feedback based on the known mechanism.

For historically restricted arms, the tool transcript is the primary network
audit record and the final declaration lists relevant external pages and
accidental accesses. Do not reconstruct or audit B's browsing history.

## Resume

Inspect the current brief, source pin, investigator directories, running owned processes, and latest useful artifacts. Continue from working state rather than recreating ceremonies or prompts. Never use one arm's result to accelerate the other before both finish.
