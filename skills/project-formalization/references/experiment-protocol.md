# Formal Experiment Protocol

## Working Brief

Use `assets/templates/freeze.yml` as a compact formal working brief. The brief
must identify a C claim boundary, safety properties, formal backend, execution
environment, property mapping, model assumptions, and runtime replay plan. Keep
`experiment.expected_verdict: null` and exclude CVEs, advisories, fixes, known
mechanisms, and ground truth from investigator-visible files.

The exact source pin and property meaning are frozen. Bounds, solver options,
resource limits, decomposition, compiler diagnostics, and harness layout may be
refined only when the property and boundary retain the same meaning.

## Repository And Source

Create a separate local harness repository. Keep the pinned C source and large
build artifacts ignored. Prefer an exact upstream commit and verify it before
formal translation. Put model files, ACSL specifications, property files, and
replay harnesses outside production source.

Use separate worktrees or directories for investigators. They may inspect
transitive C dependencies needed for compilation and modeling, but may not inspect
sibling workspaces, prompts, reviews, results, or coordinator-private artifacts.

## Formal Roles

Spawn two equal investigators with `fork_turns=none`. Both must perform formal
analysis. Prefer a complementary backend assignment when feasible:

- A: CBMC or ESBMC bounded verification.
- B: Frama-C Eva/WP, CPAchecker, Ultimate, Symbiotic, SeaHorn, or an independent
  CBMC/ESBMC encoding selected from the property and available environment.

Do not disclose a suspected mechanism or use one arm's trace to coach the other.
Add a critic only for a credible positive, a material model ambiguity, or an
explicit audit request.

## Formal Stages

1. Run `formal_runner.py probe` in native and available WSL environments.
2. Fill the formal tool, version, compiler, solver, property mapping, and command
   fields before baseline validation.
3. Compile the production translation units and formal wrapper separately.
4. Run a deliberate wrapper assertion failure and a known-safe control.
5. Run selected formal properties with raw logs, traces, and completeness checks.
6. Add a second property or backend when resource limits permit.
7. Rebuild the pinned production source freshly and replay any positive trace under
   a runtime oracle.
8. Seal the result with exact receipts, hashes, assumptions, and limitations.

Run only one memory-heavy verifier at a time on a constrained host. A solver
timeout is not a failure of the property; report `unknown` unless a valid partial
result is clearly bounded and labeled.

## Network And Historical Blindness

Apply the selected `production`, `agile`, or `audit` profile. In historically blind
work, investigators must not access target CVEs, advisories, disclosures, later
fixes, patches, fix-selected commits, or coordinator ground truth. Generic C,
compiler, solver, standards, and formal-method documentation is allowed.

For prospective work, keep A history-restricted and B open only when the profile
explicitly calls for that asymmetry. Audit A's target-specific web access and
require a final declaration. Do not audit B's URLs.

## Resume And Seal

On resume, inspect the brief, source pin, running owned processes, formal receipts,
and latest artifacts. Continue from the strongest incomplete stage. Never use an
unfinished arm to redirect the other.

After both arms seal, compare formal properties and traces before post-seal
novelty/severity research. A convergent trace is corroboration of one mechanism,
not two vulnerabilities.
