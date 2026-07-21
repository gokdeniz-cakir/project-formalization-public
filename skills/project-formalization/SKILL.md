---
name: project-formalization
description: Plan, run, resume, and audit C-focused vulnerability experiments that require machine-checked formal verification of software safety properties. Use when Codex must verify memory safety, undefined behavior, arithmetic, API-state, ownership, parser, serialization, or protocol invariants in C with bounded model checking, abstract interpretation, deductive verification, or SV-COMP-compatible verifiers; preserve formal models and counterexamples; and replay violations against pinned production code under sanitizers. Do not use for runtime-only or method-agnostic investigations; use project-formalization-raw instead.
---

# Project Formalization

Require a real formal backend. Do not label source review, static heuristics,
fuzzing, sanitizers, exhaustive examples, or manual invariant reasoning as formal
verification.

## Keep The Scope Honest

- Restrict production claims to C code and C-compatible ABI boundaries. Treat C++,
  assembly, generated code, and external libraries as explicit modeled boundaries.
- Select a bounded component with a production entry point, controllable input,
  meaningful safety property, modest dependency closure, and credible replay.
- Prefer memory lifetime, pointer validity, bounds, integer/size consistency,
  initializedness, ownership, parser completeness, state-machine, and cleanup
  properties.
- Keep the pinned production source unmodified. Put harnesses, specifications,
  models, and build artifacts outside it.

Read [target-selection.md](references/target-selection.md) when choosing or
replacing a target.

## Preflight The Formal Environment

Run `python scripts/formal_runner.py probe --json`. On Windows, probe native
tools and WSL distributions; prefer the environment with the strongest usable
C verifier and reproducible build closure. Record the environment, exact tool
version, compiler, solver, and command prefix.

Choose at least one primary machine-checking backend:

- CBMC or ESBMC for bounded C memory-safety, arithmetic, and assertion checks.
- Frama-C Eva for sound abstract interpretation within its declared model, and
  Frama-C WP with ACSL plus Why3/Alt-Ergo/Z3/CVC5 for deductive verification.
- CPAchecker, Ultimate Automizer, or Symbiotic for SV-COMP-style reachability,
  memory-safety properties, and independently checkable witnesses.
- SeaHorn or 2LS when their C/LLVM modeling and invariant engines fit better.

SV-COMP is a property and witness ecosystem, not a verifier by itself. Pair its
property files and witness validators with an actual backend. Use KLEE or other
symbolic execution only to find candidates unless path coverage and completeness
are independently established. Use ASan, UBSan, LSan, MSan, Valgrind, fuzzers,
and CFI only as runtime support and replay oracles.

Read [c-verification-methods.md](references/c-verification-methods.md) before
selecting tools or writing commands.

If no formal backend can analyze the boundary, install or use an isolated WSL or
container toolchain when routine and authorized, narrow the target, or finish
`unknown`. Never silently downgrade to runtime-only analysis.

## Freeze A Formal Plan

Create the neutral brief from [freeze.yml](assets/templates/freeze.yml). Before
rendering the baseline, fill:

- Exact source pin, C dialect, build defines, production units, and entry point
- Property identifiers and their mapping to assertions, ACSL clauses, or
  SV-COMP property files
- Primary formal tool, execution environment, version command, analysis command,
  and expected witness or proof format
- Environment models, stubs, contracts, assumptions, bounds, and completeness
  strategy
- Secondary formal cross-check or an explicit reason it is infeasible
- Runtime replay oracle, closest negative control, and checker-sanity plan

Use `workflow.method_policy: formal_required`, `target.language: c`, and
`tooling.formal.required: true`. Keep `expected_verdict: null` and keep known
vulnerabilities, fixes, and ground truth out of investigator-visible files.

Read [modeling-standard.md](references/modeling-standard.md) before accepting a
formal plan or reviewing assumptions.

## Run Machine-Checked Verification

Use two isolated investigators by default. Every arm must run at least one formal
backend. Prefer independent backend families when the target supports them, such
as CBMC versus Frama-C/CPAchecker, while keeping source identity and property
meaning identical.

For each arm:

1. Compile or translate the production C units with the real defines and headers.
2. Build a harness using nondeterministic inputs. Use assumptions only for true
   production preconditions; express safety requirements as assertions or formal
   contracts.
3. Keep stubs smaller than the code they replace and give every behavior-changing
   stub a documented contract and modeling risk.
4. Run wrapper sanity, selected properties, completeness checks, and then broader
   coverage. Tune solver/resource options without changing property meaning.
5. Record every material formal run with
   `python scripts/formal_runner.py run ... -- <tool command>` so command, tool,
   environment, exit status, and output hashes are preserved.
6. Preserve proof obligations, witnesses, counterexample traces, unwinding
   assertions, invariants, alarms, and decisive diagnostics.
7. Challenge positives with a second backend, witness validator, or focused critic
   before making a production claim.

Do not call a sampled test loop a proof. Do not call bounded satisfaction complete
unless all declared loops/recursion and object/input bounds are covered by the
tool's completeness mechanism. Do not call a Frama-C WP result proved while
relevant obligations remain `unknown`, `timeout`, or admitted.

## Replay Counterexamples

A formal counterexample is a candidate until it survives replay against a fresh,
unmodified pinned production build. Require:

- The same essential input and state transition
- ASan, UBSan, LSan, MSan, Valgrind, CFI, or another independent runtime oracle
- The closest useful negative control
- Checker sanity proving the runtime oracle and process exit propagate failures
- Source, build, define, and linkage provenance
- Mechanism-specific source events tied to the violated property

Do not weaken the formal property to match a replay. Diagnose mismatches as model
fidelity, contract misuse, unreachable state, nondeterminism, or tool unsoundness.

## Classify Evidence

- `confirmed_violation`: machine-checked counterexample plus successful fresh
  production replay, control, checker sanity, and mechanism evidence.
- `formal_only_candidate`: machine-checked violation or witness that has not
  replayed in production.
- `bounded_satisfaction`: all selected properties pass within explicit bounds and
  the declared completeness checks pass.
- `proved_under_contracts`: all relevant deductive or invariant proof obligations
  are discharged under listed contracts and assumptions.
- `unknown`: timeout, unsupported construct, incomplete model, unresolved alarm,
  missing tool, or inconclusive replay.

Runtime-only findings belong in `project-formalization-raw`, not in a
formal verdict. Read [evidence-standard.md](references/evidence-standard.md) when
validating a result.

## Preserve Independence And Finish

Keep separate investigator workspaces and out-of-band prompts. Never inspect a
sibling arm or use one arm's result to coach another before both seal. Apply the
historical-source and production-profile rules in
[experiment-protocol.md](references/experiment-protocol.md).

After sealing, compare arms, audit novelty and severity, and inspect public
history only as the selected profile permits. Never contact maintainers, publish,
push confidential results, or claim code execution without separate evidence and
explicit user authorization.

Use [interfaces.md](references/interfaces.md) for CLI/schema details and
[post-seal-audit.md](references/post-seal-audit.md) for the final audit. Disclose
relevant web access, formal-tool limitations, model assumptions, and every
cross-agent isolation incident.
