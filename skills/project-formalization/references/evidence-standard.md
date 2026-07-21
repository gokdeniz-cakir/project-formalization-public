# Formal Evidence Standard

Formal verification is a claim about a model, its assumptions, and a machine
checker. Runtime evidence is complementary, not a substitute.

## Verdicts

- `confirmed_violation`: a machine-checked counterexample plus fresh production
  replay and independent runtime evidence.
- `formal_only_candidate`: a machine-checked violation or witness that has not
  survived production replay.
- `bounded_satisfaction`: selected properties hold within declared bounds and
  all declared completeness checks pass.
- `proved_under_contracts`: all selected deductive or invariant proof obligations
  discharge under explicit contracts and assumptions.
- `unknown`: timeout, unsupported construct, incomplete model, missing backend,
  unresolved proof obligation, or replay uncertainty.

## Formal Gate

Every result other than an explicitly tool-unavailable `unknown` must identify:

- A real backend and exact version
- Execution environment, compiler, architecture, and solver
- Exact command(s) and exit status(es)
- Production translation units and property identifiers
- Model files, stubs, contracts, assumptions, and bounds
- Logs, proof obligations, witness, trace, or completeness evidence

The coordinator must validate that cited files exist and are hashed. A manifest
field is not proof that the tool ran; preserve the tool's raw output and receipt.

## Bounded Satisfaction

State the selected property, input/state bounds, loop/recursion bounds, object and
thread limits, and model assumptions. Require unwinding assertions, induction
conditions, exhaustive finite-domain enumeration, or an equivalent completeness
check for every claim described as complete. Never generalize bounded satisfaction
to unbounded safety.

## Deductive Proof

Record every proof obligation and its result. Include ACSL contracts, loop
invariants, variants, separation hypotheses, axioms, admitted lemmas, and solver
configuration. `proved_under_contracts` is invalid when an obligation is unknown,
timeout, inconsistent, or discharged only by an unreviewed axiom.

## Formal Candidate

Record the property identifier, backend trace/witness, bounds, assumptions, and
tool diagnostics. Try to replay the same behavior against an unmodified pinned
production build. A non-replaying trace remains a formal candidate or
model-fidelity question.

## Confirmed Violation

Require:

1. A machine-checked trace tied to a stated safety property.
2. A fresh build from the pinned source without production-source modifications.
3. A successful ASan, UBSan, LSan, MSan, Valgrind, CFI, or equivalent witness.
4. The closest useful negative control.
5. A checker-sanity test proving failures propagate.
6. Source, compiler, define, linkage, and formal-model provenance.
7. Mechanism-specific source events tied to the affected object and use site.

Do not infer code execution, disclosure, or arbitrary write from a formal memory
error alone.

## Unknown

Record the attempted backend, command, diagnostic, missing construct or resource
limit, model limitation, and best next step. Do not turn a runtime-only result
into a formal result merely to avoid `unknown`.
