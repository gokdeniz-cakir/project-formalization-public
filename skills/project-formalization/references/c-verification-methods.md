# C Verification Methods

Use this guide to select a machine-checking backend. Tool availability never
changes the meaning of a property; narrow the target or report `unknown` when a
backend cannot model it honestly.

## Selection Matrix

| Property or obstacle | Primary choice | Useful cross-check | Main caveat |
|---|---|---|---|
| Pointer validity, OOB, UAF, double free, leaks | CBMC or ESBMC | CPAchecker, Symbiotic, ASan replay | Bounded state and allocator models |
| Integer overflow, narrowing, size/write agreement | CBMC or ESBMC | Frama-C Eva/WP, UBSan replay | Distinguish intentional modular arithmetic |
| Parser completeness and bounded protocol state | CBMC or ESBMC | CPAchecker or Ultimate | Input and loop bounds must be meaningful |
| Global numeric invariants and absence of alarms | Frama-C Eva | Frama-C WP or CBMC | Precision and library models affect alarms |
| Functional/API contracts | Frama-C WP with ACSL | CBMC assertions | All proof obligations and axioms must be audited |
| Unbounded reachability or loop invariants | CPAchecker, Ultimate, 2LS | Frama-C WP | Tool may return unknown or require invariants |
| LLVM-level Horn-clause verification | SeaHorn | CBMC on source | Translation may lose source-level semantics |
| SV-COMP witness interoperability | CPAchecker, Ultimate, Symbiotic | Witness validator | SV-COMP itself is not a verifier |
| Candidate generation | KLEE or fuzzing | Formal backend and sanitizer replay | Path exploration is not general proof |

Prefer a second backend from a different family. Two wrappers around the same
solver and translation pipeline are weaker corroboration than genuinely
independent encodings.

## CBMC

Use CBMC as the default for bounded C safety properties. Compile the real
production units where practical, retain production types and preprocessor
defines, and use a harness with nondeterministic inputs.

Typical checks:

```sh
cbmc harness.c production.c \
  --function formal_entry \
  --pointer-check --bounds-check \
  --signed-overflow-check --conversion-check \
  --div-by-zero-check --undefined-shift-check \
  --unwinding-assertions --trace --json-ui
```

Enable `--unsigned-overflow-check`, floating-point checks, memory-leak checks,
and other properties only when they match the declared property. Use per-loop
unwind bounds when possible. Preserve failing property identifiers and the full
trace. A successful run without unwinding assertions or another completeness
argument is evidence only for the explored executions.

Use `goto-cc` and `goto-instrument` when whole build capture or instrumentation
is more faithful than direct source invocation. Record every linked GOTO unit.

## ESBMC

Use ESBMC as a bounded-model-checking alternative with SMT backends and useful
k-induction options. Start with memory, bounds, overflow, and assertion checks,
then add concurrency or k-induction only when the target requires them.

```sh
esbmc harness.c production.c \
  --function formal_entry \
  --pointer-check --bounds-check --overflow-check \
  --unlimited-k-steps --show-stacktrace
```

Pin the ESBMC version and selected SMT solver. Treat k-induction as proof only
when base, forward-condition, and inductive-step obligations all succeed under
audited assumptions.

## Frama-C Eva

Use Eva for abstract interpretation of numeric ranges, initializedness, pointer
targets, and runtime-error alarms. Supply realistic entry states and libc models.

```sh
frama-c harness.c production.c \
  -main formal_entry -eva -eva-precision 6 \
  -warn-signed-overflow -warn-unsigned-overflow
```

Preserve the alarm summary, hypotheses, slevel/partition settings, and whether
the analyzed behavior set over-approximates the production boundary. No alarms
is meaningful only when parsing, unsupported constructs, and initial-state
modeling are sound.

## Frama-C WP And ACSL

Use WP for functional contracts, memory separation, and deductive proof. Place
ACSL specifications beside copied harness/model files, or maintain a patch that
is never applied to the pinned production tree.

```sh
frama-c harness.c production.c \
  -main formal_entry -wp -wp-rte \
  -wp-prover alt-ergo,z3,cvc5 \
  -wp-report wp-report.json
```

Audit every `requires`, `assigns`, `ensures`, loop invariant, variant, axiom, and
admitted lemma. Report proved/unknown/timeout goals separately. A proof under a
false or stronger-than-production precondition is not a production safety proof.

## SV-COMP-Compatible Verification

Use a property file that names the exact claim, for example reachability,
valid-deref, valid-free, valid-memtrack, overflow, or termination. Run a concrete
backend such as CPAchecker, Ultimate Automizer, or Symbiotic and preserve its
GraphML/YAML witness when available.

```sh
cpachecker -spec property.prp -config config.properties program.i
symbiotic --prp property.prp program.c
```

Run the ecosystem's witness validator against the same preprocessed program,
architecture, and property. A validator rejection downgrades the result to
`unknown` or a tool-specific candidate.

## Other Formal Backends

- Use CPAchecker for configurable predicate/value analyses and witness-producing
  reachability or memory-safety checks.
- Use Ultimate Automizer for automata-based C reachability and termination.
- Use Symbiotic for LLVM-based slicing plus verification and SV-COMP properties.
- Use SeaHorn for LLVM-to-Horn verification when source translation is stable.
- Use 2LS for k-induction, abstract interpretation, and termination on suitable C.

Record the frontend, architecture, machine model, solver, and unsupported C
features for every backend.

## Runtime Support

Use Clang/GCC sanitizers, Valgrind, CFI, libFuzzer, AFL++, and debugger traces to
replay or refine formal candidates. They do not satisfy the formal-backend gate.

Typical replay build:

```sh
clang -O1 -g -fno-omit-frame-pointer \
  -fsanitize=address,undefined harness.c production.c -o replay
```

Use a separate checker-sanity mode that intentionally triggers the configured
oracle. Preserve the closest negative control and exact build/link provenance.
