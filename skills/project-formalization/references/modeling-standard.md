# C Modeling Standard

Use this standard for every formal harness, stub, contract, and completeness
claim.

## Production Fidelity

- Compile or translate the actual production C definitions whenever practical.
- Match architecture, endianness, integer widths, ABI, C dialect, defines,
  packing, alignment, and relevant compiler extensions.
- Keep production source immutable. Store harnesses and specifications elsewhere.
- Inventory every production translation unit included in the formal program.
- Confirm that the replay build uses the same essential configuration.

## Inputs And Assumptions

- Generate attacker-controlled or environment-controlled values nondeterministically.
- Use `assume` only for documented production preconditions or state reachability.
- Express desired safety behavior as assertions, ACSL clauses, or property files.
- Never assume the negation of a suspected bug or prune a difficult behavior
  merely to make verification finish.
- Record the source of every range, enum, pointer-alias, lifecycle, and protocol
  assumption.

## Stubs And Contracts

- Stub only code outside the claim boundary or code that cannot affect the
  selected property except through a documented contract.
- Preserve allocation, ownership, aliasing, failure, length, and side-effect
  behavior relevant to the property.
- Include failure and nondeterministic outcomes when production permits them.
- Record each replaced function, the contract, and the strongest omitted behavior.
- Treat an unconstrained stub as a modeling risk, not automatically as soundness.

## Bounds And Completeness

Record input lengths, object counts, loop unwinds, recursion depth, allocation
counts, thread bounds, state-machine steps, and bit widths. Explain why each bound
is security-meaningful.

For bounded model checking, require unwinding assertions, forward conditions, or
an equivalent per-loop completeness check before claiming bounded satisfaction.
For k-induction, preserve base, forward, and induction results. For abstract
interpretation, record widening, partitioning, initial states, alarms, and any
unsupported semantics. For deductive verification, inventory all generated and
discharged proof obligations.

## Counterexample Triage

Check that a trace:

1. Enters through a permitted production state.
2. Uses only modeled preconditions allowed by the real API.
3. Traverses production definitions or faithful contracts.
4. Violates the named property rather than a wrapper artifact.
5. Can be reduced without deleting the essential trigger.
6. Replays, or has a precise explanation for the replay mismatch.

Keep non-replaying traces as formal-only candidates or model-fidelity questions.

## Differential Sanity

Exercise the formal harness with at least one known-safe control and one deliberate
assertion failure. Where feasible, compare a bounded set of model executions with
the production implementation. Differential agreement supports model fidelity;
it does not replace formal completeness.
