# Formal C Target Selection

## Candidate Funnel

The user chooses the upstream project. When the component is missing, inspect a
disposable checkout and rank C candidates by:

1. Safety meaning: memory lifetime, bounds, arithmetic, initializedness,
   ownership, parser, serialization, or protocol-state invariant.
2. Formal tractability: bounded state, controllable inputs, compilable C closure,
   modelable external calls, and a realistic completeness strategy.
3. Replay value: a production entry point, deterministic oracle, closest control,
   and fresh pinned build.
4. Independence value: a property that two investigators and preferably two
   backend families can encode without sharing suspected locations or triggers.

Recommend one target and two alternatives, then wait for the user's target choice
when the component was not supplied.

## Target Card

Record:

- C component, production entry, and exact source units
- Controlled input and reachable state
- Safety property IDs and formal statement
- Primary and secondary backend candidates
- Compiler, architecture, defines, libc/OS model, and execution environment
- Assumptions, stubs, bounds, completeness checks, and main modeling risk
- Fresh-build replay oracle and closest negative control

## Lightweight Rejection Check

Inspect the smallest production entry and dependency closure. Confirm that:

- The selected C code compiles or translates with the pinned configuration.
- The formal backend can represent the relevant pointers, integers, control state,
  and external contracts.
- The property is not merely a policy preference or a sampled test expectation.
- A meaningful finite bound or deductive contract exists.
- A counterexample can be mapped back to a production API and replayed.

Reject targets with effectively unbounded distributed state, no trustworthy
initial-state model, no formal backend, no replay path, or a boundary that requires
modifying production code.

## Formal Selection Heuristics

- Start with CBMC for small C lifecycle, parser, serializer, and ownership slices.
- Use ESBMC when SMT, k-induction, or solver diversity materially helps.
- Use Frama-C Eva for broad over-approximate alarms and WP for ACSL contracts.
- Use CPAchecker, Ultimate, Symbiotic, SeaHorn, or 2LS for reachability and
  invariant problems that exceed a straightforward BMC encoding.
- Use SV-COMP property files and witness validation when interoperability matters.

Read [c-verification-methods.md](c-verification-methods.md) and
[modeling-standard.md](modeling-standard.md) before freezing the method.
