# Evidence Standard

Apply rigor in proportion to the claim.

## Verdicts

- `confirmed_violation`: a formal or rigorous analysis result plus independent production replay
- `formal_only_candidate`: a formal counterexample that has not survived production replay
- `bounded_satisfaction`: the declared bounded analysis satisfies the selected properties
- `unknown`: inconclusive work, timeout, unsupported construct, harness uncertainty, or tool failure

Use `cause_assessment` to distinguish `production_defect`, `harness_fidelity_artifact`, `contract_misuse_unresolved`, `not_applicable`, and `unknown`.

## Unknown

An honest unknown should be easy to finish. Record:

- The method or tool attempted
- The decisive command and diagnostic when available
- The main limitation and best next step
- The blindness declaration and any access incident

Do not require a complete artifact inventory, per-file hashes, negative controls, critic acceptance, or coordinator reruns. Preserve a useful raw log when one exists.

## Bounded Satisfaction

Record the selected properties, meaningful input and loop/recursion bounds, material models and assumptions, and whether unwinding or analogous completeness checks passed. State the result as bounded, never as general safety. Hash proof artifacts when they are intended for later independent audit; otherwise a committed final snapshot is enough in `agile` mode.

## Formal Candidate

Record the tool version, final command, property identifier, bounds, material models, and counterexample. Try to replay the same behavior against an unmodified pinned production build. A non-replaying trace remains a candidate, harness-fidelity artifact, contract-misuse question, or unknown.

## Confirmed Violation

Require:

1. A convincing analysis trace tied to a stated safety property.
2. A fresh build from the pinned source without production-source modifications.
3. A successful witness under ASan, LSan, UBSan, Valgrind, or another independent oracle.
4. The closest useful negative control, changing the essential trigger when feasible.
5. A checker-sanity test proving failures propagate.
6. Enough source, build, and linkage provenance to establish that the pinned production code ran.

For a confirmed claim, preserve exact commands, exits, relevant logs, trace, material bounds and assumptions, and hashes of the evidence being cited. The coordinator or a critic should independently challenge and rerun the discriminating gates.

## Mechanism

Tie a positive result to concrete source events:

- UAF: allocation, free, later use, object identity, and relevant stacks
- OOB: object bounds, computed index or length, and access
- Leak: allocation, ownership path, lost reachability or missing cleanup, and termination scope
- Double free: allocation, first free, second free, and object identity

For API misuse, compare the actual documented contract and stock-build behavior. A sanctioned happy path alone does not resolve an unsanctioned crash.

In retrospective work, shared files, options, or symptoms do not establish a CVE match. Compare the affected object, transition, and use site against the advisory and patch after both arms finish.

## Review

In `agile` mode, review the final result and add a critic only for a credible candidate or genuine modeling ambiguity. Ask for the highest-risk issues, not completion of a universal checklist.

In `audit` mode, immutable design/final checkpoints, exhaustive artifact hashing, and independent coordinator reruns may be required.
