# Target Selection

## Inputs

The user chooses the project and may choose the component. Determine prospective or retrospective mode and the intended safety-property family. Use a disposable checkout for reconnaissance.

For prospective work on a current production release, public vulnerability
history may inform component ranking. Prefer clusters that reveal complex
ownership, state, or policy boundaries rather than merely sending agents back
to a patched line. Keep the shared properties independently meaningful.

For retrospective work, default to source-only reconnaissance. If the user explicitly authorizes CVE-informed target selection, the coordinator may inspect ground truth before choosing the component. Keep it outside the baseline and investigator-visible storage. Use it only to choose a defensible component boundary; describe the target and properties neutrally without identifiers, mechanisms, suspected locations, patches, or expected outcomes.

If the user supplied a plausible component and asked to start, proceed. Recommend a replacement only when the component is clearly too broad, cannot be replayed, or has no independently meaningful safety property. When the user did not choose a component, recommend one target and two alternatives, then wait for that choice.

## Snapshot

- Prospective: prefer the latest stable release or exact upstream commit available at the experiment cutoff.
- Retrospective: use the vulnerable pre-patch revision while keeping the advisory, CVE, patch, and known mechanism coordinator-only. Pre-run access requires explicit user authorization; otherwise wait until both arms seal.
- Pin the exact commit. Record an archive hash or signature when practical. Treat missing signatures as a provenance note, not a separate approval ceremony.

## Practical Fit

Rank candidates on three dimensions:

- **Opportunity:** attacker-controlled influence, ownership or lifetime transitions, narrowing or representation changes, and interactions across otherwise legal operations
- **Evidence yield:** a fresh production replay, deterministic runtime oracle, and useful adjacent negative control
- **Tractability:** bounded state, controllable inputs, selectable properties, and a modest dependency closure

Look for:

- A cohesive lifecycle, ownership path, parser slice, or state machine
- Safety properties expressible without encoding a suspected bug
- Inputs that a harness can control
- Dependencies that can be compiled, modeled, or excluded without replacing the behavior under study
- A concrete production replay under a sanitizer, Valgrind, or an equivalent oracle
- A build that can be reproduced from the pinned revision

This is a judgment, not a checklist that must be documented field by field. Reject only material mismatches such as effectively unbounded distributed state, policy questions masquerading as safety properties, or a target whose meaningful replay requires modifying production code.

## Feasibility Check

Use a rejection check:

1. Identify the smallest plausible production entry and its dependency closure.
2. Confirm a controllable input, meaningful invariant, production oracle, and nearby negative control.
3. Compile a slice or measure model size only when the result is cheap and decision-relevant.

Reject or narrow targets with effectively unbounded state, an impractical build environment, no credible production replay, or a dependency closure obviously beyond the available method.

## Scope

Keep two boundaries:

- **Claim boundary:** production behavior against which a result may be asserted.
- **Readable dependency closure:** transitive source, headers, and build files needed to understand or compile the claim boundary.

Reading the dependency closure is not a scope breach. Expanding the claim boundary is a material change and should be reported.

## Recommendation

Give one recommended component with likely properties, method, runtime oracle, and main modeling risk. Give two brief alternatives and the snapshot recommendation. Avoid exhaustive freeze-packet prose.

For production-profile investigator framing, compare:

- A positive-premise arm that is not told the pin is current production and is
  restricted from target-specific vulnerability history.
- A neutral arm that may independently browse any public history.

This balances directed search against tunnel vision without feeding either arm
the coordinator's target rationale. The exact pin remains visible for
reproducibility; only its current-production status is withheld from A.
