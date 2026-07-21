# Project Formalization

Project Formalization pairs bounded formal methods, production replays, and
independent review to make vulnerability claims reproducible. This is the
public repository for already-disclosed case studies only.

## How We Used Codex and GPT-5.6

All Project Formalization experiments were conducted inside **Codex**, using
**GPT-5.6 models exclusively**, with extensive use of **GPT-5.6 Sol** for the
long-horizon work. Codex was the execution environment for the full research
loop: setting up isolated agent roles, inspecting and bounding target
components, writing formal models and replay harnesses, running verifiers and
sanitizers, preserving evidence, and having independent critics challenge
each claim.

The project uses the model's mathematical reasoning alongside its software
security knowledge. In practice, the coordinator sets a safety property and
two independent investigators approach it with different framings; each is
then critically reviewed before evidence is compared. Formal proofs and
production replays remain the basis for a published claim, rather than model
confidence alone.

The two main skills of the project were also created via heavy collaboration with GPT 5.6 family models.

## Public case studies

| Case | Project | What is included |
|---|---|---|
| [CVE-2026-10536](cases/curl/CVE-2026-10536/) | curl 8.20.0 | A minimal public-API ASan replay and a control. |
| [CVE-2026-6679](cases/wolfssl/CVE-2026-6679/) | wolfSSL 5.9.0 | Coordinator-owned evidence, a bounded arithmetic model, and the V3 lab. |
| [CVE-2026-5460](cases/wolfssl/CVE-2026-5460/) | wolfSSL TLS 1.3 PQC | A public-source correspondence note for the CVE-2026-5460 / CVE-2026-7531 family. |

## Skills

The two reusable harness skills live in [`skills/`](skills/):
[`project-formalization`](skills/project-formalization/) is C and formal-methods
focused, while [`project-formalization-raw`](skills/project-formalization-raw/)
is the general-purpose, method-agnostic version.

## Publication boundary

This repository contains only material whose underlying issue is already
publicly disclosed, plus independently reviewable models and controls. It
intentionally excludes undisclosed research, unassigned findings, private
triage records, investigator workspaces, prompts, and source checkouts.

Run the release gate before publishing or deploying:

```powershell
python scripts/audit-publication.py
python scripts/test-model.py
```

The gate permits only the CVE identifiers listed in
[`PUBLICATION_MANIFEST.yml`](PUBLICATION_MANIFEST.yml), rejects local research
paths and private-workspace markers, and checks that each published asset is
explicitly allowlisted.

## Local development

Install the pinned Wrangler version, then run the static site locally:

```powershell
npm install
npm run dev
```

For a dependency-free preview of the site alone:

```powershell
python -m http.server 8787 --directory site
```

The Cloudflare project is deliberately not deployed by this repository setup.
When you are ready to publish, attach the desired custom domain in Cloudflare
and deploy from a reviewed commit using your normal release process.

## Method

The project workflow and claim standard are documented in
[`methodology/`](methodology/). Case-specific evidence and claim boundaries
live alongside each published case.
