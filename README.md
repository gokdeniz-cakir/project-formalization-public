# Project Formalization

Project Formalization pairs bounded formal methods, production replays, and
independent review to make vulnerability claims reproducible. This is the
public repository for already-disclosed case studies only.

The interactive DTLS ACK lab lives in [`site/`](site/). It is configured as a
Cloudflare Workers static-assets project; this repository does not contain a
route, custom-domain binding, account identifier, or deployment state.

## Public case studies

| Case | Project | What is included |
|---|---|---|
| [CVE-2026-10536](cases/curl/CVE-2026-10536/) | curl 8.20.0 | A minimal public-API ASan replay and a control. |
| [CVE-2026-6679](cases/wolfssl/CVE-2026-6679/) | wolfSSL 5.9.0 | Coordinator-owned evidence, a bounded arithmetic model, and the V3 lab. |
| [CVE-2026-5460](cases/wolfssl/CVE-2026-5460/) | wolfSSL TLS 1.3 PQC | A public-source correspondence note for the CVE-2026-5460 / CVE-2026-7531 family. |

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
