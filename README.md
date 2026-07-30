# API Contract Guard

Diff two API surfaces, report what breaks for callers, and draft the changelog.

> ## How to run it
> See [setup.md](setup.md), then run `/api-contract-guard`.

## Included

- `/api-contract-guard` Scout skill
- `scripts/api_contract_guard.py` — the deterministic engine
- `lib/scoutkit/` — vendored shared library, so this repo runs on its own
- `templates/` — a bundled, fabricated example input
- `tests/` — the full pytest suite for this skill

## Quick start

Requires Python 3.10 or later. No third-party packages.

```
python scripts/api_contract_guard.py \
  --input templates/surface.example.json \
  --outdir out/api-contract-guard
```

Input: Two API surface descriptions (OpenAPI or a symbol export) to compare.

## Artifacts

- `api-contract-guard.json`
- `api-contract-guard.md`
- `api-contract-guard.html`

Canonical JSON validates against `references/report-schema.json`. The HTML is
self-contained — embedded CSS, no scripts, no external references — so it renders
identically offline and inside a SharePoint or OneDrive preview sandbox.

## Exit codes

`0` pass · `1` review · `2` block · `3` evidence error

Gating is opt-in via `--fail-on never|review|block`, so this never fails a pipeline
unless you ask it to.

## What it does not do

It does not fix anything. This skill is read-only by construction: it reports,
classifies, and recommends, and a human decides. That is why it is safe to run
unattended, and why a `pass` verdict is never permission to proceed.

It also never fetches its own evidence. You give it a file. That separation is what
makes it testable offline and what lets it promise it wrote nothing back.

## Data safety

This shared package contains no customer names, account identifiers, contact emails,
secrets, internal pricing, or deal strategy. Every bundled file under `templates/` is
fabricated — example addresses use the `.example`, `.invalid`, and `.local` reserved
domains, and example secrets are non-functional literals.

Real evidence for this skill is code you own. Point the engine at it with `--input`,
and keep any artifact it produces out of version control — a findings report is a
map of where the problems are.

## 🔍 What this skill accesses

Shown as **capability badges** on the catalog card — passive transparency, no prompt
on install. This skill can:

- 📁 reads local files you point it at
- 💾 writes files locally
- ⌨️ runs shell / Node / Python locally

_Nothing else. It never sends data to third parties, performs no network I/O, writes
nothing to a tenant, and respects Scout's runtime permission model for every action._

## Provenance

Built as part of the Scout Code Ops Kit — eight deterministic, offline skills that
read a codebase and report what it is hiding — and published here as a standalone
entry. Version 1.0.0.
