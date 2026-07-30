---
name: api-contract-guard
description: Diff two API surfaces — the one you shipped and the one you are about to — and report only what breaks for callers you cannot see, then draft the changelog and name the semver bump. Reads OpenAPI JSON or a symbol export. Trigger when the user says "/api-contract-guard", "will this break callers", "is this a breaking change", "diff these two API versions", "what changed in the API", "draft the changelog", "what semver bump is this", or hands over a baseline and a candidate surface. It reports the direction correctly — a new required request field breaks callers, a new response field does not — and blocks only on genuinely breaking changes.
---

# API Contract Guard

An API is a promise, and the person changing it is looking at the code, not the
callers. The break is invisible from where the change is made: a new required
field is one word in a handler and a `400` for everyone who already integrated; a
renamed response key is a green test suite here and a silently empty screen in an
app you have never heard of.

This diffs two surfaces and reports only what breaks *for a caller* — which is not
the same as what changed — then drafts the changelog and tells you the semver bump
the change actually earns.

## Direction is the whole subtlety

What breaks a caller depends on which way a change points, and the two directions
are not symmetric:

- **Requests — adding constrains, removing relaxes.** Adding a *required* request
  parameter breaks every existing caller (they omit it). Removing a request
  parameter does not break them (they simply send something the server now
  ignores). So we flag the addition, not the removal.
- **Responses — removing constrains, adding relaxes.** Removing a response field
  breaks every caller that read it. Adding a response field does not break anyone
  (a caller that did not know about it still does not). So we flag the removal,
  not the addition.
- **Enums cut both ways.** Removing an enum value breaks the caller who *sends* it
  (requests) or who *receives and branches on* it (responses). Adding an enum
  value breaks only the caller who switches *exhaustively* with no default branch
  — a narrow, real, but low-severity case we name precisely rather than inflate.
- **Types — and the direction flips between request and response.** On a
  *request*, narrowing breaks: `string → integer`, `number → integer`, or
  `nullable → non-nullable` rejects values a caller was allowed to send. On a
  *response* the mirror image holds — what breaks a caller is the field getting
  **wider**: `non-nullable → nullable` crashes anything that dereferences it, and
  an opened enum delivers values the caller never handled. A response field that
  becomes *always present* is entirely safe and is not flagged.

Get this backwards and you cry wolf on safe changes while waving through the ones
that page someone. This skill is built around getting it right.

## Inputs

`--input` is the **baseline** surface (what callers integrate against today).
`--against` is the **candidate** (what you are about to ship). Both must be the
same shape; the shape is auto-detected:

**(a) OpenAPI JSON** — `paths` → method → `parameters` (with `required`),
`requestBody`, and `responses`.

**(b) A symbol export** — your own extraction of a code surface:

```json
{
  "symbols": [
    {
      "name": "create_user",
      "kind": "function",
      "params": [{ "name": "email", "required": true, "type": "string" }],
      "returns": "User",
      "deprecated": false
    }
  ]
}
```

A symbol may also carry a `fields` array (the shape it returns) so response-field
removals and type narrowings are diffed the same way as OpenAPI responses.

## How to run it

```
python scripts/api_contract_guard.py \
    --input baseline.json --against candidate.json \
    --outdir out/api-contract-guard
```

Both `--input` and `--against` are required. Feed it the two bundled templates to
see every finding at once:

```
python scripts/api_contract_guard.py \
    --input templates/surface.example.json \
    --against templates/surface.candidate.json --outdir out/api-contract-guard
```

## What you get

A ranked list of findings, a **changelog** in Keep-a-Changelog form
(`### Removed / ### Changed / ### Added / ### Deprecated`), and a **semver**
recommendation (`major` / `minor` / `patch`) derived strictly from the worst
finding present. The verdict is `block` the moment anything CRITICAL — a removed
operation or a new required field — appears.

## What it detects

- `AC001` **CRITICAL — an endpoint or symbol is gone.** Every caller using it
  breaks immediately.
- `AC002` **CRITICAL — a new required parameter with no default.** Every existing
  caller omits it and is rejected.
- `AC003` **HIGH — an optional parameter became required.** Callers that leaned on
  the default now have to supply it.
- `AC004` **HIGH — a response field is gone.** Callers that read it get nothing.
- `AC005` **HIGH — a type changed in a caller-breaking direction.** On a request
  that means narrowing (`string → enum`, `number → integer`, nullable →
  non-nullable): values that were legal are now rejected. On a response it means
  the opposite — widening, such as non-nullable → nullable or an enum opening up.
- `AC006` **MEDIUM — an enum value was removed.** Breaks the caller who sends or
  handles it.
- `AC007` **LOW — an enum value was added.** Breaks *only* consumers that switch
  exhaustively with no default branch; safe for everyone else.
- `AC008` **MEDIUM — a success status code was removed or changed.** A caller
  checking for exactly that code treats the new response as failure.
- `AC009` **LOW — something was newly deprecated.** Nothing breaks yet; this is
  the warning that a removal is coming.
- `AC010` **MEDIUM — a parameter looks renamed** (same position + same type, new
  name). Callers still sending the old name lose it silently.

## Limits — state these when you report

- **Only caller-breaking changes are reported.** Adding a response field, removing
  a request parameter, and widening a type are deliberately silent — they are safe
  by direction, and reporting them would be noise. Say this when the diff looks
  "incomplete": the omissions are the point.
- **Renames (AC010) are inferred, not known.** The heuristic is same location +
  same position + same type + different name. An edit that inserts or reorders
  parameters can hide a real rename or manufacture a false one. Every AC010 is a
  reading to confirm, never a fact — which is why it no longer suppresses
  anything. A rename guess used to cancel the `AC002` CRITICAL that the "new"
  name would otherwise raise, so a coincidence of position and type could
  downgrade a break every caller was about to hit. Both findings are now
  reported together: AC010 explains, AC002 decides the verdict.
- **`$ref`, `allOf`/`oneOf`/`anyOf`, and schemas nested deeper than two levels are
  not resolved.** A break hidden inside a `$ref` or a deep union is not seen. Flag
  heavily-`$ref`'d specs as only partially covered.
- **Symbol return *types* are not diffed for breakage.** Narrowing a return is not
  caller-breaking and widening rarely is; only a symbol's `fields` (its response
  shape) are compared. Return type changes surface in the operation list, not as
  findings.
- **The semver recommendation is mechanical.** It is the worst finding present,
  nothing more — it does not read your intent, your versioning policy, or whether
  you meant to ship a breaking change behind a flag.
- **Two shapes cannot be crossed.** An OpenAPI baseline against a symbol-export
  candidate is refused, not guessed — there is no honest mapping between them.

## Guardrails

Reads two surface files. Writes three artifacts to your output directory and
nothing else. No network, no code execution, no mutation of either surface. It
describes the difference between two promises; it keeps neither for you.
