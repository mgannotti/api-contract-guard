#!/usr/bin/env python3
"""api-contract-guard — what this change breaks for the callers you cannot see.

An API is a promise, and the person changing it is looking at the code, not the
callers. So the break is invisible from where the change is made: a new required
field is one word in a handler and a 400 for everyone who already integrated; a
renamed response key is a green test suite and a silently empty screen in an app
you have never heard of.

This diffs two surfaces — the one you shipped and the one you are about to — and
reports only what breaks *for a caller*, which is not the same as what changed.
The direction is the whole subtlety: adding a required request field breaks
callers; adding a response field does not. Removing a response field breaks
callers; removing a request field usually does not. It gets that asymmetry right,
drafts the changelog, and tells you the semver bump the change actually earns.

Offline. Read-only. Two descriptions in, a verdict out. It changes neither.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from scoutkit import (  # noqa: E402
    Finding,
    Report,
    Severity,
    read_json,
)
from scoutkit.cli import run  # noqa: E402
from scoutkit.io import EvidenceError  # noqa: E402

SKILL = "api-contract-guard"
TITLE = "API Contract Guard — what this change breaks for callers"

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "options", "head", "trace")

# How wide a type is — how many values it accepts. Narrowing (a smaller number)
# rejects inputs a caller was allowed to send; widening does not break anyone.
TYPE_BREADTH = {
    "any": 6, "object": 5, "array": 4, "string": 3,
    "number": 2, "float": 2, "double": 2,
    "integer": 1, "int": 1, "long": 1, "boolean": 1, "bool": 1,
}

# The changelog bucket each finding belongs in, Keep-a-Changelog style.
CHANGELOG_BUCKET = {
    "AC001": "removed", "AC004": "removed", "AC006": "removed", "AC008": "removed",
    "AC002": "changed", "AC003": "changed", "AC005": "changed", "AC010": "changed",
    "AC007": "added",
    "AC009": "deprecated",
}
# Any of these present and the change is breaking: a major bump.
MAJOR_CODES = frozenset({"AC001", "AC002", "AC003", "AC004", "AC005", "AC006", "AC008", "AC010"})
# These alone are additive or advisory: a minor bump.
MINOR_CODES = frozenset({"AC007", "AC009"})


@dataclass(frozen=True, slots=True)
class Param:
    """A request input: a query/path/header parameter or a request-body field."""

    name: str
    required: bool
    type: str
    enum: tuple[str, ...]
    nullable: bool
    has_default: bool
    location: str
    position: int


@dataclass(frozen=True, slots=True)
class ResponseField:
    """A field a caller reads out of a success response."""

    name: str
    type: str
    enum: tuple[str, ...]
    nullable: bool
    required: bool


@dataclass(frozen=True, slots=True)
class Operation:
    """One comparable unit: an endpoint (METHOD path) or an exported symbol."""

    key: str
    kind: str
    params: tuple[Param, ...]
    fields: tuple[ResponseField, ...]
    statuses: tuple[str, ...]
    returns: str
    deprecated: bool


# --- shape reading ---------------------------------------------------------

def _enum_of(schema: dict) -> tuple[str, ...]:
    values = schema.get("enum") if isinstance(schema, dict) else None
    if not isinstance(values, list):
        return ()
    return tuple(sorted(str(v) for v in values))


def _type_of(schema) -> tuple[str, bool]:
    """Return (type, nullable). Handles OAS 3.0 ``nullable`` and 3.1 type lists."""
    if not isinstance(schema, dict):
        return "", False
    raw = schema.get("type")
    nullable = bool(schema.get("nullable", False))
    if isinstance(raw, list):
        nullable = nullable or ("null" in raw)
        concrete = [t for t in raw if t != "null"]
        return (str(concrete[0]) if concrete else ""), nullable
    return (str(raw) if raw else ""), nullable


def _flatten_fields(schema: dict, prefix: str, depth: int, out: list[ResponseField]) -> None:
    if not isinstance(schema, dict):
        return
    props = schema.get("properties")
    if not isinstance(props, dict):
        return
    required = set(schema.get("required", []) if isinstance(schema.get("required"), list) else [])
    for name in sorted(props):
        sub = props[name] if isinstance(props[name], dict) else {}
        full = f"{prefix}{name}"
        type_str, nullable = _type_of(sub)
        out.append(ResponseField(full, type_str, _enum_of(sub), nullable, name in required))
        if depth < 2 and sub.get("type") == "object":
            _flatten_fields(sub, f"{full}.", depth + 1, out)


def _json_schema(container: dict) -> dict:
    """The JSON schema out of an OpenAPI content map, preferring application/json."""
    content = container.get("content") if isinstance(container, dict) else None
    if not isinstance(content, dict) or not content:
        return {}
    media = content.get("application/json")
    if not isinstance(media, dict):
        media = next((v for v in content.values() if isinstance(v, dict)), {})
    schema = media.get("schema")
    return schema if isinstance(schema, dict) else {}


def _openapi_operation(key: str, spec: dict, shared_params: list) -> Operation:
    params: list[Param] = []
    by_location: dict[str, int] = {}

    def next_position(location: str) -> int:
        idx = by_location.get(location, 0)
        by_location[location] = idx + 1
        return idx

    for raw in list(shared_params) + list(spec.get("parameters", []) or []):
        if not isinstance(raw, dict) or not raw.get("name"):
            continue
        schema = raw.get("schema") if isinstance(raw.get("schema"), dict) else {}
        type_str, nullable = _type_of(schema)
        location = str(raw.get("in", "query"))
        params.append(Param(
            name=str(raw["name"]),
            required=bool(raw.get("required", False)),
            type=type_str,
            enum=_enum_of(schema),
            nullable=nullable,
            has_default=("default" in raw) or ("default" in schema),
            location=location,
            position=next_position(location),
        ))

    body_schema = _json_schema(spec.get("requestBody", {}))
    if body_schema:
        body_required = set(body_schema.get("required", [])
                            if isinstance(body_schema.get("required"), list) else [])
        props = body_schema.get("properties")
        if isinstance(props, dict):
            for name in props:
                sub = props[name] if isinstance(props[name], dict) else {}
                type_str, nullable = _type_of(sub)
                params.append(Param(
                    name=str(name),
                    required=name in body_required,
                    type=type_str,
                    enum=_enum_of(sub),
                    nullable=nullable,
                    has_default=("default" in sub),
                    location="body",
                    position=next_position("body"),
                ))

    responses = spec.get("responses") if isinstance(spec.get("responses"), dict) else {}
    statuses = tuple(sorted(str(code) for code in responses if _is_success(str(code))))
    fields: list[ResponseField] = []
    success = _pick_success(responses)
    if success is not None:
        _flatten_fields(_json_schema(responses[success]), "", 0, fields)

    return Operation(
        key=key,
        kind="endpoint",
        params=tuple(params),
        fields=tuple(sorted(fields, key=lambda f: f.name)),
        statuses=statuses,
        returns="",
        deprecated=bool(spec.get("deprecated", False)),
    )


def _is_success(code: str) -> bool:
    return bool(re.match(r"^2\d\d$", code)) or code.lower() == "2xx"


def _pick_success(responses: dict) -> str | None:
    codes = [str(c) for c in responses if _is_success(str(c))]
    numeric = sorted(c for c in codes if c.isdigit())
    if numeric:
        return numeric[0]
    return sorted(codes)[0] if codes else None


def _openapi_surface(data: dict) -> dict[str, Operation]:
    surface: dict[str, Operation] = {}
    paths = data.get("paths", {})
    for path in sorted(paths):
        item = paths[path]
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters", []) if isinstance(item.get("parameters"), list) else []
        for method in HTTP_METHODS:
            spec = item.get(method)
            if isinstance(spec, dict):
                key = f"{method.upper()} {path}"
                surface[key] = _openapi_operation(key, spec, shared)
    return surface


def _symbol_operation(sym: dict) -> Operation:
    params: list[Param] = []
    for idx, raw in enumerate(sym.get("params", []) or []):
        if not isinstance(raw, dict) or not raw.get("name"):
            continue
        default = raw.get("default")
        params.append(Param(
            name=str(raw["name"]),
            required=bool(raw.get("required", False)),
            type=str(raw.get("type", "")),
            enum=_enum_of(raw),
            nullable=bool(raw.get("nullable", False)),
            has_default=("default" in raw and default is not None),
            location="arg",
            position=idx,
        ))

    returns = sym.get("returns")
    fields: list[ResponseField] = []
    if isinstance(sym.get("fields"), list):
        fields = _symbol_fields(sym["fields"])
    elif isinstance(returns, dict):
        fields = _symbol_fields(returns.get("fields", [])) or _return_object_fields(returns)
    returns_str = returns if isinstance(returns, str) else (
        str(returns.get("type", "object")) if isinstance(returns, dict) else "")

    return Operation(
        key=str(sym.get("name", "")),
        kind=str(sym.get("kind", "symbol")),
        params=tuple(params),
        fields=tuple(sorted(fields, key=lambda f: f.name)),
        statuses=(),
        returns=returns_str,
        deprecated=bool(sym.get("deprecated", False)),
    )


def _symbol_fields(items: list) -> list[ResponseField]:
    out: list[ResponseField] = []
    for raw in items:
        if isinstance(raw, dict) and raw.get("name"):
            out.append(ResponseField(
                name=str(raw["name"]),
                type=str(raw.get("type", "")),
                enum=_enum_of(raw),
                nullable=bool(raw.get("nullable", False)),
                required=bool(raw.get("required", True)),
            ))
    return out


def _return_object_fields(returns: dict) -> list[ResponseField]:
    out: list[ResponseField] = []
    _flatten_fields(returns, "", 0, out)
    return out


def _symbol_surface(data: dict) -> dict[str, Operation]:
    surface: dict[str, Operation] = {}
    for sym in data.get("symbols", []):
        if isinstance(sym, dict) and sym.get("name"):
            op = _symbol_operation(sym)
            surface[op.key] = op
    return surface


def load_surface(path: str) -> tuple[str, dict[str, Operation]]:
    """Read a surface file and auto-detect its shape (OpenAPI or symbol export)."""
    data = read_json(path)
    if isinstance(data, dict) and isinstance(data.get("paths"), dict):
        return "openapi", _openapi_surface(data)
    if isinstance(data, dict) and isinstance(data.get("symbols"), list):
        return "symbols", _symbol_surface(data)
    raise EvidenceError(
        f"unrecognized surface in {path}: expected an OpenAPI document with a 'paths' "
        f"object or a symbol export with a 'symbols' array"
    )


# --- comparison ------------------------------------------------------------

def _narrowings(ot: str, oe: tuple, on: bool, nt: str, ne: tuple, nn: bool) -> list[str]:
    """Ways ``new`` accepts fewer values than ``old`` — each one breaks a caller.

    This is *request* direction. An input that accepts less than it used to
    rejects traffic that previously worked.
    """
    reasons: list[str] = []
    if on and not nn:
        reasons.append("nullable became non-nullable")
    if not oe and ne:
        reasons.append(f"an open {ot or 'value'} was constrained to a fixed set")
    if ot and nt and ot != nt:
        ob, nb = TYPE_BREADTH.get(ot.lower()), TYPE_BREADTH.get(nt.lower())
        if ob is not None and nb is not None and nb < ob:
            reasons.append(f"{ot} narrowed to {nt}")
    return reasons


def _widenings(ot: str, oe: tuple, on: bool, nt: str, ne: tuple, nn: bool) -> list[str]:
    """Ways ``new`` returns more than ``old`` — each one breaks a caller.

    Responses are the mirror of requests and must not share a direction. What
    breaks a caller reading a response is the field getting *wider*: a value
    that was always present becoming null, a closed set opening up, a type
    growing beyond what the caller's parser accepts.

    Applying the request rule here inverts both halves — it reports
    ``nullable -> non-nullable`` (a field that is now always present, entirely
    safe) as breaking, and stays silent on ``non-nullable -> nullable``, which
    crashes every caller that dereferences it.
    """
    reasons: list[str] = []
    if not on and nn:
        reasons.append("a field that was always present can now be null")
    if oe and not ne:
        reasons.append("a fixed set of values was opened up")
    if ot and nt and ot != nt:
        ob, nb = TYPE_BREADTH.get(ot.lower()), TYPE_BREADTH.get(nt.lower())
        if ob is not None and nb is not None and nb > ob:
            reasons.append(f"{ot} widened to {nt}")
    return reasons


@dataclass
class Diff:
    findings: list[tuple] = field(default_factory=list)  # (code, severity, title, detail, locator, fix, evidence)
    changelog_lines: dict[str, list[str]] = field(default_factory=lambda: {
        "removed": [], "changed": [], "added": [], "deprecated": []})
    additive: bool = False

    def emit(self, code, severity, title, detail, locator, fix, evidence="", changelog=""):
        self.findings.append((code, severity, title, detail, locator, fix, evidence))
        bucket = CHANGELOG_BUCKET.get(code)
        if bucket and changelog:
            self.changelog_lines[bucket].append(changelog)


def _match_renames(bparams: dict, cparams: dict) -> list[tuple[str, str]]:
    """Params that look renamed: same location, same position, same type, new name.

    The pairing is deliberately generous, because the *narrative* is useful: a
    reader wants to know that `nickname` probably became `handle`. What it must
    never do is silence the consequence — see the AC002 loop below, which no
    longer treats a rename as a reason to skip a newly required parameter.
    """
    removed = [p for n, p in bparams.items() if n not in cparams]
    added = [p for n, p in cparams.items() if n not in bparams]
    pairs: list[tuple[str, str]] = []
    taken: set[str] = set()
    for old in sorted(removed, key=lambda p: (p.location, p.position, p.name)):
        for new in sorted(added, key=lambda p: (p.location, p.position, p.name)):
            if new.name in taken:
                continue
            if old.location == new.location and old.position == new.position and old.type == new.type:
                pairs.append((old.name, new.name))
                taken.add(new.name)
                break
    return pairs


def compare_operation(diff: Diff, bop: Operation, cop: Operation) -> None:
    where = bop.key
    bparams = {p.name: p for p in bop.params}
    cparams = {p.name: p for p in cop.params}

    renames = _match_renames(bparams, cparams)
    renamed_new = {new for _, new in renames}
    renamed_old = {old for old, _ in renames}
    for old, new in renames:
        diff.emit("AC010", Severity.MEDIUM, "A parameter was renamed",
                  f"On `{where}` the parameter `{old}` looks renamed to `{new}` (same position and "
                  f"type). Every caller still sending `{old}` loses it silently.",
                  f"{where}::{old}", f"Accept both `{old}` and `{new}` for a release, or version the "
                  f"endpoint. If this is not a rename, treat the reading as a false positive.",
                  f"{old} -> {new}", changelog=f"`{old}` renamed to `{new}` on `{where}`")

    # New request inputs.
    #
    # A rename guess must never suppress this. Position-and-type coincidence is
    # weak evidence, so two unrelated edits — drop an optional param, add a
    # required one — read as a rename; and even a genuine rename of a required
    # parameter breaks every caller still sending the old name. Either way the
    # CRITICAL is the truthful report, and AC010 remains alongside it as the
    # explanation.
    for name, cparam in cparams.items():
        if name in bparams:
            continue
        if cparam.required and not cparam.has_default:
            diff.emit("AC002", Severity.CRITICAL, "A new required parameter has no default",
                      f"`{where}` now requires `{name}` with no default. Every existing caller omits "
                      f"it and breaks immediately with a rejected request."
                      + (f" It looks like a rename of `{dict((n, o) for o, n in renames).get(name)}`, "
                         f"which does not spare callers that still send the old name."
                         if name in renamed_new else ""),
                      f"{where}::{name}", f"Make `{name}` optional with a safe default, or ship it on a "
                      f"new version and keep the old one answering.",
                      changelog=f"`{where}` requires new parameter `{name}` (no default)")
        elif name not in renamed_new:
            diff.additive = True  # a new optional parameter is safe to add

    # Inputs present in both.
    for name in sorted(set(bparams) & set(cparams)):
        bp, cp = bparams[name], cparams[name]
        if not bp.required and cp.required:
            diff.emit("AC003", Severity.HIGH, "An optional parameter became required",
                      f"On `{where}`, `{name}` was optional and is now required. Callers that relied "
                      f"on the default now have to supply it.",
                      f"{where}::{name}", f"Keep `{name}` optional, or roll the requirement into a new "
                      f"version.", changelog=f"`{name}` is now required on `{where}`")
        for reason in _narrowings(bp.type, bp.enum, bp.nullable, cp.type, cp.enum, cp.nullable):
            diff.emit("AC005", Severity.HIGH, "A parameter type was narrowed",
                      f"On `{where}`, `{name}` narrowed: {reason}. Values a caller was allowed to send "
                      f"are now rejected.",
                      f"{where}::{name}", f"Keep accepting the wider type, or version the change.",
                      reason, changelog=f"`{name}` narrowed ({reason}) on `{where}`")
        _compare_enums(diff, where, f"parameter `{name}`", f"{where}::{name}", bp.enum, cp.enum, sends=True)

    # Response fields.
    bfields = {f.name: f for f in bop.fields}
    cfields = {f.name: f for f in cop.fields}
    for name in sorted(bfields):
        if name not in cfields:
            diff.emit("AC004", Severity.HIGH, "A response field was removed",
                      f"`{where}` no longer returns `{name}`. Any caller reading it now gets nothing "
                      f"where it used to get a value.",
                      f"{where}::{name}", f"Keep returning `{name}` (deprecate it first), or version the "
                      f"response.", changelog=f"response field `{name}` removed from `{where}`")
    for name in sorted(cfields):
        if name not in bfields:
            diff.additive = True  # a new response field is safe to add
    for name in sorted(set(bfields) & set(cfields)):
        bf, cf = bfields[name], cfields[name]
        for reason in _widenings(bf.type, bf.enum, bf.nullable, cf.type, cf.enum, cf.nullable):
            diff.emit("AC005", Severity.HIGH, "A response field changed in a caller-breaking way",
                      f"On `{where}`, response field `{name}` widened: {reason}. A caller written "
                      f"against the narrower response does not handle the new one.",
                      f"{where}::{name}", f"Keep the narrower guarantee, or version the response.",
                      reason, changelog=f"response field `{name}` widened ({reason}) on `{where}`")
        _compare_enums(diff, where, f"response field `{name}`", f"{where}::{name}",
                       bf.enum, cf.enum, sends=False)

    # Success statuses.
    for code in bop.statuses:
        if code not in cop.statuses:
            diff.emit("AC008", Severity.MEDIUM, "A success status code is gone",
                      f"`{where}` no longer answers with `{code}`. A caller that checks for exactly "
                      f"`{code}` treats the new response as a failure.",
                      f"{where}::{code}", f"Keep returning `{code}`, or document the new success code "
                      f"as a breaking change.", changelog=f"success status `{code}` removed from `{where}`")
    if set(cop.statuses) - set(bop.statuses):
        diff.additive = True

    # Deprecation.
    if not bop.deprecated and cop.deprecated:
        diff.emit("AC009", Severity.LOW, "Something was newly deprecated",
                  f"`{where}` is now marked deprecated. Nothing breaks yet — this is the warning that "
                  f"a removal is coming.",
                  where, f"Give callers a migration path and a date before you remove it.",
                  changelog=f"`{where}` deprecated")


def _compare_enums(diff: Diff, where: str, what: str, locator: str,
                   old: tuple, new: tuple, *, sends: bool) -> None:
    """Enum changes only count when both sides constrain — otherwise it is a type change."""
    if not old or not new:
        return
    removed = [v for v in old if v not in new]
    added = [v for v in new if v not in old]
    if removed:
        who = "send it" if sends else "receive and handle it"
        diff.emit("AC006", Severity.MEDIUM, "An enum value was removed",
                  f"On `{where}`, {what} dropped {', '.join(f'`{v}`' for v in removed)}. Callers that "
                  f"{who} break.",
                  locator, f"Keep the value accepted (reject it in logic if you must), or version the "
                  f"change.", ", ".join(removed),
                  changelog=f"enum value(s) {', '.join(removed)} removed from {what} on `{where}`")
    if added:
        note = ("callers that switch exhaustively on it" if not sends
                else "servers that reject unknown values — usually only new callers use it")
        diff.emit("AC007", Severity.LOW, "An enum value was added",
                  f"On `{where}`, {what} gained {', '.join(f'`{v}`' for v in added)}. This breaks only "
                  f"{note}; it is safe for everyone else.",
                  locator, f"Ship it as a minor change and tell exhaustive consumers to add a default "
                  f"branch.", ", ".join(added),
                  changelog=f"enum value(s) {', '.join(added)} added to {what} on `{where}`")


def _changelog_markdown(lines: dict[str, list[str]]) -> str:
    out = ["## Changelog", ""]
    for bucket, header in (("removed", "Removed"), ("changed", "Changed"),
                           ("added", "Added"), ("deprecated", "Deprecated")):
        out.append(f"### {header}")
        entries = sorted(lines[bucket])
        if entries:
            out.extend(f"- {line}" for line in entries)
        else:
            out.append("_none_")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def analyze(args: argparse.Namespace) -> Report:
    base_shape, baseline = load_surface(args.input)
    cand_shape, candidate = load_surface(args.against)
    if base_shape != cand_shape:
        raise EvidenceError(
            f"cannot diff a {base_shape} surface against a {cand_shape} one; describe both the "
            f"same way (both OpenAPI, or both symbol exports)"
        )
    if not baseline and not candidate:
        raise EvidenceError("both surfaces are empty; there is nothing to compare")

    report = Report(skill=SKILL, subject=f"{Path(args.input).name} -> {Path(args.against).name}")
    diff = Diff()

    # AC001: an operation that existed and is gone.
    for key in sorted(baseline):
        if key not in candidate:
            op = baseline[key]
            noun = "endpoint" if op.kind == "endpoint" else op.kind
            diff.emit("AC001", Severity.CRITICAL, "An endpoint or symbol was removed",
                      f"`{key}` was in the baseline and is gone. Every caller that uses it breaks the "
                      f"moment this ships.",
                      key, f"Restore `{key}`, or keep it answering on the old version while callers "
                      f"migrate.", changelog=f"`{key}` removed")
    for key in sorted(candidate):
        if key not in baseline:
            diff.additive = True  # a brand-new operation breaks no existing caller

    for key in sorted(set(baseline) & set(candidate)):
        compare_operation(diff, baseline[key], candidate[key])

    for code, severity, title, detail, locator, fix, evidence in diff.findings:
        report.add(Finding(code=code, severity=severity, title=title, detail=detail,
                           locator=locator, evidence=evidence, recommendation=fix))

    present = {f.code for f in report.findings}
    if present & MAJOR_CODES:
        semver = "major"
    elif (present & MINOR_CODES) or diff.additive:
        semver = "minor"
    else:
        semver = "patch"

    report.decide_verdict()

    report.sections = {
        "shape": base_shape,
        "semver": semver,
        "changelog": {
            "removed": sorted(diff.changelog_lines["removed"]),
            "changed": sorted(diff.changelog_lines["changed"]),
            "added": sorted(diff.changelog_lines["added"]),
            "deprecated": sorted(diff.changelog_lines["deprecated"]),
            "markdown": _changelog_markdown(diff.changelog_lines),
        },
        "operations": {
            "baseline": sorted(baseline),
            "candidate": sorted(candidate),
            "added": sorted(k for k in candidate if k not in baseline),
            "removed": sorted(k for k in baseline if k not in candidate),
        },
    }
    report.summary = {
        "shape": base_shape,
        "baseline_operations": len(baseline),
        "candidate_operations": len(candidate),
        "removed_operations": sum(1 for f in report.findings if f.code == "AC001"),
        "breaking": sum(1 for f in report.findings if f.code in MAJOR_CODES),
        "additive": diff.additive,
        "semver": semver,
    }
    report.note(
        "Only what breaks a caller is reported. Adding a required request field or removing a "
        "response field is breaking; adding a response field or removing a request field is not, and "
        "is left out on purpose."
    )
    report.note(
        "Parameter renames (AC010) are inferred from position and type, not identity. An insertion "
        "that shifts positions can hide a rename or invent one; every AC010 is a reading to confirm."
    )
    report.note(
        "$ref, allOf/oneOf/anyOf composition, and schemas nested deeper than two levels are not "
        "resolved. A break hidden inside a $ref or a deep union will not be seen."
    )
    report.note(
        "The semver recommendation is derived strictly from the worst finding present, and the "
        "verdict blocks only when something CRITICAL (a removal or a new required field) is found."
    )
    return report


def _extend(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--against", required=True,
        help="the candidate surface to compare against the baseline (--input). Same shape as the "
             "baseline: both OpenAPI, or both symbol exports.",
    )


def main(argv: list[str] | None = None) -> int:
    return run(
        argv, skill=SKILL, title=TITLE,
        description="Diff two API surfaces, report what breaks for callers, and draft the changelog.",
        analyze=analyze, extend=_extend,
    )


if __name__ == "__main__":
    raise SystemExit(main())
