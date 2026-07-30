"""Tests for api-contract-guard.

The whole skill lives or dies on direction: adding a required *request* field
breaks callers and must fire; adding a *response* field is safe and must stay
silent — and the reverse for removals. So the awkward cases here are deliberately
run in *both* directions, once to prove the finding fires and once to prove its
mirror image does not. The rest cover the two input shapes (OpenAPI and a symbol
export), the rename heuristic and the AC002 it suppresses, the changelog and
semver derivation, and byte-for-byte reproducibility.
"""

from __future__ import annotations

import json

import pytest

from api_contract_guard import analyze, load_surface
from scoutkit.io import EvidenceError


class Args:
    def __init__(self, **kw):
        self.input = kw.pop("input")
        self.against = kw.pop("against")
        for k, v in kw.items():
            setattr(self, k, v)


def codes(report):
    return {f.code for f in report.findings}


def by_code(report, code):
    return next(f for f in report.findings if f.code == code)


def doc(paths: dict) -> str:
    return json.dumps({"openapi": "3.0.3", "info": {"title": "t", "version": "0"}, "paths": paths})


def syms(symbols: list) -> str:
    return json.dumps({"symbols": symbols})


def run(write, baseline: str, candidate: str):
    base = write("base.json", baseline)
    cand = write("cand.json", candidate)
    return analyze(Args(input=str(base), against=str(cand)))


def resp(status="200", props=None, required=None):
    schema = {"type": "object"}
    if props is not None:
        schema["properties"] = props
    if required is not None:
        schema["required"] = required
    return {status: {"description": "ok", "content": {"application/json": {"schema": schema}}}}


def query_param(name, *, required=False, type="string", enum=None, default=None):
    schema = {"type": type}
    if enum is not None:
        schema["enum"] = enum
    if default is not None:
        schema["default"] = default
    return {"name": name, "in": "query", "required": required, "schema": schema}


def body(props, required=None):
    schema = {"type": "object", "properties": props}
    if required is not None:
        schema["required"] = required
    return {"requestBody": {"content": {"application/json": {"schema": schema}}}}


# --- AC001: an operation disappears ----------------------------------------

def test_a_removed_endpoint_is_critical(write):
    base = doc({"/a": {"get": {"responses": resp()}}, "/b": {"get": {"responses": resp()}}})
    cand = doc({"/a": {"get": {"responses": resp()}}})
    report = run(write, base, cand)
    assert "AC001" in codes(report)
    assert by_code(report, "AC001").severity == "critical"
    assert report.verdict == "block"


def test_a_removed_symbol_is_critical(write):
    base = syms([{"name": "create_user", "kind": "function"},
                 {"name": "delete_user", "kind": "function"}])
    cand = syms([{"name": "create_user", "kind": "function"}])
    report = run(write, base, cand)
    assert "AC001" in codes(report)
    assert by_code(report, "AC001").locator == "delete_user"


# --- AC002: a new required request field (the request-side asymmetry) -------

def test_a_new_required_parameter_breaks_callers(write):
    base = doc({"/a": {"get": {"responses": resp()}}})
    cand = doc({"/a": {"get": {"parameters": [query_param("tenant", required=True)],
                               "responses": resp()}}})
    report = run(write, base, cand)
    assert "AC002" in codes(report)
    assert by_code(report, "AC002").severity == "critical"


def test_a_new_required_parameter_with_a_default_is_not_breaking(write):
    base = doc({"/a": {"get": {"responses": resp()}}})
    cand = doc({"/a": {"get": {"parameters": [query_param("tenant", required=True, default="x")],
                               "responses": resp()}}})
    report = run(write, base, cand)
    assert "AC002" not in codes(report)


def test_a_new_optional_parameter_is_not_breaking(write):
    base = doc({"/a": {"get": {"responses": resp()}}})
    cand = doc({"/a": {"get": {"parameters": [query_param("tenant", required=False)],
                               "responses": resp()}}})
    report = run(write, base, cand)
    assert "AC002" not in codes(report)


def test_removing_a_request_parameter_is_not_flagged(write):
    """The mirror of AC002: dropping a request input does not break existing callers."""
    base = doc({"/a": {"get": {"parameters": [query_param("old")], "responses": resp()}}})
    cand = doc({"/a": {"get": {"responses": resp()}}})
    report = run(write, base, cand)
    assert codes(report) == set()


# --- AC003: optional -> required -------------------------------------------

def test_an_optional_parameter_becoming_required_is_high(write):
    base = doc({"/a": {"get": {"parameters": [query_param("q", required=False)], "responses": resp()}}})
    cand = doc({"/a": {"get": {"parameters": [query_param("q", required=True)], "responses": resp()}}})
    report = run(write, base, cand)
    assert "AC003" in codes(report)
    assert by_code(report, "AC003").severity == "high"


# --- AC004: a response field disappears (the response-side asymmetry) -------

def test_a_removed_response_field_is_high(write):
    base = doc({"/a": {"get": {"responses": resp(props={"id": {"type": "string"},
                                                        "total": {"type": "integer"}})}}})
    cand = doc({"/a": {"get": {"responses": resp(props={"id": {"type": "string"}})}}})
    report = run(write, base, cand)
    assert "AC004" in codes(report)
    assert by_code(report, "AC004").severity == "high"


def test_adding_a_response_field_is_not_flagged(write):
    """The mirror of AC004: a new response field breaks no existing caller."""
    base = doc({"/a": {"get": {"responses": resp(props={"id": {"type": "string"}})}}})
    cand = doc({"/a": {"get": {"responses": resp(props={"id": {"type": "string"},
                                                        "extra": {"type": "string"}})}}})
    report = run(write, base, cand)
    assert "AC004" not in codes(report)
    assert codes(report) == set()


# --- AC005: type narrowing (and its widening mirror) -----------------------

def test_a_narrowed_parameter_type_is_high(write):
    base = doc({"/a": {"get": {"parameters": [query_param("n", type="number")], "responses": resp()}}})
    cand = doc({"/a": {"get": {"parameters": [query_param("n", type="integer")], "responses": resp()}}})
    report = run(write, base, cand)
    assert "AC005" in codes(report)
    assert by_code(report, "AC005").severity == "high"


def test_nullable_to_non_nullable_in_a_response_is_safe(write):
    """A response field that is now always present breaks nobody.

    This asserted the opposite until the response comparison stopped reusing the
    request-direction rule.
    """
    base = doc({"/a": {"get": {"responses": resp(props={"cursor": {"type": "string", "nullable": True}})}}})
    cand = doc({"/a": {"get": {"responses": resp(props={"cursor": {"type": "string", "nullable": False}})}}})
    report = run(write, base, cand)
    assert "AC005" not in codes(report)


def test_non_nullable_to_nullable_in_a_response_is_breaking(write):
    """A field that could never be null now can be — every caller dereferencing it fails."""
    base = doc({"/a": {"get": {"responses": resp(props={"cursor": {"type": "string", "nullable": False}})}}})
    cand = doc({"/a": {"get": {"responses": resp(props={"cursor": {"type": "string", "nullable": True}})}}})
    report = run(write, base, cand)
    assert "AC005" in codes(report)


def test_openapi_31_type_list_null_is_treated_as_nullable(write):
    """`type: [string, null]` is the 3.1 spelling of nullable, in the breaking direction."""
    base = doc({"/a": {"get": {"responses": resp(props={"cursor": {"type": "string"}})}}})
    cand = doc({"/a": {"get": {"responses": resp(props={"cursor": {"type": ["string", "null"]}})}}})
    report = run(write, base, cand)
    assert "AC005" in codes(report)


def test_widening_a_type_is_not_flagged(write):
    """integer -> string accepts more, so it breaks no one."""
    base = doc({"/a": {"get": {"parameters": [query_param("n", type="integer")], "responses": resp()}}})
    cand = doc({"/a": {"get": {"parameters": [query_param("n", type="string")], "responses": resp()}}})
    report = run(write, base, cand)
    assert "AC005" not in codes(report)


# --- AC006 / AC007: enum values, both directions ---------------------------

def test_a_removed_enum_value_is_medium(write):
    base = doc({"/a": {"get": {"parameters": [query_param("s", enum=["a", "b", "c"])], "responses": resp()}}})
    cand = doc({"/a": {"get": {"parameters": [query_param("s", enum=["a", "b"])], "responses": resp()}}})
    report = run(write, base, cand)
    assert "AC006" in codes(report)
    assert by_code(report, "AC006").severity == "medium"
    assert "AC007" not in codes(report)


def test_an_added_response_enum_value_is_low_and_precise(write):
    base = doc({"/a": {"get": {"responses": resp(props={"state": {"type": "string", "enum": ["on", "off"]}})}}})
    cand = doc({"/a": {"get": {"responses": resp(props={"state": {"type": "string", "enum": ["on", "off", "idle"]}})}}})
    report = run(write, base, cand)
    assert "AC007" in codes(report)
    assert by_code(report, "AC007").severity == "low"
    assert "exhaustive" in by_code(report, "AC007").detail


def test_introducing_an_enum_is_narrowing_not_an_added_value(write):
    """An open string constrained to a fixed set is AC005, never a stream of AC007s."""
    base = doc({"/a": {"get": {"parameters": [query_param("s", type="string")], "responses": resp()}}})
    cand = doc({"/a": {"get": {"parameters": [query_param("s", type="string", enum=["a", "b"])],
                               "responses": resp()}}})
    report = run(write, base, cand)
    assert "AC005" in codes(report)
    assert "AC007" not in codes(report)


# --- AC008: success status -------------------------------------------------

def test_a_removed_success_status_is_medium(write):
    base = doc({"/a": {"get": {"responses": resp("200")}}})
    cand = doc({"/a": {"get": {"responses": resp("201")}}})
    report = run(write, base, cand)
    assert "AC008" in codes(report)
    assert by_code(report, "AC008").locator.endswith("200")


# --- AC009: deprecation ----------------------------------------------------

def test_newly_deprecated_is_low(write):
    base = doc({"/a": {"get": {"responses": resp()}}})
    cand = doc({"/a": {"get": {"deprecated": True, "responses": resp()}}})
    report = run(write, base, cand)
    assert "AC009" in codes(report)
    assert by_code(report, "AC009").severity == "low"


def test_already_deprecated_is_not_re_reported(write):
    base = doc({"/a": {"get": {"deprecated": True, "responses": resp()}}})
    cand = doc({"/a": {"get": {"deprecated": True, "responses": resp()}}})
    report = run(write, base, cand)
    assert "AC009" not in codes(report)


# --- AC010: rename heuristic and the AC002 it suppresses -------------------

def test_a_renamed_required_parameter_reports_both_the_rename_and_the_break(write):
    """Renaming a required field is still a break for every caller sending the old name.

    This previously asserted that AC010 *suppressed* AC002 — which meant a
    CRITICAL was downgraded to a MEDIUM and the verdict dropped from block to
    review. The rename is worth saying; it is not a reason to stay quiet.
    """
    base = doc({"/a": {"post": body({"name": {"type": "string"}, "color": {"type": "string"}},
                                    required=["name"])}})
    cand = doc({"/a": {"post": body({"title": {"type": "string"}, "color": {"type": "string"}},
                                    required=["title"])}})
    report = run(write, base, cand)
    assert "AC010" in codes(report)
    assert "AC002" in codes(report)
    assert report.verdict == "block"
    assert "rename" in by_code(report, "AC002").detail.lower()


def test_a_renamed_optional_parameter_is_only_a_rename(write):
    """Nothing was required, so nothing breaks — the rename stands alone."""
    base = doc({"/a": {"post": body({"name": {"type": "string"}, "color": {"type": "string"}})}})
    cand = doc({"/a": {"post": body({"title": {"type": "string"}, "color": {"type": "string"}})}})
    report = run(write, base, cand)
    assert "AC010" in codes(report)
    assert "AC002" not in codes(report)


def test_a_different_type_at_the_same_position_is_not_a_rename(write):
    base = doc({"/a": {"post": body({"name": {"type": "string"}}, required=["name"])}})
    cand = doc({"/a": {"post": body({"count": {"type": "integer"}}, required=["count"])}})
    report = run(write, base, cand)
    assert "AC010" not in codes(report)
    assert "AC002" in codes(report)  # a genuinely new required field


# --- symbol-export shape ----------------------------------------------------

def test_symbol_export_new_required_param_is_critical(write):
    base = syms([{"name": "f", "kind": "function", "params": [{"name": "a", "required": True, "type": "string"}]}])
    cand = syms([{"name": "f", "kind": "function", "params": [
        {"name": "a", "required": True, "type": "string"},
        {"name": "b", "required": True, "type": "string"}]}])
    report = run(write, base, cand)
    assert "AC002" in codes(report)


def test_symbol_export_removed_field_is_high(write):
    base = syms([{"name": "f", "kind": "function",
                  "fields": [{"name": "id", "type": "string"}, {"name": "email", "type": "string"}]}])
    cand = syms([{"name": "f", "kind": "function", "fields": [{"name": "id", "type": "string"}]}])
    report = run(write, base, cand)
    assert "AC004" in codes(report)


# --- shape detection and evidence errors -----------------------------------

def test_openapi_shape_is_detected(write):
    shape, surface = load_surface(str(write("s.json", doc({"/a": {"get": {"responses": resp()}}}))))
    assert shape == "openapi"
    assert "GET /a" in surface


def test_symbol_shape_is_detected(write):
    shape, surface = load_surface(str(write("s.json", syms([{"name": "f", "kind": "function"}]))))
    assert shape == "symbols"
    assert "f" in surface


def test_crossing_two_shapes_is_refused(write):
    base = doc({"/a": {"get": {"responses": resp()}}})
    cand = syms([{"name": "f", "kind": "function"}])
    with pytest.raises(EvidenceError):
        run(write, base, cand)


def test_an_unrecognized_surface_is_an_evidence_error(write):
    with pytest.raises(EvidenceError):
        run(write, json.dumps({"not": "a surface"}), json.dumps({"not": "a surface"}))


def test_two_empty_surfaces_is_an_evidence_error(write):
    with pytest.raises(EvidenceError):
        run(write, doc({}), doc({}))


def test_a_missing_file_is_an_evidence_error(write):
    base = write("base.json", doc({"/a": {"get": {"responses": resp()}}}))
    with pytest.raises(EvidenceError):
        analyze(Args(input=str(base), against=str(base.parent / "nope.json")))


# --- changelog and semver ---------------------------------------------------

def test_changelog_sorts_findings_into_keep_a_changelog_buckets(write):
    base = doc({"/gone": {"get": {"responses": resp()}},
                "/a": {"get": {"deprecated": False, "responses": resp()}}})
    cand = doc({"/a": {"get": {"deprecated": True,
                               "parameters": [query_param("t", required=True)], "responses": resp()}}})
    report = run(write, base, cand)
    changelog = report.sections["changelog"]
    assert any("/gone" in line for line in changelog["removed"])
    assert any("`t`" in line for line in changelog["changed"])
    assert any("deprecated" in line for line in changelog["deprecated"])
    assert "### Deprecated" in changelog["markdown"]


def test_semver_is_major_on_a_breaking_change(write):
    base = doc({"/a": {"get": {"responses": resp()}}})
    # /a removed and /b added: the removal is breaking, so the whole change is major
    report = run(write, base, doc({"/b": {"get": {"responses": resp()}}}))
    assert "AC001" in codes(report)
    assert report.sections["semver"] == "major"


def test_semver_is_minor_on_additive_only(write):
    base = doc({"/a": {"get": {"responses": resp()}}})
    cand = doc({"/a": {"get": {"responses": resp()}},
                "/b": {"get": {"responses": resp()}}})  # a new endpoint, nothing broken
    report = run(write, base, cand)
    assert report.sections["semver"] == "minor"
    assert report.verdict == "pass"


def test_semver_is_patch_when_nothing_changed(write):
    base = doc({"/a": {"get": {"parameters": [query_param("q")], "responses": resp(props={"id": {"type": "string"}})}}})
    report = run(write, base, base)
    assert report.findings == []
    assert report.sections["semver"] == "patch"
    assert report.verdict == "pass"


# --- reproducibility and the bundled template ------------------------------

def test_report_is_reproducible(write):
    base = doc({"/a": {"get": {"parameters": [query_param("q", enum=["a", "b"])],
                               "responses": resp(props={"id": {"type": "string"}})}}})
    cand = doc({"/a": {"get": {"parameters": [query_param("q", enum=["a"], required=True)],
                               "responses": resp()}}})
    first = run(write, base, cand).to_dict()
    second = run(write, base, cand).to_dict()
    assert first == second


def test_the_bundled_template_runs(template):
    baseline = template("api-contract-guard", "surface.example.json")
    candidate = template("api-contract-guard", "surface.candidate.json")
    report = analyze(Args(input=str(baseline), against=str(candidate)))
    present = codes(report)
    for expected in ("AC001", "AC002", "AC003", "AC004", "AC005",
                     "AC006", "AC007", "AC008", "AC009", "AC010"):
        assert expected in present, f"template did not exercise {expected}"
    assert report.verdict == "block"
    assert report.sections["semver"] == "major"


# --------------------------------------------------------------------------- #
# Adversarial regressions.
#
# The response-field comparison reused the *request* narrowing rule, which
# inverts both halves of the direction this skill exists to get right: a safe
# change was reported as major, and a genuinely breaking one shipped as a clean
# patch with no finding at all.
# --------------------------------------------------------------------------- #

def _returns(nullable: bool) -> str:
    return syms([{
        "name": "get_user", "kind": "function", "params": [], "returns": "User",
        "fields": [{"name": "email", "type": "string", "nullable": nullable}],
    }])


def test_a_response_field_becoming_always_present_is_safe(write):
    """nullable -> non-nullable means the caller always gets a value now."""
    report = run(write, _returns(True), _returns(False))
    assert "AC005" not in codes(report)
    assert report.verdict == "pass"
    assert report.summary.get("semver") == "patch"


def test_a_response_field_becoming_nullable_is_breaking(write):
    """non-nullable -> nullable crashes every caller that dereferences it."""
    report = run(write, _returns(False), _returns(True))
    assert "AC005" in codes(report)
    assert report.summary.get("semver") == "major"


def _enumerated(values: list | None) -> str:
    field = {"name": "status", "type": "string"}
    if values is not None:
        field["enum"] = values
    return syms([{"name": "get_order", "kind": "function", "params": [],
                  "returns": "Order", "fields": [field]}])


def test_opening_a_response_enum_is_breaking(write):
    """A caller switching exhaustively now receives values it does not handle."""
    report = run(write, _enumerated(["open", "closed"]), _enumerated(None))
    assert "AC005" in codes(report)


def test_constraining_a_response_enum_is_not_reported_as_narrowing(write):
    """Returning fewer distinct values does not break a caller's parser."""
    report = run(write, _enumerated(None), _enumerated(["open", "closed"]))
    assert "AC005" not in codes(report)


def test_a_rename_guess_cannot_hide_a_new_required_parameter(write):
    """Drop an optional param, add a required one at the same position and type.

    Position-and-type coincidence is weak evidence. Accepting it as proof of a
    rename let the AC010 MEDIUM suppress the AC002 CRITICAL that every existing
    caller is about to hit, and dropped the verdict from block to review.
    """
    baseline = doc({"/users": {"post": {"requestBody": {"content": {"application/json": {
        "schema": {"type": "object", "properties": {"nickname": {"type": "string"}}}}}}}}})
    candidate = doc({"/users": {"post": {"requestBody": {"content": {"application/json": {
        "schema": {"type": "object", "properties": {"ssn": {"type": "string"}},
                   "required": ["ssn"]}}}}}}})
    report = run(write, baseline, candidate)
    assert "AC002" in codes(report)
    assert report.verdict == "block"
