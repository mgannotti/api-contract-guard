"""Tests for the shared library.

These cover the primitives every engine depends on. A defect here is a defect
in eight skills at once, so the cases are the awkward ones rather than the
happy path: renames, binary files, prereleases, 0.x majors, and tracebacks in
four languages.
"""

from __future__ import annotations

import pytest

from scoutkit import (
    EvidenceError,
    RangeKind,
    Severity,
    bump_kind,
    changed_symbols,
    classify_path,
    deepest_application_frame,
    detect_language,
    fingerprint,
    iter_repo_files,
    looks_like_placeholder,
    mask,
    normalize_line,
    parse_git_log,
    parse_unified_diff,
    parse_version,
    range_kind,
    shannon_entropy,
    split_records,
    stack_frames,
)
from scoutkit.findings import Finding, Report


# --- classification --------------------------------------------------------

@pytest.mark.parametrize("path,expected", [
    ("src/app/handler.py", "source"),
    ("tests/test_handler.py", "test"),
    ("src/__tests__/handler.spec.ts", "test"),
    ("spec/models/user_spec.rb", "test"),
    ("docs/architecture.md", "docs"),
    ("README.md", "docs"),
    (".github/workflows/ci.yml", "ci"),
    ("package.json", "config"),
    ("assets/logo.png", "asset"),
    ("src/styles/main.css", "source"),
])
def test_classify_path(path, expected):
    assert classify_path(path) == expected


def test_test_dir_beats_config_name():
    """A package.json inside tests/ is scaffolding, not project configuration."""
    assert classify_path("tests/fixtures/package.json") == "test"


def test_classify_path_handles_windows_separators():
    assert classify_path(r"src\app\handler.py") == "source"


def test_detect_language_by_name_not_only_suffix():
    assert detect_language("Dockerfile") == "Dockerfile"
    assert detect_language("src/main.rs") == "Rust"
    assert detect_language("mystery.qqq") == "Other"


# --- repo walking ----------------------------------------------------------

def test_iter_repo_files_skips_dependency_trees(repo):
    root = repo({
        "src/app.py": "x = 1\n",
        "node_modules/left-pad/index.js": "module.exports = 1\n",
        "__pycache__/app.cpython-312.pyc": "junk",
        ".git/config": "[core]\n",
        "tests/test_app.py": "def test(): pass\n",
    })
    found = sorted(p.name for p in iter_repo_files(root))
    assert found == ["app.py", "test_app.py"]


def test_iter_repo_files_is_deterministic(repo):
    root = repo({f"src/mod_{i}.py": "pass\n" for i in range(12)})
    assert [p.name for p in iter_repo_files(root)] == [p.name for p in iter_repo_files(root)]


def test_iter_repo_files_rejects_missing_directory(tmp_path):
    with pytest.raises(EvidenceError):
        list(iter_repo_files(tmp_path / "nope"))


def test_iter_repo_files_terminates_on_a_directory_loop(tmp_path):
    """A link pointing at an ancestor makes the tree infinite.

    Before cycle detection this walked until the path outgrew the platform
    limit and the resulting OSError was swallowed — 22 phantom copies of one
    file on Windows, considerably more on Linux.
    """
    import os
    import subprocess

    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
    link = repo / "src" / "loop"

    try:
        link.symlink_to(repo, target_is_directory=True)
    except (OSError, NotImplementedError):
        if os.name != "nt":
            pytest.skip("cannot create a directory link on this platform")
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(repo)],
                              capture_output=True, text=True)
        if made.returncode != 0:
            pytest.skip("cannot create a junction on this platform")

    found = [p.name for p in iter_repo_files(repo)]
    assert found == ["a.py"], f"the loop was walked more than once: {found}"


# --- git history -----------------------------------------------------------

LOG = (
    "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678\tDana Reed\tdana@example.test\t2026-03-04\tAdd retry to the uploader\n"
    "12\t3\tsrc/upload.py\n"
    "4\t0\ttests/test_upload.py\n"
    "\n"
    "b2c3d4e5f60718293a4b5c6d7e8f901234567890\tAlex Chen\talex@example.test\t2026-03-05\tMove the parser\n"
    "8\t8\tsrc/{old => new}/parse.py\n"
    "-\t-\tassets/logo.png\n"
)


def test_parse_git_log_reads_commits_and_numstat():
    commits = parse_git_log(LOG)
    assert len(commits) == 2
    first = commits[0]
    assert first.author == "Dana Reed"
    assert first.subject == "Add retry to the uploader"
    assert first.when is not None and first.when.isoformat() == "2026-03-04"
    assert first.churn == 19


def test_parse_git_log_resolves_brace_renames():
    """git prints a rename as old/{a => b}/name; churn belongs to the path that exists now."""
    commits = parse_git_log(LOG)
    paths = [f.path for f in commits[1].files]
    assert "src/new/parse.py" in paths


def test_parse_git_log_marks_binary_without_counting_lines():
    binary = [f for f in parse_git_log(LOG)[1].files if f.path.endswith(".png")][0]
    assert binary.binary is True
    assert binary.churn == 0


def test_parse_git_log_accepts_plain_format():
    text = (
        "commit abc1234def5678\n"
        "Author: Sam Patel <sam@example.test>\n"
        "Date:   2026-01-09\n"
        "\n"
        "    Fix the null check\n"
        "\n"
        "3\t1\tsrc/check.py\n"
    )
    commit = parse_git_log(text)[0]
    assert commit.author == "Sam Patel"
    assert commit.subject == "Fix the null check"
    assert commit.files[0].added == 3


def test_parse_git_log_rejects_junk():
    with pytest.raises(EvidenceError):
        parse_git_log("this is not a git log at all\n")


# --- diffs -----------------------------------------------------------------

DIFF = """diff --git a/src/auth.py b/src/auth.py
index 1111111..2222222 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,7 +10,9 @@ class Session:
     def refresh(self):
-        return self.token
+        if self.expired():
+            raise SessionExpired()
+        return self.token
diff --git a/docs/auth.md b/docs/auth.md
new file mode 100644
--- /dev/null
+++ b/docs/auth.md
@@ -0,0 +1,2 @@
+# Auth
+Sessions expire.
"""


def test_parse_unified_diff_splits_files_and_counts_lines():
    files = parse_unified_diff(DIFF)
    assert [f.path for f in files] == ["src/auth.py", "docs/auth.md"]
    assert files[0].added == 3
    assert files[0].removed == 1
    assert files[1].status == "added"


def test_changed_symbols_reads_changed_lines_not_the_hunk_heading():
    """The heading names the enclosing symbol, which the change may not have touched."""
    files = parse_unified_diff(DIFF)
    assert "Session" not in changed_symbols(files[0])


def test_changed_symbols_finds_definitions():
    diff = """--- a/x.py
+++ b/x.py
@@ -1,3 +1,5 @@
+def parse_header(raw):
+    return raw
-def old_helper(x):
"""
    names = changed_symbols(parse_unified_diff(diff)[0])
    assert "parse_header" in names and "old_helper" in names


def test_parse_unified_diff_rejects_empty():
    with pytest.raises(EvidenceError):
        parse_unified_diff("   \n")


# --- logs ------------------------------------------------------------------

def test_normalize_line_collapses_the_variable_parts():
    a = normalize_line("2026-03-04T10:11:12Z ERROR request 8f2c1a90-1111-2222-3333-444455556666 failed after 1200ms")
    b = normalize_line("2026-03-05T22:01:02Z ERROR request 0a0a0a0a-9999-8888-7777-666655554444 failed after 87ms")
    assert a == b


def test_normalize_line_keeps_different_errors_apart():
    a = normalize_line("ERROR connection refused to db-1")
    b = normalize_line("ERROR permission denied on /etc/shadow")
    assert a != b


@pytest.mark.parametrize("trace,expected_fragment", [
    ('  File "app/handler.py", line 42, in dispatch', "app/handler.py"),
    ("        at com.acme.Service.handle(Service.java:42)", "Service.java"),
    ("    at handle (/srv/app/handler.js:42:9)", "/srv/app/handler.js"),
    ("   at Acme.Service.Handle() in C:\\src\\Service.cs:line 42", "Service.cs"),
])
def test_stack_frames_reads_every_common_format(trace, expected_fragment):
    frames = stack_frames(trace)
    assert frames and expected_fragment in frames[0].location


def test_deepest_application_frame_skips_dependencies():
    trace = (
        '  File "app/views.py", line 10, in get\n'
        '  File "/usr/lib/python3.12/site-packages/django/db/models.py", line 900, in fetch\n'
    )
    frame = deepest_application_frame(stack_frames(trace))
    assert frame is not None and frame.location == "app/views.py"


def test_split_records_keeps_a_traceback_with_its_message():
    text = (
        "2026-03-04 10:00:00 ERROR upload failed\n"
        "Traceback (most recent call last):\n"
        '  File "app/upload.py", line 12, in send\n'
        "ConnectionError: refused\n"
        "2026-03-04 10:00:05 INFO retrying\n"
    )
    records = split_records(text)
    assert len(records) == 2
    assert len(records[0]) == 4


# --- versions --------------------------------------------------------------

@pytest.mark.parametrize("text,major,minor,patch", [
    ("1.2.3", 1, 2, 3),
    ("v2.0.0", 2, 0, 0),
    ("10.4", 10, 4, 0),
    ("1.2.3.4", 1, 2, 3),
    ("2.0.0-rc1", 2, 0, 0),
])
def test_parse_version(text, major, minor, patch):
    v = parse_version(text)
    assert v is not None
    assert (v.major, v.minor, v.patch) == (major, minor, patch)


def test_prerelease_sorts_below_its_release():
    assert parse_version("2.0.0-rc1") < parse_version("2.0.0")


def test_parse_version_rejects_non_versions():
    assert parse_version("latest") is None
    assert parse_version("^1.2.3") is None


@pytest.mark.parametrize("current,target,expected", [
    ("1.2.3", "2.0.0", "major"),
    ("1.2.3", "1.3.0", "minor"),
    ("1.2.3", "1.2.4", "patch"),
    ("1.2.3", "1.2.3", "none"),
    ("2.0.0", "1.9.9", "downgrade"),
])
def test_bump_kind(current, target, expected):
    assert bump_kind(parse_version(current), parse_version(target)) == expected


def test_zero_major_minor_bump_is_breaking():
    """0.x has no stability promise; a minor move there removes APIs."""
    assert bump_kind(parse_version("0.4.1"), parse_version("0.5.0")) == "major"


@pytest.mark.parametrize("spec,expected", [
    ("1.2.3", RangeKind.EXACT),
    ("==1.2.3", RangeKind.EXACT),
    ("^1.2.3", RangeKind.MINOR),
    ("~1.2.3", RangeKind.PATCH),
    ("~=1.2", RangeKind.MINOR),
    (">=1.0.0", RangeKind.ANY),
    ("*", RangeKind.ANY),
    ("", RangeKind.ANY),
    (">=1.0,<2.0", RangeKind.MINOR),
    ("git+https://example.test/x.git", RangeKind.GIT),
    ("file:../local", RangeKind.LOCAL),
])
def test_range_kind(spec, expected):
    assert range_kind(spec) == expected


# --- redaction -------------------------------------------------------------

# AWS-shaped literals are assembled at runtime rather than written out, so this
# file contains no contiguous provider-key literal for GitHub's own secret
# scanning — or this pack's secret-sweeper — to flag in a public repository.
_AWS_PREFIX = "AK" + "IA"
FAKE_AWS_KEY = _AWS_PREFIX + "1234567890" + "ABCDEF"
DOCUMENTED_AWS_EXAMPLE = _AWS_PREFIX + "IOSFODNN7" + "EXAMPLE"


def test_mask_never_returns_the_secret():
    secret = FAKE_AWS_KEY
    masked = mask(secret)
    assert secret not in masked
    assert "len=20" in masked


def test_mask_of_a_short_value_keeps_no_prefix():
    assert mask("abcdef").startswith("len<")


def test_mask_of_a_short_password_gives_nothing_away():
    """Three characters of a nine-character password is a third of it."""
    assert mask("hunter2!x").startswith("len<")


# --- adversarial regressions ------------------------------------------------
#
# Both found by running every engine against hostile input rather than by
# reading the code.

def test_read_json_on_binary_is_an_evidence_error(tmp_path):
    """A non-UTF-8 file crashed with a raw UnicodeDecodeError instead of exit 3."""
    from scoutkit import read_json
    path = tmp_path / "binary.json"
    path.write_bytes(b"\xff\xfe\x00 not text at all")
    with pytest.raises(EvidenceError):
        read_json(path)


def test_read_jsonl_on_binary_is_an_evidence_error(tmp_path):
    from scoutkit import read_jsonl
    path = tmp_path / "binary.jsonl"
    path.write_bytes(b"\xff\xfe\x00 not text at all")
    with pytest.raises(EvidenceError):
        read_jsonl(path)


def test_read_json_tolerates_a_byte_order_mark(tmp_path):
    from scoutkit import read_json
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + b'{"ok": true}')
    assert read_json(path) == {"ok": True}


@pytest.mark.parametrize("supplied,expected", [
    ("../../escaped", "escaped"),
    ("..\\..\\escaped", "escaped"),
    ("/etc/passwd", "passwd"),
    ("C:/Windows/system32/evil", "evil"),
    ("sub/dir/report", "report"),
    ("", "fallback"),
    ("   ", "fallback"),
    ("..", "fallback"),
    ("normal-name", "normal-name"),
])
def test_basename_cannot_escape_the_output_directory(supplied, expected):
    """--outdir is the declared write boundary; --basename must not cross it."""
    from scoutkit.cli import safe_basename
    assert safe_basename(supplied, fallback="fallback") == expected


def test_mask_of_a_long_token_keeps_a_matching_prefix():
    """Twenty characters or more, and the prefix is what matches a vault entry."""
    assert mask(FAKE_AWS_KEY).startswith("AKI\u2026")


def test_mask_is_stable():
    assert mask("hunter2hunter2hunter2") == mask("hunter2hunter2hunter2")


@pytest.mark.parametrize("value", [
    "xxxxxxxx", "your-api-key-here", "${API_KEY}", "<token>", "changeme",
    "CHANGE_ME", "REDACTED", "aaaaaaaaaaaa", "%APPDATA%", "{{secret}}",
])
def test_placeholders_are_recognized(value):
    assert looks_like_placeholder(value) is True


def test_a_real_looking_key_is_not_a_placeholder():
    assert looks_like_placeholder("kJ8mQ2vB7nXpL9wR3sT6yU1iO0zA5cV4") is False


def test_documented_example_credentials_are_placeholders():
    """A vendor's published example key is not a live credential."""
    assert looks_like_placeholder(DOCUMENTED_AWS_EXAMPLE) is True


def test_a_weak_word_buried_in_a_real_secret_does_not_dismiss_it():
    """'test' inside random characters is a coincidence, not a signal.

    Matching it anywhere would silently dismiss any secret containing those
    four letters, which is the worst failure mode a scanner can have.
    """
    assert looks_like_placeholder("kJ8mQ2vB7nXtestZ4pL9wR3sT6yU1iO0") is False


def test_entropy_separates_random_from_prose():
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0
    assert shannon_entropy("kJ8#mQ2!vB7@nX4z") > 3.5


# --- findings --------------------------------------------------------------

def test_verdict_escalates_with_the_worst_finding():
    report = Report(skill="t")
    assert report.decide_verdict() == "pass"
    report.add(Finding(code="X1", severity=Severity.LOW, title="t", detail="d"))
    assert report.decide_verdict() == "pass"
    report.add(Finding(code="X2", severity=Severity.MEDIUM, title="t", detail="d"))
    assert report.decide_verdict() == "review"
    report.add(Finding(code="X3", severity=Severity.CRITICAL, title="t", detail="d"))
    assert report.decide_verdict() == "block"


def test_finding_requires_a_known_severity():
    with pytest.raises(ValueError):
        Finding(code="X", severity="catastrophic", title="t", detail="d")

# --- shared redaction: the leak that came from having two implementations ---
#
# error-triage carried its own smaller copy of the credential patterns. It fell
# behind secret-sweeper's, and every shape it had stopped recognizing was both
# reported as no finding AND reproduced verbatim in the JSON artifact.

def _secret(kind: str) -> str:
    """Realistic shapes, assembled at runtime so no literal ships in this file."""
    return {
        "aws_id": "AK" + "IA" + "IOSFODNN7" + "EXAMPLB",
        "env_password": "DB_PASSWORD=S3cr3tP4ssw0rdABCDEF",
        "env_token": "API_TOKEN=tok_9f8e7d6c5b4a3210ZZ",
        "env_secret": "APP_SECRET=whisper-Quiet-River-42-XY",
        "aws_env": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLB",
        "google": "AIza" + "SyD" + "1a2b3c4d5e6f7g8h9i0jklmnopqrstuv",
        "azure": "AccountKey=Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0aQ==",
        "url_password": "postgres://svc:hunter2hunter2XY@db.internal:5432/app",
        "slack": "xox" + "b-" + "1234567890-abcdefghijkl",
        "github": "gh" + "p_" + "0123456789abcdefghijABCDEFGHIJ",
    }[kind]


SECRET_KINDS = ["aws_id", "env_password", "env_token", "env_secret", "aws_env",
                "google", "azure", "url_password", "slack", "github"]


@pytest.mark.parametrize("kind", SECRET_KINDS)
def test_redact_text_removes_every_shape_the_pack_detects(kind):
    from scoutkit import redact_text
    line = f"2026-03-04T10:00:00Z ERROR startup failed cfg {_secret(kind)} retrying"
    cleaned = redact_text(line)
    secret_part = _secret(kind).split("=", 1)[-1].split("://")[-1]
    assert "<redacted" in cleaned, f"{kind} was not redacted at all"
    for fragment in (secret_part,):
        assert fragment not in cleaned, f"{kind}: {fragment!r} survived redaction"


@pytest.mark.parametrize("kind", SECRET_KINDS)
def test_an_environment_variable_shape_is_detected(kind):
    """`\\b` before the keyword cannot match after an underscore.

    That single character made DB_PASSWORD=, API_TOKEN= and
    AWS_SECRET_ACCESS_KEY= invisible to the old detector.
    """
    from scoutkit import credential_spans
    assert credential_spans(_secret(kind)), f"{kind} produced no credential span"


def test_redaction_keeps_the_surrounding_text_readable():
    from scoutkit import redact_text
    cleaned = redact_text("connection to db.internal refused after 3 attempts")
    assert cleaned == "connection to db.internal refused after 3 attempts"


def test_a_placeholder_is_left_alone_by_redaction():
    from scoutkit import redact_text
    assert redact_text("api_key=${API_KEY}") == "api_key=${API_KEY}"


def test_fingerprint_is_stable_across_calls():
    """Allowlisting by fingerprint depends on this."""
    assert fingerprint("hunter2hunter2hunter2") == fingerprint("hunter2hunter2hunter2")


def test_fingerprint_is_not_a_bare_sha256_prefix():
    """An unsalted digest of a weak secret is an oracle, not an identity."""
    import hashlib
    value = "hunter2"
    assert fingerprint(value) != hashlib.sha256(value.encode()).hexdigest()[:12]


def test_mask_withholds_the_exact_length_of_a_short_secret():
    """An exact length bounds the keyspace for an offline search."""
    masked = mask("4821")
    assert "len=4" not in masked
    assert "len<20" in masked


def test_mask_still_publishes_the_length_of_a_long_secret():
    assert "len=20" in mask("AK" + "IA" + "1234567890" + "ABCDEF")



# --- pack contract ---------------------------------------------------------
#
# Everything below verifies the pack holds together. `build_standalone.py`
# replaces this last test with a single-repo equivalent when it vendors the
# suite, so keep it last and keep its name stable.

import json  # noqa: E402
import re  # noqa: E402
from pathlib import Path  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SLUG = "api-contract-guard"

EXPECTED_SKILLS = {
    "api-contract-guard", "commit-narrator", "dependency-forecast", "error-triage",
    "flake-hunter", "repo-cartographer", "secret-sweeper", "test-gap-map",
}


def test_skill_manifest_is_wellformed():
    """This standalone repo declares an engine, a template, and a test file that exist."""
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["name"] == ROOT.name or manifest["name"] == MANIFEST_SLUG
    assert manifest["network_required"] is False
    assert manifest["cloud_writes"] is False
    assert manifest["sends_messages"] is False
    for key in ("engine", "template", "tests"):
        assert (ROOT / manifest[key]).is_file(), f"missing {key} -> {manifest[key]}"
    for name in ("SKILL.md", "skill.yaml", "README.md", "setup.md"):
        assert (ROOT / name).is_file(), f"missing {name}"
    assert (ROOT / manifest["schemas"]["output"]).is_file(), "vendored schema is missing"


def test_catalog_preview_assets_exist():
    """The catalog card image and its editable source both ship with the repo."""
    for asset in ("screenshots/preview.png", "screenshots/preview.svg"):
        path = ROOT / asset
        assert path.is_file(), f"missing catalog asset: {asset}"
        assert path.stat().st_size > 0, f"empty catalog asset: {asset}"


def test_vendored_library_is_complete():
    """Every scoutkit module the engines rely on is present in this repo."""
    lib = ROOT / "lib" / "scoutkit"
    for module in ("__init__.py", "cli.py", "findings.py", "hashing.py", "io.py", "render.py"):
        assert (lib / module).is_file(), f"vendored scoutkit is missing {module}"
