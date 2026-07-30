"""scoutkit — shared primitives for the Scout Code Ops Kit skill pack.

Every skill in this pack is a deterministic, offline analyzer: it reads
evidence from disk — a repository, an exported history, a diff, a log, a
coverage report — produces findings, and renders canonical JSON plus
human-reviewable Markdown/HTML.

Nothing here performs network I/O, mutates the subject under analysis, clones
a repository, invokes git, or sends a message. A skill in this pack cannot
change the thing it is describing.
"""

from .code import (
    Commit,
    FileChange,
    IGNORED_DIRS,
    LANGUAGE_BY_SUFFIX,
    classify_path,
    detect_language,
    is_probably_binary,
    is_source,
    iter_repo_files,
    parse_git_log,
    parse_iso_date,
    repo_relative,
)
from .diffs import DiffFile, Hunk, changed_symbols, parse_unified_diff
from .findings import Finding, Report, Severity
from .hashing import chain_digest, sha256_bytes, sha256_file, sha256_text
from .io import (
    RESULT_SCHEMA_VERSION,
    EvidenceError,
    append_jsonl,
    iter_text_files,
    read_json,
    read_jsonl,
    read_text,
    relative_label,
    write_json,
    write_text,
)
from .logs import (
    Frame,
    deepest_application_frame,
    level_of,
    normalize_line,
    signature,
    split_records,
    stack_frames,
)
from .redaction import (
    charset_of,
    credential_spans,
    fingerprint,
    looks_like_placeholder,
    mask,
    redact_text,
    shannon_entropy,
)
from .render import render_html, render_markdown
from .text import IMPERATIVE_VERBS, jaccard, significant_tokens, title_case_words, truncate
from .versions import RangeKind, Version, bump_kind, parse_version, range_kind

__all__ = [
    "Commit",
    "DiffFile",
    "EvidenceError",
    "FileChange",
    "Finding",
    "Frame",
    "Hunk",
    "IGNORED_DIRS",
    "IMPERATIVE_VERBS",
    "LANGUAGE_BY_SUFFIX",
    "RESULT_SCHEMA_VERSION",
    "RangeKind",
    "Report",
    "Severity",
    "Version",
    "append_jsonl",
    "bump_kind",
    "chain_digest",
    "changed_symbols",
    "charset_of",
    "classify_path",
    "credential_spans",
    "deepest_application_frame",
    "detect_language",
    "fingerprint",
    "is_probably_binary",
    "is_source",
    "iter_repo_files",
    "iter_text_files",
    "jaccard",
    "level_of",
    "looks_like_placeholder",
    "mask",
    "normalize_line",
    "parse_git_log",
    "parse_iso_date",
    "parse_unified_diff",
    "parse_version",
    "range_kind",
    "read_json",
    "read_jsonl",
    "read_text",
    "redact_text",
    "relative_label",
    "render_html",
    "render_markdown",
    "repo_relative",
    "sha256_bytes",
    "sha256_file",
    "sha256_text",
    "shannon_entropy",
    "signature",
    "significant_tokens",
    "split_records",
    "stack_frames",
    "title_case_words",
    "truncate",
    "write_json",
    "write_text",
]

__version__ = "1.0.0"
