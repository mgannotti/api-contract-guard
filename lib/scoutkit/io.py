"""Deterministic file I/O helpers.

All writers sort keys and use a fixed separator so that re-running a skill on
unchanged input produces a byte-identical artifact. That property is what makes
the run-ledger integrity chain meaningful.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable, Iterator

RESULT_SCHEMA_VERSION = "1.0.0"

TEXT_SUFFIXES = frozenset(
    {".txt", ".md", ".markdown", ".json", ".jsonl", ".html", ".htm", ".xml", ".csv", ".yaml", ".yml", ".log"}
)

_MAX_TEXT_BYTES = 8 * 1024 * 1024


class EvidenceError(ValueError):
    """Raised when supplied evidence is missing or structurally unusable."""


def read_text(path: str | os.PathLike[str], *, max_bytes: int = _MAX_TEXT_BYTES) -> str:
    """Read a text file as UTF-8, replacing undecodable bytes rather than failing."""
    p = Path(path)
    if not p.is_file():
        raise EvidenceError(f"not a file: {p}")
    data = p.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


def read_json(path: str | os.PathLike[str]) -> Any:
    p = Path(path)
    if not p.is_file():
        raise EvidenceError(f"not a file: {p}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid JSON in {p}: {exc}") from exc


def read_jsonl(path: str | os.PathLike[str]) -> list[Any]:
    """Read newline-delimited JSON, ignoring blank lines. Missing file -> []."""
    p = Path(path)
    if not p.is_file():
        return []
    records: list[Any] = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            records.append(json.loads(stripped))
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"invalid JSON on line {lineno} of {p}: {exc}") from exc
    return records


def write_json(path: str | os.PathLike[str], payload: Any) -> Path:
    """Atomically write canonical JSON (sorted keys, 2-space indent, trailing newline)."""
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return write_text(path, text)


def write_text(path: str | os.PathLike[str], text: str) -> Path:
    """Atomically write text so a crashed run never leaves a half-written artifact."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return p


def append_jsonl(path: str | os.PathLike[str], record: Any) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, sort_keys=True, ensure_ascii=False)
    with p.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(line + "\n")
    return p


def iter_text_files(root: str | os.PathLike[str], *, suffixes: Iterable[str] | None = None) -> Iterator[Path]:
    """Yield text-ish files under ``root`` in sorted order.

    A single file path is yielded as-is so callers accept either shape.
    """
    base = Path(root)
    allowed = frozenset(s.lower() for s in suffixes) if suffixes else TEXT_SUFFIXES
    if base.is_file():
        yield base
        return
    if not base.is_dir():
        raise EvidenceError(f"no such path: {base}")
    for candidate in sorted(base.rglob("*")):
        if candidate.is_file() and candidate.suffix.lower() in allowed:
            yield candidate


def relative_label(path: Path, root: Path) -> str:
    """Stable, forward-slashed label for a path, for reproducible reports."""
    try:
        rel = path.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        rel = Path(path.name)
    return rel.as_posix()
