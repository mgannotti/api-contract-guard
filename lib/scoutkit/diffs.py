"""Unified diff parsing.

A diff is the only honest account of what a change actually did. Commit
messages describe intent; branch names describe hope. This parses the real
thing into files, hunks, and the lines that moved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator

from .io import EvidenceError

__all__ = ["Hunk", "DiffFile", "parse_unified_diff", "changed_symbols"]

_DIFF_GIT = re.compile(r"^diff --git a/(?P<a>.+?) b/(?P<b>.+)$")
_OLD_FILE = re.compile(r"^--- (?:a/)?(?P<path>.+?)(?:\t.*)?$")
_NEW_FILE = re.compile(r"^\+\+\+ (?:b/)?(?P<path>.+?)(?:\t.*)?$")
_HUNK = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_len>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_len>\d+))? @@(?P<heading>.*)$"
)
_NEW_MODE = re.compile(r"^new file mode ")
_DEL_MODE = re.compile(r"^deleted file mode ")
_RENAME_FROM = re.compile(r"^rename from (?P<path>.+)$")
_RENAME_TO = re.compile(r"^rename to (?P<path>.+)$")
_BINARY = re.compile(r"^(?:GIT )?[Bb]inary files? ")

# Definition forms across the languages this pack expects to meet. Deliberately
# shallow — this identifies *which* symbols a hunk touched, which is what a
# commit message needs. It is not a parser and does not pretend to be one.
_DEFINITION = re.compile(
    r"^\s*(?:"
    r"(?:async\s+)?def\s+(?P<py>\w+)"                                    # Python
    r"|class\s+(?P<cls>\w+)"                                             # Python/JS/Java/C#
    r"|(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(?P<js>\w+)"  # JS/TS
    r"|(?:export\s+)?const\s+(?P<const>\w+)\s*=\s*(?:async\s*)?\("        # JS/TS arrow
    r"|func\s+(?:\([^)]*\)\s*)?(?P<go>\w+)"                              # Go
    r"|fn\s+(?P<rs>\w+)"                                                 # Rust
    r"|(?:public|private|protected|internal|static|final|override|virtual)[\w\s<>\[\],]*?\s(?P<cs>\w+)\s*\("
    r")"
)


@dataclass
class Hunk:
    old_start: int = 0
    old_len: int = 0
    new_start: int = 0
    new_len: int = 0
    heading: str = ""
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    context: list[str] = field(default_factory=list)


@dataclass
class DiffFile:
    path: str = ""
    old_path: str = ""
    status: str = "modified"          # added | removed | renamed | modified
    binary: bool = False
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def added(self) -> int:
        return sum(len(h.added) for h in self.hunks)

    @property
    def removed(self) -> int:
        return sum(len(h.removed) for h in self.hunks)

    @property
    def churn(self) -> int:
        return self.added + self.removed

    def added_lines(self) -> Iterator[str]:
        for hunk in self.hunks:
            yield from hunk.added

    def removed_lines(self) -> Iterator[str]:
        for hunk in self.hunks:
            yield from hunk.removed

    def to_dict(self) -> dict[str, object]:
        return {
            "added": self.added,
            "binary": self.binary,
            "hunks": len(self.hunks),
            "old_path": self.old_path,
            "path": self.path,
            "removed": self.removed,
            "status": self.status,
        }


def parse_unified_diff(text: str) -> list[DiffFile]:
    """Parse a unified diff (``git diff``, ``git show``, or ``diff -u``) into files.

    Accepts output with or without the ``diff --git`` headers, so a plain
    ``diff -u`` between two trees parses the same way.
    """
    if not text or not text.strip():
        raise EvidenceError("the diff is empty")

    files: list[DiffFile] = []
    current: DiffFile | None = None
    hunk: Hunk | None = None
    saw_marker = False

    def close_file() -> None:
        nonlocal current, hunk
        if current is not None and (current.hunks or current.binary or current.status != "modified"):
            files.append(current)
        current, hunk = None, None

    for raw in text.splitlines():
        line = raw.rstrip("\r")

        git_header = _DIFF_GIT.match(line)
        if git_header:
            saw_marker = True
            close_file()
            current = DiffFile(path=git_header["b"].strip(), old_path=git_header["a"].strip())
            continue

        if current is not None:
            if _NEW_MODE.match(line):
                current.status = "added"
                continue
            if _DEL_MODE.match(line):
                current.status = "removed"
                continue
            rename_from = _RENAME_FROM.match(line)
            if rename_from:
                current.old_path = rename_from["path"].strip()
                current.status = "renamed"
                continue
            rename_to = _RENAME_TO.match(line)
            if rename_to:
                current.path = rename_to["path"].strip()
                current.status = "renamed"
                continue
            if _BINARY.match(line):
                current.binary = True
                continue

        old = _OLD_FILE.match(line)
        if old and not line.startswith("---" + " " * 60):
            saw_marker = True
            if current is None:
                current = DiffFile()
            if old["path"] not in ("/dev/null",):
                current.old_path = current.old_path or old["path"].strip()
            else:
                current.status = "added"
            hunk = None
            continue

        new = _NEW_FILE.match(line)
        if new:
            saw_marker = True
            if current is None:
                current = DiffFile()
            if new["path"] == "/dev/null":
                current.status = "removed"
                current.path = current.path or current.old_path
            else:
                current.path = new["path"].strip() if not current.path else current.path
            hunk = None
            continue

        header = _HUNK.match(line)
        if header and current is not None:
            hunk = Hunk(
                old_start=int(header["old_start"]),
                old_len=int(header["old_len"] or 1),
                new_start=int(header["new_start"]),
                new_len=int(header["new_len"] or 1),
                heading=header["heading"].strip(),
            )
            current.hunks.append(hunk)
            continue

        if hunk is None:
            continue

        if line.startswith("+"):
            hunk.added.append(line[1:])
        elif line.startswith("-"):
            hunk.removed.append(line[1:])
        elif line.startswith(" ") or line == "":
            hunk.context.append(line[1:] if line else "")

    close_file()

    if not files:
        if saw_marker:
            raise EvidenceError("the diff has file headers but no changed lines")
        raise EvidenceError(
            "no unified diff found. Export one with: git diff > change.diff, "
            "or git show <sha> > change.diff"
        )
    return files


def changed_symbols(diff_file: DiffFile) -> list[str]:
    """Names defined on lines this diff added or removed, in first-seen order.

    Reads only the ``+``/``-`` lines, never the hunk heading. The heading names
    the enclosing symbol, which is usually a function the change merely sits
    inside rather than one it altered.
    """
    seen: list[str] = []
    for line in list(diff_file.added_lines()) + list(diff_file.removed_lines()):
        match = _DEFINITION.match(line)
        if not match:
            continue
        name = next((v for v in match.groupdict().values() if v), None)
        if name and name not in seen and not name.lower() in {"if", "for", "while", "switch", "catch"}:
            seen.append(name)
    return seen
