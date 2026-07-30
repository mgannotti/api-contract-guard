"""Log normalization and stack-frame extraction.

Two occurrences of the same bug almost never produce the same string. They
differ by timestamp, request id, thread number, memory address, and the row
that happened to trip it. Grouping raw lines therefore produces one cluster per
*occurrence*, which is the same as no grouping at all.

Normalization replaces everything variable with a token, leaving a template
that is stable across occurrences and can be counted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

__all__ = [
    "Frame",
    "normalize_line",
    "signature",
    "stack_frames",
    "split_records",
    "deepest_application_frame",
]

# Order matters: the broadest, most structured patterns first, so a timestamp is
# replaced as a timestamp rather than shredded into separate numbers.
_SUBSTITUTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}"), "<DATE>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<TIME>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "<EMAIL>"),
    (re.compile(r"\b[a-zA-Z]:\\[^\s\"']+"), "<PATH>"),
    (re.compile(r"(?<![\w.])/(?:[\w.-]+/){1,}[\w.-]+"), "<PATH>"),
    (re.compile(r"\bhttps?://[^\s\"')]+"), "<URL>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<HASH>"),
    # No word boundary on the numeric rules: durations and sizes arrive welded to
    # their unit ("1200ms", "4KB"), and \b never fires between a digit and a letter,
    # so a bounded rule leaves exactly the values that differ per occurrence.
    (re.compile(r"\d+\.\d+"), "<FLOAT>"),
    (re.compile(r"\d+"), "<N>"),
    (re.compile(r"'[^']{0,120}'"), "<STR>"),
    (re.compile(r'"[^"]{0,120}"'), "<STR>"),
)

_LEVEL = re.compile(
    r"\b(?P<level>TRACE|DEBUG|INFO|INFORMATION|NOTICE|WARN|WARNING|ERROR|ERR|SEVERE|FATAL|CRITICAL)\b"
)
_WS = re.compile(r"\s+")


def normalize_line(line: str) -> str:
    """Reduce one log line to a template with variable parts tokenized."""
    text = line.strip()
    if not text:
        return ""
    for pattern, token in _SUBSTITUTIONS:
        text = pattern.sub(token, text)
    return _WS.sub(" ", text).strip()


def level_of(line: str) -> str:
    """Severity word present in a line, uppercased, or ``""`` when absent."""
    match = _LEVEL.search(line or "")
    return match["level"].upper() if match else ""


def signature(lines: Iterable[str], *, depth: int = 3) -> str:
    """A stable cluster key from the first ``depth`` meaningful normalized lines."""
    kept: list[str] = []
    for line in lines:
        norm = normalize_line(line)
        if norm:
            kept.append(norm)
        if len(kept) >= depth:
            break
    return " | ".join(kept)


@dataclass(frozen=True, slots=True)
class Frame:
    """One stack frame: where the code was, and what it was doing."""

    location: str
    function: str = ""
    line: int | None = None

    @property
    def label(self) -> str:
        where = f"{self.location}:{self.line}" if self.line else self.location
        return f"{where} {self.function}".strip()


_FRAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Python:  File "app/handler.py", line 42, in dispatch
    re.compile(r'^\s*File "(?P<location>[^"]+)", line (?P<line>\d+), in (?P<function>\S+)'),
    # Java / Kotlin:  at com.acme.Service.handle(Service.java:42)
    re.compile(r"^\s*at (?P<function>[\w$.<>]+)\((?P<location>[^:)]+)(?::(?P<line>\d+))?\)"),
    # JS / TS:  at handle (/srv/app/handler.js:42:9)
    re.compile(r"^\s*at (?P<function>[^\s(]+) \((?P<location>[^):]+):(?P<line>\d+)(?::\d+)?\)"),
    # JS anonymous:  at /srv/app/handler.js:42:9
    re.compile(r"^\s*at (?P<location>[^\s():]+):(?P<line>\d+)(?::\d+)?$"),
    # .NET:  at Acme.Service.Handle() in C:\src\Service.cs:line 42
    re.compile(r"^\s*at (?P<function>[\w.`<>+]+)\([^)]*\) in (?P<location>.+?):line (?P<line>\d+)"),
    # Go:  /srv/app/handler.go:42 +0x1f
    re.compile(r"^\s*(?P<location>\S+\.go):(?P<line>\d+)"),
)

# Frames inside a runtime or a dependency tell you where the failure *surfaced*.
# The deepest frame that is not one of these is where it probably *originated*,
# and that is the frame worth clustering on.
_VENDOR_FRAME = re.compile(
    r"(^|[/\\])(site-packages|dist-packages|node_modules|vendor|third_party|"
    r"lib[/\\]python|runtime|jre|jdk|golang|\.cargo|\.rustup|gems)([/\\]|$)"
    r"|^(java\.|javax\.|jdk\.|sun\.|System\.|Microsoft\.|Newtonsoft\.)"
    r"|^<(?:frozen|string|anonymous)",
    re.IGNORECASE,
)


def stack_frames(text: str) -> list[Frame]:
    """Extract stack frames from a traceback in any of the common formats."""
    frames: list[Frame] = []
    for raw in (text or "").splitlines():
        for pattern in _FRAME_PATTERNS:
            match = pattern.match(raw)
            if not match:
                continue
            groups = match.groupdict()
            line_no = groups.get("line")
            frames.append(Frame(
                location=(groups.get("location") or "").strip(),
                function=(groups.get("function") or "").strip(),
                line=int(line_no) if line_no and line_no.isdigit() else None,
            ))
            break
    return frames


def deepest_application_frame(frames: list[Frame]) -> Frame | None:
    """The last frame that is not runtime or dependency code.

    Python and .NET print the innermost frame last; JS and Java print it first.
    Scanning from the end and falling back to the start covers both without
    needing to know which language produced the trace.
    """
    for frame in reversed(frames):
        if frame.location and not _VENDOR_FRAME.search(frame.location):
            return frame
    for frame in reversed(frames):
        if frame.location:
            return frame
    return None


_HARD_START = re.compile(
    r"^(?:\[?\d{4}-\d{2}-\d{2}"                       # leading ISO date
    r"|\[?\d{2}:\d{2}:\d{2}"                          # or bare time
    r"|\[(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\]"
    r"|(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)[\s:]"
    r")",
    re.IGNORECASE,
)
_TRACEBACK_HEAD = re.compile(r"^Traceback \(most recent call last\)")
_EXCEPTION_LINE = re.compile(r"^[\w.$]*(?:Error|Exception|Failure|Fault)\b\s*[:\-]")
_CONTINUATION = re.compile(r"^(?:\s+|Caused by:|\.{3}|at\s|File \"|\tat\s)")


def split_records(text: str) -> list[list[str]]:
    """Group log lines into records, keeping tracebacks attached to their message.

    A stack trace split across ten lines is one event. Treating each line as its
    own record inflates every count by the depth of the stack and buries the
    message that names the failure.

    Only a timestamp or a level word unambiguously opens a new record. A
    ``Traceback`` header opens one *only* when the record already in hand has a
    traceback of its own, so a message followed by its stack stays whole while
    two consecutive stacks still separate. The exception line that terminates a
    Python traceback is a continuation for the same reason: it belongs to the
    frames above it, not to whatever comes next.
    """
    records: list[list[str]] = []
    current: list[str] = []
    has_trace = False

    def flush() -> None:
        nonlocal current, has_trace
        if current:
            records.append(current)
        current, has_trace = [], False

    for raw in (text or "").splitlines():
        if not raw.strip():
            continue

        if _CONTINUATION.match(raw):
            current.append(raw)
            has_trace = True
            continue

        if _HARD_START.match(raw):
            flush()
            current = [raw]
            continue

        if _TRACEBACK_HEAD.match(raw):
            if has_trace:
                flush()
            current.append(raw)
            has_trace = True
            continue

        if _EXCEPTION_LINE.match(raw):
            if has_trace or not current:
                current.append(raw)
                continue
            flush()
            current = [raw]
            continue

        current.append(raw)

    flush()
    return records
