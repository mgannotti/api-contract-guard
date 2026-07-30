"""Version and range handling for dependency and API analysis.

Semver with the parts of the real world that semver does not cover: epochs,
four-part Microsoft versions, ``v`` prefixes, and the range syntaxes npm,
pip, Cargo, and Go each spell differently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = ["Version", "parse_version", "bump_kind", "range_kind", "RangeKind"]

_VERSION = re.compile(
    r"^\s*[vV=]?\s*"
    r"(?:(?P<epoch>\d+)!)?"
    r"(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-._]?(?P<pre>(?:a|b|c|rc|alpha|beta|pre|preview|dev)[.-]?\d*))?"
    r"(?:\+(?P<build>[0-9A-Za-z.-]+))?"
    r"\s*$"
)


@dataclass(frozen=True, slots=True)
class Version:
    parts: tuple[int, ...]
    pre: str = ""
    epoch: int = 0
    raw: str = ""

    @property
    def major(self) -> int:
        return self.parts[0] if self.parts else 0

    @property
    def minor(self) -> int:
        return self.parts[1] if len(self.parts) > 1 else 0

    @property
    def patch(self) -> int:
        return self.parts[2] if len(self.parts) > 2 else 0

    @property
    def is_prerelease(self) -> bool:
        return bool(self.pre)

    def _key(self) -> tuple[Any, ...]:
        padded = self.parts + (0,) * (4 - len(self.parts)) if len(self.parts) < 4 else self.parts
        # A prerelease sorts below its own release: 2.0.0-rc1 < 2.0.0.
        return (self.epoch, padded, 0 if self.pre else 1, self.pre)

    def __lt__(self, other: "Version") -> bool:
        return self._key() < other._key()

    def __le__(self, other: "Version") -> bool:
        return self._key() <= other._key()

    def __gt__(self, other: "Version") -> bool:
        return self._key() > other._key()

    def __ge__(self, other: "Version") -> bool:
        return self._key() >= other._key()

    def __str__(self) -> str:
        return self.raw or ".".join(str(p) for p in self.parts)


def parse_version(text: Any) -> Version | None:
    """Parse a version string. Returns None when the text is not a version."""
    if isinstance(text, (int, float)):
        text = str(text)
    if not isinstance(text, str):
        return None
    match = _VERSION.match(text)
    if not match:
        return None
    parts = tuple(int(p) for p in match["release"].split("."))
    return Version(
        parts=parts,
        pre=(match["pre"] or "").lower(),
        epoch=int(match["epoch"] or 0),
        raw=text.strip(),
    )


def bump_kind(current: Version | None, target: Version | None) -> str:
    """Classify the distance between two versions.

    ``major`` | ``minor`` | ``patch`` | ``prerelease`` | ``none`` | ``downgrade``
    | ``unknown``. A 0.x major is reported as ``major`` when the *minor* moves,
    because that is what 0.x actually means and treating it as a minor bump is
    how a "safe" upgrade removes half an API.
    """
    if current is None or target is None:
        return "unknown"
    if target < current:
        return "downgrade"
    if target.parts == current.parts and target.pre == current.pre:
        return "none"
    if target.major != current.major:
        return "major"
    if current.major == 0 and target.minor != current.minor:
        return "major"
    if target.minor != current.minor:
        return "minor"
    if target.patch != current.patch:
        return "patch"
    return "prerelease"


class RangeKind:
    EXACT = "exact"
    PATCH = "patch-range"
    MINOR = "minor-range"
    ANY = "unbounded"
    GIT = "git-or-url"
    LOCAL = "local-path"
    UNKNOWN = "unknown"


_ANY = re.compile(r"^\s*(?:\*|x|X|latest|)\s*$")
_GIT = re.compile(r"^\s*(?:git\+|git:|https?://|ssh://|github:|gitlab:|bitbucket:)", re.I)
_LOCAL = re.compile(r"^\s*(?:file:|link:|\.{1,2}/|/|[a-zA-Z]:\\)")
_CARET = re.compile(r"^\s*\^")
_TILDE = re.compile(r"^\s*~")
_COMPATIBLE = re.compile(r"^\s*~=")
_EXACT = re.compile(r"^\s*(?:==?|===)?\s*v?\d")
_HAS_UPPER = re.compile(r"[<]")
_LOWER_ONLY = re.compile(r"^\s*>=?")


def range_kind(spec: Any) -> str:
    """Classify a dependency range by how much room it leaves for surprise.

    The distinction that matters is not the syntax but the ceiling: a range with
    no upper bound will one day resolve to a major version nobody tested, and it
    will do it during an unrelated install.
    """
    if spec is None:
        return RangeKind.UNKNOWN
    if isinstance(spec, dict):
        spec = spec.get("version") or spec.get("spec") or ""
    text = str(spec).strip()

    if _ANY.match(text):
        return RangeKind.ANY
    if _GIT.match(text):
        return RangeKind.GIT
    if _LOCAL.match(text):
        return RangeKind.LOCAL
    if _COMPATIBLE.match(text):
        return RangeKind.MINOR
    if _CARET.match(text):
        return RangeKind.MINOR
    if _TILDE.match(text):
        return RangeKind.PATCH
    if _HAS_UPPER.search(text):
        return RangeKind.MINOR
    if _LOWER_ONLY.match(text):
        return RangeKind.ANY
    if _EXACT.match(text) and not re.search(r"[|,\s]", text.strip()):
        return RangeKind.EXACT
    if "||" in text or " - " in text:
        return RangeKind.MINOR
    return RangeKind.UNKNOWN
