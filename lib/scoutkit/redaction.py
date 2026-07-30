"""Redaction primitives.

A tool that finds credentials must never become a tool that copies them
somewhere new. Everything a scanner reports goes through :func:`mask` first, so
a finding is enough to locate a secret and never enough to use one.

The masked form is stable: the same secret produces the same fingerprint every
run, so a report can be diffed against last week's without ever holding a value.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter

__all__ = ["mask", "fingerprint", "shannon_entropy", "looks_like_placeholder", "charset_of"]

# Values that exist to be replaced. Reporting these as credentials is how a
# secret scanner trains its user to ignore it.
#
# Split into two tiers on purpose. Strong markers are unambiguous anywhere in a
# value. Weak words — "example", "test", "sample" — are ordinary English and
# appear inside real credentials by chance, so they only count at a token or
# string boundary. Matching them anywhere would silently dismiss any secret
# containing the letters t-e-s-t, which is the worst failure a scanner can have.
_STRONG_PLACEHOLDER = re.compile(
    r"^(?:x{3,}|y{3,}|a{3,}|0{3,}|1{3,}|\.{3,}|-{3,}|_{3,}|\*{3,})$"
    r"|^(?:your|my|the|some|an?)[-_ ]?(?:api[-_ ]?)?(?:key|token|secret|password|pass|pwd)"
    r"|change[-_ ]?me|placeholder|redacted|not[-_ ]?set"
    r"|^\$\{[^}]*\}$|^<[^>]*>$|^%[A-Za-z_]+%$|^\{\{[^}]*\}\}$|^\$[A-Z_][A-Z0-9_]*$",
    re.IGNORECASE,
)
_WEAK_PLACEHOLDER = re.compile(
    r"(?:^|[^A-Za-z0-9])"
    r"(?:example|sample|dummy|fake|test|insert|replace|todo|tbd|xxx|none|null|nil|empty|unset|value)"
    r"(?:[^A-Za-z0-9]|$)"
    r"|(?:EXAMPLE|SAMPLE|DUMMY|FAKE|TEST)$",
    re.IGNORECASE,
)

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_B64 = re.compile(r"^[A-Za-z0-9+/=_-]+$")

# Below this length a three-character prefix is a meaningful share of the value,
# so nothing survives masking but the length and the fingerprint.
PREFIX_MIN_LENGTH = 20


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character. Random-looking strings score above ~3.5."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def charset_of(text: str) -> str:
    if not text:
        return "empty"
    if _HEX.match(text):
        return "hex"
    if _B64.match(text):
        return "base64ish"
    return "mixed"


def looks_like_placeholder(value: str) -> bool:
    """True when a value is obviously a stand-in rather than a live credential."""
    stripped = (value or "").strip().strip("\"'")
    if len(stripped) < 4:
        return True
    if _STRONG_PLACEHOLDER.search(stripped):
        return True
    if _WEAK_PLACEHOLDER.search(stripped):
        return True
    # A single repeated character carries no information regardless of length.
    return len(set(stripped)) <= 2


def fingerprint(value: str) -> str:
    """Stable 12-hex-character identity for a secret, derived but not reversible."""
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()[:12]


def mask(value: str, *, keep: int = 3) -> str:
    """Render a secret as ``pre…len=42 fp=ab12cd34ef56`` — locatable, unusable.

    ``keep`` leading characters survive only when the value is long enough that
    three of them are a negligible fraction of it. A provider token is twenty
    characters or more and its prefix is what lets a human match the finding
    against a vault entry; a nine-character password would be giving away a
    third of itself for the same convenience, and the file and line in the
    finding already locate it.
    """
    text = (value or "").strip().strip("\"'")
    if not text:
        return "<empty>"
    head = text[:keep] if len(text) >= PREFIX_MIN_LENGTH else ""
    lead = f"{head}\u2026" if head else ""
    return f"{lead}len={len(text)} fp={fingerprint(text)}"
