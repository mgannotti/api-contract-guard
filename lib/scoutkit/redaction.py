"""Redaction primitives.

A tool that finds credentials must never become a tool that copies them
somewhere new. Everything a scanner reports goes through :func:`mask` first, so
a finding is enough to locate a secret and never enough to use one.

The masked form is stable: the same secret produces the same fingerprint every
run, so a report can be diffed against last week's without ever holding a value,
and an allowlist can suppress a reviewed finding by fingerprint alone.

:func:`redact_text` is the other half. Any engine that reproduces a fragment of
its input — a log sample, a matched line, a quoted context — must route it
through here first. The detection set lives in this module rather than in each
engine on purpose: two copies of a credential pattern diverge, and the one that
falls behind silently republishes whatever it stopped recognizing.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from functools import lru_cache

__all__ = [
    "mask",
    "fingerprint",
    "redact_text",
    "credential_spans",
    "shannon_entropy",
    "looks_like_placeholder",
    "charset_of",
    "PREFIX_MIN_LENGTH",
]

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
# so nothing survives masking but a coarse length and the fingerprint.
PREFIX_MIN_LENGTH = 20

# A fixed salt keeps the fingerprint stable across runs and machines, which is
# what lets an allowlist suppress a reviewed finding by fingerprint.
#
# Two round counts, because the cost should sit where the risk is. A short
# secret is the one an offline search can actually recover, so it gets heavy
# stretching. A long one is infeasible to search regardless, and paying the same
# cost for every token in a large repository turned a three-second scan into a
# forty-second one. The tier is chosen by length, which the mask already
# discloses, so the split reveals nothing new.
_FINGERPRINT_SALT = b"scoutkit/redaction/v1"
_FINGERPRINT_ROUNDS_SHORT = 200_000
_FINGERPRINT_ROUNDS_LONG = 1_000


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


@lru_cache(maxsize=8192)
def fingerprint(value: str) -> str:
    """Stable 12-hex-character identity for a secret, derived but not reversible.

    Derived with PBKDF2 rather than a bare SHA-256 prefix. A plain digest of a
    low-entropy secret is not an identity, it is an oracle: a four-digit PIN or
    a dictionary word falls to an offline search in milliseconds, and the
    fingerprint is published in an artifact meant to be shareable. The stretch
    keeps the identity stable across runs — which is what allowlisting by
    fingerprint depends on — while making that search expensive.

    Short values get the heavy round count because they are the ones a search
    can realistically cover. Cached because a scan fingerprints the same value
    once per occurrence.
    """
    text = value or ""
    rounds = (_FINGERPRINT_ROUNDS_SHORT if len(text) < PREFIX_MIN_LENGTH
              else _FINGERPRINT_ROUNDS_LONG)
    derived = hashlib.pbkdf2_hmac("sha256", text.encode("utf-8"),
                                  _FINGERPRINT_SALT, rounds, dklen=6)
    return derived.hex()


def mask(value: str, *, keep: int = 3) -> str:
    """Render a secret as ``pre…len=42 fp=ab12cd34ef56`` — locatable, unusable.

    ``keep`` leading characters survive only when the value is long enough that
    three of them are a negligible fraction of it. A provider token is twenty
    characters or more and its prefix is what lets a human match the finding
    against a vault entry; a nine-character password would be giving away a
    third of itself for the same convenience, and the file and line in the
    finding already locate it.

    The exact length is published for the same reason and withheld below the
    same threshold: an exact length bounds the keyspace, and for a short secret
    that bound is most of what an offline search needs.
    """
    text = (value or "").strip().strip("\"'")
    if not text:
        return "<empty>"
    if len(text) >= PREFIX_MIN_LENGTH:
        return f"{text[:keep]}\u2026len={len(text)} fp={fingerprint(text)}"
    return f"len<{PREFIX_MIN_LENGTH} fp={fingerprint(text)}"


# --- shared credential detection -------------------------------------------
#
# One definition, used by every engine that either reports a credential or
# reproduces a fragment of text that might contain one.

_PROVIDER_SHAPES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b"),                              # AWS
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),                            # Slack
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),                            # GitHub
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),                                # Google
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"),  # JWT
    re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),                # PEM
)

# `(?:AccountKey|SharedAccessKey)=<value>` — the value is what must go.
_AZURE_KEY = re.compile(r"(?P<lead>(?:AccountKey|SharedAccessKey)=)(?P<value>[A-Za-z0-9+/=]{20,})")

# A credential in a `name = value` assignment.
#
# No `\b` before the keyword. `\b` requires a non-word character on the left,
# and `_` is a word character — so an anchored pattern never fires on
# `DB_PASSWORD=`, `API_TOKEN=`, or `AWS_SECRET_ACCESS_KEY=`, which is every
# environment variable anyone actually writes.
_ASSIGNED = re.compile(
    r"(?P<lead>(?<![A-Za-z0-9])[A-Za-z0-9_]{0,24}?"
    r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|access[_-]?token|"
    r"auth[_-]?token|authorization|client[_-]?secret|private[_-]?key|token)"
    r"(?:[_-][A-Za-z0-9]{1,24})?"
    r"[ \t]*[:=][ \t]*[\"']?)"
    r"(?P<value>[^\s\"',;&]{6,})",
    re.IGNORECASE,
)

# scheme://user:password@host — the password, not the whole URL.
_URL_PASSWORD = re.compile(
    r"(?P<lead>[a-z][a-z0-9+.\-]*://[^:@/\s]+:)(?P<value>[^@/\s]+)(?=@)", re.IGNORECASE
)


def credential_spans(text: str) -> list[tuple[int, int]]:
    """``[(start, end)]`` character ranges holding something credential-shaped."""
    spans: list[tuple[int, int]] = []
    for pattern in _PROVIDER_SHAPES:
        spans.extend((m.start(), m.end()) for m in pattern.finditer(text or ""))
    for pattern in (_AZURE_KEY, _ASSIGNED, _URL_PASSWORD):
        for m in pattern.finditer(text or ""):
            value = m.group("value")
            if looks_like_placeholder(value):
                continue
            spans.append((m.start("value"), m.end("value")))
    return sorted(set(spans))


def redact_text(text: str) -> str:
    """Replace every credential-shaped value in ``text`` with its mask.

    For text an engine intends to reproduce — a log sample, a matched line, a
    quoted fragment. The surrounding words survive so the result is still worth
    reading and still safe to paste into a ticket.
    """
    if not text:
        return text or ""
    spans = credential_spans(text)
    if not spans:
        return text

    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    out: list[str] = []
    cursor = 0
    for start, end in merged:
        out.append(text[cursor:start])
        out.append(f"<redacted {mask(text[start:end])}>")
        cursor = end
    out.append(text[cursor:])
    return "".join(out)
