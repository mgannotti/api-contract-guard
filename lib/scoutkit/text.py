"""Small text helpers shared across the pack.

Deliberately thin. Anything that needs real parsing lives in the module for its
domain — :mod:`scoutkit.code`, :mod:`scoutkit.diffs`, :mod:`scoutkit.logs`.
"""

from __future__ import annotations

import re

__all__ = ["significant_tokens", "jaccard", "truncate", "title_case_words", "IMPERATIVE_VERBS"]

_STOPWORDS = frozenset({
    "the", "a", "an", "any", "all", "and", "or", "of", "to", "in", "into", "on",
    "for", "with", "without", "from", "at", "by", "it", "its", "this", "that",
    "these", "those", "them", "they", "you", "your", "do", "does", "not", "is",
    "are", "was", "were", "be", "been", "has", "have", "had", "will", "would",
    "can", "could", "should", "when", "where", "which", "who", "what", "how",
})


def significant_tokens(text: str) -> set[str]:
    """Content words, lowercased — the words that carry the meaning of a phrase."""
    return {
        w for w in re.findall(r"[a-z][a-z0-9'_-]{2,}", (text or "").lower())
        if w not in _STOPWORDS
    }


def jaccard(a: set[str], b: set[str]) -> float:
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def truncate(text: str, limit: int = 120) -> str:
    """Collapse whitespace and cut to ``limit`` characters with an ellipsis."""
    flat = " ".join((text or "").split())
    return flat if len(flat) <= limit else flat[: limit - 1].rstrip() + "\u2026"


def title_case_words(slug: str) -> str:
    return " ".join(part.capitalize() for part in re.split(r"[-_\s]+", slug or "") if part)


# The verbs a commit subject should start with, by convention and by usefulness:
# they describe what the change does to the codebase rather than what the author
# was thinking about while making it.
IMPERATIVE_VERBS = frozenset({
    "add", "remove", "delete", "drop", "fix", "correct", "update", "upgrade",
    "downgrade", "bump", "refactor", "rename", "move", "extract", "inline",
    "introduce", "replace", "revert", "restore", "handle", "guard", "validate",
    "support", "implement", "document", "test", "cover", "simplify", "split",
    "merge", "enable", "disable", "expose", "hide", "cache", "log", "rework",
    "harden", "relax", "skip", "ignore", "pin", "unpin", "vendor", "port",
})
