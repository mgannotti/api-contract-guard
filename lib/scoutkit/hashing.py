"""SHA-256 helpers, including the tamper-evident chain used by run-ledger."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: str | os.PathLike[str], *, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(payload: Any) -> str:
    """Canonical serialization used for every hash so digests are reproducible."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain_digest(previous: str, payload: Any) -> str:
    """Hash ``payload`` bound to ``previous``, forming an append-only chain.

    Changing or removing any earlier entry invalidates every later digest,
    which is what lets ``run-ledger`` detect retroactive edits.
    """
    return sha256_text(f"{previous}\n{canonical_json(payload)}")
