"""Findings model shared by every analyzer in the pack.

A ``Report`` is the canonical result object. Skills differ in how they *derive*
findings; they do not differ in how findings are shaped, ranked, or serialized.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .io import RESULT_SCHEMA_VERSION


class Severity:
    """Ordered severity vocabulary. ``rank`` drives sorting and gate decisions."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    ORDER = (CRITICAL, HIGH, MEDIUM, LOW, INFO)

    @classmethod
    def rank(cls, severity: str) -> int:
        try:
            return cls.ORDER.index(severity)
        except ValueError:
            return len(cls.ORDER)

    @classmethod
    def validate(cls, severity: str) -> str:
        if severity not in cls.ORDER:
            raise ValueError(f"unknown severity {severity!r}; expected one of {cls.ORDER}")
        return severity

    @classmethod
    def max(cls, severities: Iterable[str]) -> str | None:
        ranked = sorted(severities, key=cls.rank)
        return ranked[0] if ranked else None


@dataclass(frozen=True, slots=True)
class Finding:
    """One observation. ``code`` is stable across versions so findings are diffable."""

    code: str
    severity: str
    title: str
    detail: str
    locator: str = ""
    evidence: str = ""
    recommendation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        Severity.validate(self.severity)
        if not self.code:
            raise ValueError("finding code must be non-empty")

    @property
    def sort_key(self) -> tuple[int, str, str]:
        return (Severity.rank(self.severity), self.code, self.locator)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "detail": self.detail,
            "evidence": self.evidence,
            "locator": self.locator,
            "metadata": dict(self.metadata),
            "recommendation": self.recommendation,
            "severity": self.severity,
            "title": self.title,
        }


@dataclass
class Report:
    """Container for a single skill run."""

    skill: str
    verdict: str = "pass"
    generated_at: str = ""
    subject: str = ""
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    sections: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def note(self, message: str) -> None:
        if message not in self.notes:
            self.notes.append(message)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key)

    def counts(self) -> dict[str, int]:
        counts = {level: 0 for level in Severity.ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def highest_severity(self) -> str | None:
        return Severity.max(f.severity for f in self.findings)

    def decide_verdict(self, *, block_at: str = Severity.CRITICAL, review_at: str = Severity.MEDIUM) -> str:
        """Derive a three-state verdict from the worst finding present."""
        worst = self.highest_severity()
        if worst is None:
            self.verdict = "pass"
        elif Severity.rank(worst) <= Severity.rank(block_at):
            self.verdict = "block"
        elif Severity.rank(worst) <= Severity.rank(review_at):
            self.verdict = "review"
        else:
            self.verdict = "pass"
        return self.verdict

    def to_dict(self) -> dict[str, Any]:
        return {
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "generated_at": self.generated_at,
            "highest_severity": self.highest_severity(),
            "notes": list(self.notes),
            "schema_version": RESULT_SCHEMA_VERSION,
            "sections": self.sections,
            "skill": self.skill,
            "subject": self.subject,
            "summary": self.summary,
            "verdict": self.verdict,
        }
