"""
Normalized findings schema.

Every scanner adapter (Bandit, detect-secrets, future ones) must translate
its tool-specific output into these shapes. Every reporter (JSON, Markdown,
HTML, SARIF) reads only from these shapes. Neither side needs to know
anything about the other — that's the whole point of the adapter pattern.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import hashlib


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Higher = more severe. Used for sorting and threshold comparisons."""
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return order[self]


@dataclass
class Finding:
    """A single normalized security finding, regardless of which scanner produced it."""

    scanner: str  # e.g. "bandit", "detect-secrets"
    rule_id: str  # scanner's own rule/check ID, e.g. "B105", "AWSKeyDetector"
    title: str  # short human-readable description
    severity: Severity
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    description: str = ""
    suppressed: bool = False
    suppression_reason: Optional[str] = None

    @property
    def fingerprint(self) -> str:
        """
        Stable identity for a finding, used for deduplication when two
        scanners flag the same underlying issue in the same place.
        """
        key = f"{self.scanner}:{self.rule_id}:{self.file_path}:{self.line_start}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class ScannerRunResult:
    """Metadata + findings for a single scanner's execution."""

    scanner: str
    success: bool
    duration_seconds: float
    findings: list[Finding] = field(default_factory=list)
    error_message: Optional[str] = None

    @property
    def actionable_count(self) -> int:
        return len([f for f in self.findings if not f.suppressed])


@dataclass
class AggregatedResults:
    """The final merged output of an entire scan run, across all scanners."""

    scanner_runs: list[ScannerRunResult] = field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        return [f for run in self.scanner_runs for f in run.findings]

    @property
    def actionable_findings(self) -> list[Finding]:
        return [f for f in self.all_findings if not f.suppressed]

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.actionable_findings:
            counts[f.severity.value] += 1
        return counts

    def exceeds_threshold(self, threshold: Severity) -> bool:
        """True if any actionable finding is at or above the given severity."""
        return any(f.severity.rank >= threshold.rank for f in self.actionable_findings)
