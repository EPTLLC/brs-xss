"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 09:39 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Type definitions for the count module.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SeverityCounts:
    """
    Vulnerability counts by severity.

    THIS IS THE ONLY PLACE WHERE COUNTS ARE DEFINED.
    All UI, Telegram, PDF, API must use this structure.
    """

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def total(self) -> int:
        """Total vulnerabilities"""
        return self.critical + self.high + self.medium + self.low

    def to_dict(self) -> dict[str, int]:
        """Convert to dictionary for JSON serialization"""
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "total": self.total,
        }

    @classmethod
    def from_dict(cls, data: dict[str, int]) -> "SeverityCounts":
        """Create from dictionary"""
        return cls(
            critical=data.get("critical", 0),
            high=data.get("high", 0),
            medium=data.get("medium", 0),
            low=data.get("low", 0),
        )

    def __str__(self) -> str:
        return f"Critical: {self.critical} | High: {self.high} | Medium: {self.medium} | Low: {self.low}"


@dataclass
class NormalizedFinding:
    """
    A normalized vulnerability finding ready for counting and reporting.
    """

    id: str
    url: str
    parameter: str
    payload: str
    severity: str  # critical, high, medium, low
    confidence: float
    xss_type: str
    context_type: str

    # Evidence
    evidence: str = ""

    # Classification details
    sink: str = ""
    source: str = ""

    # Metadata
    confirmation_reason: str = ""

    # For deduplication
    fingerprint: str = ""
    occurrence_count: int = 1
    affected_urls: list[dict[str, str]] = field(default_factory=list)

    # Raw data for detailed reports
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            "id": self.id,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "severity": self.severity,
            "confidence": self.confidence,
            "xss_type": self.xss_type,
            "context_type": self.context_type,
            "evidence": self.evidence,
            "sink": self.sink,
            "source": self.source,
            "confirmation_reason": self.confirmation_reason,
            "fingerprint": self.fingerprint,
            "occurrence_count": self.occurrence_count,
            "affected_urls": self.affected_urls,
        }
        # Merge raw data
        result.update(self.raw)
        return result


@dataclass
class ReportData:
    """
    Complete report data structure.

    This is what ALL report generators receive:
    - UI
    - Telegram
    - PDF
    - JSON API

    Ensures consistency across all outputs.
    """

    # Counts - THE source of truth
    counts: SeverityCounts

    # Findings list
    findings: list[NormalizedFinding] = field(default_factory=list)

    # Statistics
    unique_findings: int = 0
    total_occurrences: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "counts": self.counts.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "stats": {
                "unique_findings": self.unique_findings,
                "total_occurrences": self.total_occurrences,
            },
        }
