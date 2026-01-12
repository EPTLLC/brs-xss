"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 09:39 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Counter - THE function for counting vulnerabilities.

SINGLE SOURCE OF TRUTH:
All counting goes through count_findings().
"""

from typing import Any

from .types import SeverityCounts


def count_findings(vulnerabilities: list[dict[str, Any]]) -> SeverityCounts:
    """
    Count vulnerabilities by severity.

    THIS IS THE ONLY FUNCTION THAT COUNTS VULNERABILITIES.
    All UI, Telegram, PDF, API must use this function.

    Args:
        vulnerabilities: List of vulnerability dictionaries.
                        Each must have 'severity' field.

    Returns:
        SeverityCounts with critical, high, medium, low counts.

    Example:
        counts = count_findings(scan.vulnerabilities)
        print(f"Critical: {counts.critical}")
        print(f"Total: {counts.total}")
    """
    counts = SeverityCounts()

    for vuln in vulnerabilities:
        severity = _extract_severity(vuln)

        if severity == "critical":
            counts.critical += 1
        elif severity == "high":
            counts.high += 1
        elif severity == "medium":
            counts.medium += 1
        elif severity == "low":
            counts.low += 1
        # info and other severities are not counted

    return counts


def _extract_severity(vuln: dict[str, Any] | Any) -> str:
    """
    Extract severity string from vulnerability object.

    Handles multiple formats:
    - dict with 'severity' key
    - object with severity attribute
    - SeverityLevel enum
    """
    # If it's a dict
    if isinstance(vuln, dict):
        severity = vuln.get("severity", "")
    # If it's an object with attributes
    elif hasattr(vuln, "severity"):
        severity = getattr(vuln, "severity", "")
    else:
        return "unknown"

    # Handle enum (SeverityLevel.HIGH -> "high")
    if hasattr(severity, "value"):
        severity = severity.value

    # Normalize to lowercase string
    return str(severity).lower().strip()
