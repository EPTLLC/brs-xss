"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 09:39 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Processor - Prepares report data with counts and normalized findings.
"""

from typing import Any
import hashlib
import re

from .types import SeverityCounts, ReportData, NormalizedFinding
from .counter import count_findings, _extract_severity


def prepare_report_data(
    vulnerabilities: list[dict[str, Any] | Any],
    deduplicate: bool = True,
) -> ReportData:
    """
    Prepare complete report data from raw vulnerabilities.

    This function:
    1. Normalizes all findings to consistent format
    2. Counts by severity using count_findings()
    3. Optionally deduplicates similar findings

    Args:
        vulnerabilities: Raw vulnerability list from scanner
        deduplicate: Whether to group similar findings

    Returns:
        ReportData with counts and normalized findings
    """
    # Convert to dicts if needed
    vuln_dicts = _to_dicts(vulnerabilities)

    # Normalize findings
    normalized = [_normalize_finding(v) for v in vuln_dicts]

    # Deduplicate if requested
    if deduplicate:
        normalized = _deduplicate_findings(normalized)

    # Count using THE counter
    counts = count_findings(vuln_dicts)

    return ReportData(
        counts=counts,
        findings=normalized,
        unique_findings=len(normalized),
        total_occurrences=len(vuln_dicts),
    )


def _to_dicts(vulnerabilities: list[Any]) -> list[dict[str, Any]]:
    """Convert vulnerability objects to dictionaries."""
    result = []
    for v in vulnerabilities:
        if isinstance(v, dict):
            result.append(v)
        elif hasattr(v, "model_dump"):
            result.append(v.model_dump())
        elif hasattr(v, "dict"):
            result.append(v.dict())
        elif hasattr(v, "__dict__"):
            result.append(vars(v))
        else:
            # Try to extract common fields
            result.append({
                "severity": getattr(v, "severity", "unknown"),
                "url": getattr(v, "url", ""),
                "parameter": getattr(v, "parameter", ""),
                "payload": getattr(v, "payload", ""),
                "context_type": getattr(v, "context_type", ""),
                "confidence": getattr(v, "confidence", 0.0),
            })
    return result


def _normalize_finding(vuln: dict[str, Any]) -> NormalizedFinding:
    """Normalize a single finding to consistent format."""
    severity = _extract_severity(vuln)

    # Extract xss_type with fallback
    xss_type = vuln.get("xss_type") or vuln.get("vulnerability_type") or "XSS"

    return NormalizedFinding(
        id=vuln.get("id", ""),
        url=vuln.get("url", ""),
        parameter=vuln.get("parameter", ""),
        payload=vuln.get("payload", ""),
        severity=severity,
        confidence=float(vuln.get("confidence", 0.0)),
        xss_type=str(xss_type),
        context_type=vuln.get("context_type", ""),
        evidence=vuln.get("evidence", ""),
        sink=vuln.get("sink", ""),
        source=vuln.get("source", ""),
        raw=vuln,  # Keep original data
    )


def _deduplicate_findings(
    findings: list[NormalizedFinding],
) -> list[NormalizedFinding]:
    """
    Deduplicate findings by fingerprint.

    Groups findings with same parameter + context + payload pattern.
    """
    if not findings:
        return []

    groups: dict[str, list[NormalizedFinding]] = {}

    for f in findings:
        fp = _compute_fingerprint(f)
        f.fingerprint = fp
        if fp not in groups:
            groups[fp] = []
        groups[fp].append(f)

    result: list[NormalizedFinding] = []

    for fp, group in groups.items():
        primary = group[0]

        # Collect affected URLs
        affected = []
        for f in group:
            if f.url:
                affected.append({"url": f.url, "method": "GET"})

        primary.affected_urls = affected
        primary.occurrence_count = len(group)
        result.append(primary)

    return result


def _compute_fingerprint(finding: NormalizedFinding) -> str:
    """Compute unique fingerprint for deduplication."""
    param = finding.parameter.lower().strip()
    context = finding.context_type.lower().strip()
    payload = finding.payload.lower().strip()

    # Normalize payload - remove variable parts
    payload_normalized = re.sub(r'https?://[^\s<>"\']+', "URL", payload)
    payload_normalized = re.sub(r"\d{10,}", "TS", payload_normalized)

    key = f"{param}|{context}|{payload_normalized}"
    return hashlib.md5(key.encode()).hexdigest()[:12]
