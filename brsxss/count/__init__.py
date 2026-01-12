"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 09:39 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Count Module - SINGLE SOURCE OF TRUTH for vulnerability counting.

CRITICAL ARCHITECTURE RULE:
==========================
ALL vulnerability counting MUST go through this module.
UI, Telegram, PDF, API - everyone uses count_findings().
NO EXCEPTIONS.

This ensures:
- Identical numbers everywhere (UI = Telegram = PDF = API)
- Single place to debug counting logic
- Transparent and auditable rules
- Easy to extend

Usage:
------
    from brsxss.count import count_findings, SeverityCounts

    # Count vulnerabilities
    counts = count_findings(vulnerabilities)

    # Access counts
    print(counts.critical)   # Number of critical
    print(counts.high)       # Number of high
    print(counts.total)      # Total confirmed (critical+high+medium+low)

    # For reports
    report_data = prepare_report_data(vulnerabilities, mode="standard")
    print(report_data.counts.critical)
    print(report_data.confirmed)  # List of confirmed findings
"""

from .types import SeverityCounts, ReportData, NormalizedFinding
from .counter import count_findings
from .processor import prepare_report_data

__all__ = [
    "SeverityCounts",
    "ReportData",
    "NormalizedFinding",
    "count_findings",
    "prepare_report_data",
]
