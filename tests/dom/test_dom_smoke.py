#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - DOM smoke
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 03:50:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.dom.dom_detector import DOMXSSDetector
from brsxss.dom.vulnerability_types import RiskLevel


def test_scan_javascript_code_smoke():
    d = DOMXSSDetector()
    # Minimal JS that typical heuristics might flag: location + innerHTML sink
    js = """
    const q = location.hash;
    document.body.innerHTML = "<div>" + q + "</div>";
    """
    res = d.scan_javascript_code(js, source_name="inline.js")
    # We don't assert exact count; just smoke that API returns a valid result shape
    assert res.total_files == 1 and isinstance(d.get_vulnerability_summary(res), dict)


def test_filter_vulnerabilities_empty_ok():
    d = DOMXSSDetector()
    res = d.scan_javascript_code("", source_name="empty.js")
    filtered = d.filter_vulnerabilities(res, min_risk=RiskLevel.MEDIUM)
    assert filtered.total_vulnerabilities == 0

