#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - Templates tail branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 19:55:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import json

from brsxss.report.templates import JSONTemplate, JUnitTemplate


def test_json_template_summary_and_counts():
    t = JSONTemplate()
    data = {
        "statistics": type("S", (), {"__dict__": {"scan_duration": 1.1, "total_requests": 2}})(),
        "vulnerabilities": [
            {"severity": "high", "parameter": "q", "payload": "<p>", "url": "https://x", "context": "html_content"},
            {"severity": "low", "parameter": "p", "payload": "<p>", "url": "https://x", "context": "html_content"},
        ],
        "target_info": {"url": "https://x"},
    }
    out = json.loads(t.generate(data))
    assert out["summary"]["risk_levels"]["high"] == 1


def test_junit_template_single_when_no_vulns():
    t = JUnitTemplate()
    out = t.generate({"vulnerabilities": [], "statistics": {"scan_duration": 0}})
    assert "<testcase name=\"XSS Security Test\"" in out


