#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - Report Templates Branch Fill
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 01:05:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.report.templates import (
    HTMLTemplate,
    JSONTemplate,
    SARIFTemplate,
    JUnitTemplate,
)


def test_html_template_header_and_stats_no_vulns():
    t = HTMLTemplate()
    html = t.generate(
        {
            "vulnerabilities": [],
            "statistics": {
                "scan_duration": 1.2,
                "total_requests": 3,
                "parameters_tested": 2,
            },
            "target_info": {"url": "http://example.com"},
        }
    )
    assert (
        "BRS-XSS Security Report" in html
        and "Total Vulnerabilities" in html
        and "http://example.com" in html
    )


def test_json_template_generate_and_summary_only():
    t = JSONTemplate()
    data = {
        "vulnerabilities": [
            {"severity": "high", "parameter": "q", "url": "http://e/a"},
            {"severity": "low", "parameter": "p", "url": "http://e/b"},
        ],
        "statistics": {"scan_duration": 0.5},
        "target_info": {"url": "http://example.com"},
    }
    js = t.generate(data)
    assert "scan_info" in js and "statistics" in js and "risk_levels" in js
    # summary-only path
    summ = t.generate_summary(
        {"statistics": {"vulnerabilities_found": 2, "total_requests": 10}}
    )
    assert "scan_summary" in summ and "vulnerabilities_found" in summ


def test_sarif_template_severity_mapping_and_properties():
    t = SARIFTemplate()
    vulns = [
        {
            "severity": s,
            "parameter": f"p{s}",
            "url": f"http://e/{s}",
            "payload": "x",
            "context": "html",
            "confidence": 0.9,
        }
        for s in ("critical", "high", "medium", "low", "unknown")
    ]
    s = t.generate({"vulnerabilities": vulns})
    # check level mapping appears in output
    assert (
        '"level": "error"' in s and '"level": "warning"' in s and '"level": "note"' in s
    )
    # properties presence
    assert '"properties": {' in s and '"parameter"' in s and '"payload"' in s


def test_junit_template_no_vulns_and_with_vulns():
    t = JUnitTemplate()
    # no vulns
    xml_empty = t.generate({"vulnerabilities": [], "statistics": {"scan_duration": 0}})
    assert (
        'tests="1" failures="0"' in xml_empty
        and '<testcase name="XSS Security Test"' in xml_empty
    )
    # with vulns
    xml_v = t.generate(
        {
            "vulnerabilities": [
                {
                    "parameter": "q",
                    "context": "html",
                    "url": "http://e",
                    "payload": "<x>",
                    "severity": "high",
                    "confidence": 0.5,
                }
            ],
            "statistics": {"scan_duration": 0.2},
        }
    )
    assert (
        'failures="1"' in xml_v
        and '<failure message="XSS vulnerability found"' in xml_v
    )
