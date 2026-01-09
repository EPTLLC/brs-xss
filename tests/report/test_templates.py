#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - Report Templates
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:50:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import json

from brsxss.report.templates import HTMLTemplate, JSONTemplate, SARIFTemplate


def _sample_data():
    return {
        "vulnerabilities": [
            {
                "title": "XSS in 'q' parameter",
                "severity": "high",
                "url": "https://example.com/search?q=test",
                "parameter": "q",
                "context": "html_content",
                "description": "Reflected XSS",
                "payload": "<script>alert(1)</script>",
            }
        ],
        "statistics": {
            "scan_duration": 0.1,
            "total_requests": 1,
            "parameters_tested": 1,
        },
        "target_info": {"url": "https://example.com"},
    }


def test_html_template_contains_title_and_payload():
    tpl = HTMLTemplate()
    content = tpl.generate(_sample_data())
    assert "BRS-XSS Security Report" in content
    assert "XSS in 'q' parameter" in content
    assert "<script>alert(1)</script>" in content


def test_json_template_has_summary_and_vulnerabilities():
    tpl = JSONTemplate()
    js = tpl.generate(_sample_data())
    data = json.loads(js)
    assert data["summary"]["total_vulnerabilities"] == 1
    assert data["vulnerabilities"][0]["parameter"] == "q"


def test_sarif_template_builds_results():
    tpl = SARIFTemplate()
    js = tpl.generate(_sample_data())
    data = json.loads(js)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1
    assert data["runs"][0]["results"][0]["message"]["text"].startswith(
        "XSS vulnerability"
    )
