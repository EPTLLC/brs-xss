#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - SARIFReporter
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:43:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.report.sarif_reporter import SARIFReporter
from brsxss.report.data_models import VulnerabilityData


def test_sarif_reporter_generates_valid_runs(tmp_path):
    vulns = [
        VulnerabilityData(
            id="x1",
            title="XSS in 'q'",
            description="Reflected XSS",
            severity="high",
            confidence=0.9,
            url="https://example.com/search?q=test",
            parameter="q",
            payload="<script>alert(1)</script>",
            context="html_content",
            vulnerability_type="reflected_xss",
            context_type="html_content",
        )
    ]
    scan_info = {
        "targets_scanned": 1,
        "duration": "1s",
        "command_line": "brs-xss scan"
    }

    reporter = SARIFReporter()
    sarif = reporter.generate_sarif(vulns, scan_info)

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "BRS-XSS"
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["message"]["arguments"][0] == "q"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("https://example.com")


