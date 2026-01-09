#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - Templates SARIF/JUnit edge cases
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:43:30 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import json
from pathlib import Path

from brsxss.report.report_generator import ReportGenerator
from brsxss.report.report_types import ReportConfig, ReportFormat
from brsxss.report.data_models import VulnerabilityData, ScanStatistics


def _vuln(sev: str) -> VulnerabilityData:
    return VulnerabilityData(
        id="1",
        title="Title",
        description="Desc",
        severity=sev,
        confidence=0.6,
        url="https://x",
        parameter="q",
        payload="<p>",
        context="html_content",
    )


def test_sarif_template_minimal(tmp_path: Path):
    cfg = ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.SARIF])
    gen = ReportGenerator(cfg)
    files = gen.generate_report(
        [_vuln("low")], ScanStatistics(scan_duration=0.5), {"url": "https://x"}
    )
    sarif_path = Path(files[ReportFormat.SARIF])
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["properties"]["context_type"] == "html_content"


def test_junit_template_empty(tmp_path: Path):
    cfg = ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.JUNIT])
    gen = ReportGenerator(cfg)
    files = gen.generate_report(
        [], ScanStatistics(scan_duration=0.0), {"url": "https://x"}
    )
    xml = Path(files[ReportFormat.JUNIT]).read_text(encoding="utf-8")
    assert "<testsuites" in xml and 'tests="1"' in xml
