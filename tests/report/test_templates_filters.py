#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - Templates filters (min_severity, max_vulnerabilities)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:36:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import json
from pathlib import Path

from brsxss.report.report_generator import ReportGenerator
from brsxss.report.report_types import ReportConfig, ReportFormat
from brsxss.report.data_models import VulnerabilityData, ScanStatistics


def _mk_vuln(idx: int, severity: str) -> VulnerabilityData:
    # v4.0.0-beta.2: Add evidence_response to make findings confirmed
    return VulnerabilityData(
        id=f"v-{idx}",
        title=f"Vuln {idx}",
        description="desc",
        severity=severity,
        confidence=0.9,
        url=f"https://t/{idx}",
        parameter=f"p{idx}",
        payload="<p>",
        context="html_content",
        evidence_response="Payload reflected in response",
    )


def test_html_template_respects_filters(tmp_path: Path):
    vulns = [
        _mk_vuln(1, "low"),
        _mk_vuln(2, "high"),
        _mk_vuln(3, "critical"),
        _mk_vuln(4, "medium"),
    ]
    stats = ScanStatistics(scan_duration=1.23, total_requests_sent=10)
    cfg = ReportConfig(
        output_dir=str(tmp_path),
        formats=[ReportFormat.HTML],
        min_severity="high",
        max_vulnerabilities=2,
    )
    gen = ReportGenerator(cfg)
    files = gen.generate_report(vulns, stats, {"url": "https://t"})
    html_path = Path(files[ReportFormat.HTML])
    content = html_path.read_text(encoding="utf-8")

    # Only 2 items after filters and limit
    assert 'stat-value">2</div>' in content
    # Lower-than-min should not appear
    assert "LOW" not in content
    assert content.count('class="vulnerability ') == 2


def test_json_template_respects_filters_and_empty(tmp_path: Path):
    vulns = [
        _mk_vuln(1, "low"),
        _mk_vuln(2, "medium"),
        _mk_vuln(3, "high"),
    ]
    stats = ScanStatistics(scan_duration=2.0, total_requests_sent=5)
    cfg = ReportConfig(
        output_dir=str(tmp_path),
        formats=[ReportFormat.JSON],
        min_severity="high",
        max_vulnerabilities=1,
    )
    gen = ReportGenerator(cfg)
    files = gen.generate_report(vulns, stats, {"url": "https://t"})
    json_path = Path(files[ReportFormat.JSON])
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["summary"]["total_vulnerabilities"] == 1
    assert len(data["vulnerabilities"]) == 1
    assert all(
        v["severity"].lower() in ("high", "critical") for v in data["vulnerabilities"]
    )

    # Empty case: raise min_severity to critical when none are critical
    cfg2 = ReportConfig(
        output_dir=str(tmp_path),
        formats=[ReportFormat.JSON],
        min_severity="critical",
        max_vulnerabilities=5,
    )
    gen2 = ReportGenerator(cfg2)
    files2 = gen2.generate_report(vulns, stats, {"url": "https://t"})
    data2 = json.loads(Path(files2[ReportFormat.JSON]).read_text(encoding="utf-8"))
    assert data2["summary"]["total_vulnerabilities"] == 0
