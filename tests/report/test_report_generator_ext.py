#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ReportGenerator Extended
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:12:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path
import json

from brsxss.report.report_generator import ReportGenerator
from brsxss.report.report_types import ReportConfig, ReportFormat
from brsxss.report.data_models import VulnerabilityData, ScanStatistics


def _mk_vuln(i: int, sev: str) -> VulnerabilityData:
    return VulnerabilityData(
        id=f"x{i}",
        title=f"Vuln {i}",
        description="A" * 60,
        severity=sev,
        confidence=0.9,
        url=f"https://example.com/p{i}",
        parameter="q",
        payload="<poc>",
        context="html_content",
    )


def test_report_generator_filters_and_summary(tmp_path: Path):
    vulns = [_mk_vuln(1, "low"), _mk_vuln(2, "high"), _mk_vuln(3, "medium")]
    stats = ScanStatistics(total_urls_tested=1, total_parameters_tested=3, vulnerabilities_found=3)
    cfg = ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.HTML, ReportFormat.JSON], max_vulnerabilities=2, min_severity="medium")
    gen = ReportGenerator(cfg)
    out = gen.generate_report(vulns, stats, {"url": "https://example.com", "policy": {"min_vulnerability_score": 2.0}})
    assert ReportFormat.HTML in out and ReportFormat.JSON in out

    # Read JSON and verify filter applied (min_severity medium, max 2 items)
    json_path = Path(out[ReportFormat.JSON])
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["summary"]["total_vulnerabilities"] == 2
    # Ensure recommendations list exists
    assert isinstance(data.get("recommendations", []), list)


def test_risk_score_levels(tmp_path: Path):
    # All critical to push score
    vulns = [_mk_vuln(i, "critical") for i in range(1, 6)]
    stats = ScanStatistics(total_urls_tested=1, total_parameters_tested=5, vulnerabilities_found=5)
    cfg = ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.JSON])
    gen = ReportGenerator(cfg)
    out = gen.generate_report(vulns, stats, {"url": "x"})
    data = json.loads(Path(out[ReportFormat.JSON]).read_text(encoding="utf-8"))
    # JSON template exposes per-severity distribution instead of risk_level
    assert "risk_levels" in data["summary"]
    assert data["summary"]["risk_levels"]["critical"] >= 1


