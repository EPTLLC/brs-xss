#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - Templates empty branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 19:15:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path

from brsxss.report.report_generator import ReportGenerator
from brsxss.report.report_types import ReportConfig, ReportFormat
from brsxss.report.data_models import ScanStatistics


def test_html_and_junit_when_no_vulnerabilities(tmp_path: Path):
    stats = ScanStatistics(scan_duration=0.0)
    cfg = ReportConfig(
        output_dir=str(tmp_path), formats=[ReportFormat.HTML, ReportFormat.JUNIT]
    )
    gen = ReportGenerator(cfg)
    files = gen.generate_report([], stats, {"url": "https://t"})
    html = Path(files[ReportFormat.HTML]).read_text(encoding="utf-8")
    junit = Path(files[ReportFormat.JUNIT]).read_text(encoding="utf-8")
    assert "Total Vulnerabilities" in html and ">0<" in html
    assert '<testcase name="XSS Security Test"' in junit
