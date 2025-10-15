#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ReportGenerator empty data branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 19:20:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path

from brsxss.report.report_generator import ReportGenerator
from brsxss.report.report_types import ReportConfig, ReportFormat
from brsxss.report.data_models import ScanStatistics


def test_generate_with_no_vulns_minimal_target_info(tmp_path: Path):
    cfg = ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.HTML, ReportFormat.JSON])
    gen = ReportGenerator(cfg)
    files = gen.generate_report([], ScanStatistics(scan_duration=0.0), target_info={})
    assert Path(files[ReportFormat.HTML]).exists()
    assert Path(files[ReportFormat.JSON]).exists()


