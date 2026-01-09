#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ReportGenerator tail branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 19:52:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path

from brsxss.report.report_generator import ReportGenerator
from brsxss.report.report_types import ReportConfig, ReportFormat
from brsxss.report.data_models import VulnerabilityData, ScanStatistics


def _v(id_, sev, vtype):
    return VulnerabilityData(
        id=id_,
        title=f"T{id_}",
        description="D",
        severity=sev,
        confidence=0.5,
        url="https://x",
        parameter="q",
        payload="<p>",
        context="html_content",
        vulnerability_type=vtype,
    )


def test_generate_report_with_unsupported_format_logs_error(tmp_path: Path):
    cfg = ReportConfig(
        output_dir=str(tmp_path), formats=[ReportFormat.HTML, ReportFormat.CSV]
    )
    gen = ReportGenerator(cfg)
    files = gen.generate_report(
        [_v("1", "low", "reflected_xss")],
        ScanStatistics(scan_duration=0.1),
        {"url": "https://x"},
    )
    assert ReportFormat.HTML in files and ReportFormat.CSV not in files
    assert Path(files[ReportFormat.HTML]).exists()


def test_generate_summary_report_file(tmp_path: Path):
    gen = ReportGenerator(
        ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.HTML])
    )
    scan_results = [
        {
            "vulnerabilities": [
                {
                    "url": "https://x",
                    "parameter": "q",
                    "payload": "<p>",
                    "severity": "high",
                    "confidence": 0.8,
                }
            ],
            "target_info": {"url": "https://x"},
        }
    ]
    p = gen.generate_summary_report(scan_results)
    assert Path(p).exists()


def test_risk_level_all_branches():
    gen = ReportGenerator()
    assert gen._get_risk_level(85) == "Critical"
    assert gen._get_risk_level(65) == "High"
    assert gen._get_risk_level(45) == "Medium"
    assert gen._get_risk_level(25) == "Low"
    assert gen._get_risk_level(5) == "Minimal"


def test_generate_recommendations_variants():
    gen = ReportGenerator()
    recs = gen._generate_recommendations(
        [
            _v("1", "high", "reflected_xss"),
            _v("2", "low", "dom_xss"),
            _v("3", "medium", "stored_xss"),
        ]
    )
    # Expect baseline plus additions for dom_xss and stored_xss
    assert any("textContent" in r for r in recs)
    assert any("Avoid using" in r for r in recs)
    assert any("server-side" in r for r in recs)
