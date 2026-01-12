#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ReportGenerator more branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 01:22:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path
import json

from brsxss.report.report_generator import ReportGenerator
from brsxss.report.report_types import ReportConfig, ReportFormat
from brsxss.report.data_models import VulnerabilityData, ScanStatistics


def _vuln(
    id_: str, title: str, desc: str, sev: str, url: str = "https://t"
) -> VulnerabilityData:
    # v4.0.0-beta.2: Add evidence_response to make findings confirmed
    return VulnerabilityData(
        id=id_,
        title=title,
        description=desc,
        severity=sev,
        confidence=0.7,
        url=url,
        parameter="q",
        payload="<poc>",
        context="html_content",
        evidence_response="Payload reflected in response body",
    )


def test_prepare_report_data_kb_merge_preserve_fields(tmp_path, monkeypatch):
    cfg = ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.JSON])
    gen = ReportGenerator(cfg)
    # Patch KB to control details
    import brsxss.report.report_generator as rg

    monkeypatch.setattr(
        rg,
        "get_vulnerability_details",
        lambda c: {
            "title": "KB Title",
            "description": "KB Description",
            "attack_vector": "KB AV",
            "remediation": "KB Fix",
        },
    )
    # Provide user title but empty description -> expect title preserved, description from KB
    vulns = [_vuln("1", "User Title", "", "high")]
    stats = ScanStatistics(vulnerabilities_found=1)
    out = gen.generate_report(vulns, stats, {"url": "https://x"})
    data = json.loads(Path(out[ReportFormat.JSON]).read_text(encoding="utf-8"))
    assert data["vulnerabilities"][0]["title"] == "User Title"
    assert data["vulnerabilities"][0]["description"] == "KB Description"


def test_generate_single_format_sarif_calls_reporter_and_writes_file(
    tmp_path, monkeypatch
):
    cfg = ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.SARIF])
    saved = {}

    class DummyReporter:
        def save_sarif(self, vulns, scan_info, path):
            # Record inputs and create a minimal file to simulate success
            saved["vulns_len"] = len(vulns)
            saved["scan_info_keys"] = sorted(list((scan_info or {}).keys()))
            p = Path(path)
            p.write_text(json.dumps({"runs": []}), encoding="utf-8")

    import brsxss.report.report_generator as rg

    monkeypatch.setattr(rg, "SARIFReporter", lambda: DummyReporter())
    gen = ReportGenerator(cfg)

    vulns = [_vuln("1", "T", "D", "low")]
    stats = ScanStatistics(total_parameters_tested=1)
    out = gen.generate_report(vulns, stats, {"url": "https://x"})
    sarif_path = Path(out[ReportFormat.SARIF])
    assert sarif_path.exists()
    assert saved.get("vulns_len") == 1
    # Ensure expected scan_info keys are provided by generator
    assert all(
        k in saved.get("scan_info_keys", [])
        for k in [
            "command_line",
            "duration",
            "end_time",
            "machine",
            "start_time",
            "targets_scanned",
        ]
    )


def test_get_top_vulnerable_urls_and_generator_stats(tmp_path):
    cfg = ReportConfig(output_dir=str(tmp_path), formats=[ReportFormat.JSON])
    gen = ReportGenerator(cfg)
    vulns = [
        _vuln("1", "t", "d", "low", url="https://a"),
        _vuln("2", "t", "d", "low", url="https://a"),
        _vuln("3", "t", "d", "low", url="https://b"),
    ]
    top = gen._get_top_vulnerable_urls(vulns)
    assert top[0][0] == "https://a" and top[0][1] == 2

    stats = gen.get_generator_stats()
    assert stats["output_directory"] == str(tmp_path)
    assert (
        "html" in stats["supported_formats"] and "json" in stats["configured_formats"]
    )
