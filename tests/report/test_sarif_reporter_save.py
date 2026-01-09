#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - SARIFReporter save_sarif
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:20:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import json
from pathlib import Path

from brsxss.report.sarif_reporter import SARIFReporter
from brsxss.report.data_models import VulnerabilityData


def test_save_sarif_writes_file(tmp_path: Path):
    vulns = [
        VulnerabilityData(
            id="x",
            title="x",
            description="d" * 60,
            severity="high",
            confidence=0.9,
            url="https://a/b",
            parameter="q",
            payload="<p>",
            context="html_content",
        )
    ]
    reporter = SARIFReporter()
    out = tmp_path / "r.sarif"
    reporter.save_sarif(vulns, {"targets_scanned": 1}, str(out))
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) >= 1
