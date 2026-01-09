#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - CLI fuzz command more
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 00:56:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path
from typer.testing import CliRunner
from cli.commands.fuzz import app as fuzz_app


def test_fuzz_cli_saves_output_json(tmp_path, monkeypatch):
    runner = CliRunner()
    # Mock URLValidator
    from brsxss.utils import validators

    class V:
        valid = True
        normalized_value = "http://example.com"
        errors = []

    monkeypatch.setattr(validators.URLValidator, "validate_url", lambda url: V)

    # Mock WAF detector to return one item
    class W:
        def __init__(self):
            self.waf_type = type("WT", (), {"value": "cloudflare"})
            self.confidence = 0.5
            self.evidence = []

    class Det:
        async def detect_waf(self, url):
            return [W()]

    import brsxss.waf.detector as detm

    monkeypatch.setattr(detm, "WAFDetector", lambda: Det())
    out = tmp_path / "fz"
    result = runner.invoke(fuzz_app, ["http://example.com", "--output", str(out)])
    assert result.exit_code == 0
    assert Path(str(out) + ".json").exists()


def test_fuzz_cli_detected_branch(monkeypatch):
    runner = CliRunner()
    # Mock URLValidator
    from brsxss.utils import validators

    class V:
        valid = True
        normalized_value = "http://example.com"
        errors = []

    monkeypatch.setattr(validators.URLValidator, "validate_url", lambda url: V)

    # Mock detector with one detected entry
    class W:
        def __init__(self):
            self.waf_type = type("WT", (), {"value": "modsecurity"})
            self.confidence = 0.8
            self.evidence = []

    class Det:
        async def detect_waf(self, url):
            return [W()]

    import brsxss.waf.detector as detm

    monkeypatch.setattr(detm, "WAFDetector", lambda: Det())
    result = runner.invoke(fuzz_app, ["http://example.com"])
    assert result.exit_code == 0 and "WAF protection detected" in result.stdout
