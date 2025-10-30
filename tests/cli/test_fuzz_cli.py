#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - CLI fuzz command smoke
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 21:15:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from typer.testing import CliRunner
from cli.commands.fuzz import app as fuzz_app


def test_fuzz_cli_invalid_url():
    runner = CliRunner()
    result = runner.invoke(fuzz_app, ["bad url"]) 
    assert result.exit_code != 0 and "Invalid URL" in result.stdout


def test_fuzz_cli_happy_path(monkeypatch):
    runner = CliRunner()
    # Mock URLValidator
    from brsxss.utils import validators
    class V:
        valid = True
        normalized_value = "http://example.com"
        errors = []
    monkeypatch.setattr(validators.URLValidator, "validate_url", lambda url: V)
    # Mock WAF detector and fingerprinter
    class Det:
        async def detect_waf(self, url):
            return []
    class Fing:
        async def fingerprint_waf(self, url):
            class F:
                confidence = 0.0
            return F()
    import brsxss.waf.waf_detector as wd
    import brsxss.waf.waf_fingerprinter as wf
    monkeypatch.setattr(wd, "WAFDetector", lambda: Det())
    monkeypatch.setattr(wf, "WAFFingerprinter", lambda: Fing())
    result = runner.invoke(fuzz_app, ["http://example.com"]) 
    assert result.exit_code == 0 and "Fuzzing completed" in result.stdout


