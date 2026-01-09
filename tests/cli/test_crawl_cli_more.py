#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - CLI crawl command more
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 00:55:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path
from typer.testing import CliRunner
from cli.commands.crawl import app


def test_crawl_cli_saves_output_json(tmp_path, monkeypatch):
    runner = CliRunner()
    # Mock URLValidator
    from brsxss.utils import validators

    class V:
        valid = True
        normalized_value = "http://example.com"
        errors = []

    monkeypatch.setattr(validators.URLValidator, "validate_url", lambda url: V)

    # Mock CrawlerEngine
    class R:
        discovered_urls = [type("U", (), {"url": "http://example.com/a"})()]
        extracted_forms = []
        potential_parameters = {"q"}

    class CE:
        def __init__(self, *a, **k):
            pass

        async def crawl(self, url):
            return [R()]

    import brsxss.crawler.engine as eng

    monkeypatch.setattr(eng, "CrawlerEngine", CE)
    out = tmp_path / "res"
    result = runner.invoke(app, ["http://example.com", "--output", str(out)])
    assert result.exit_code == 0
    # File should be saved with .json suffix
    assert Path(str(out) + ".json").exists()


def test_crawl_cli_no_output_does_not_save(tmp_path, monkeypatch):
    runner = CliRunner()
    # Mock URLValidator
    from brsxss.utils import validators

    class V:
        valid = True
        normalized_value = "http://example.com"
        errors = []

    monkeypatch.setattr(validators.URLValidator, "validate_url", lambda url: V)

    # Mock CrawlerEngine minimal
    class R:
        discovered_urls = []
        extracted_forms = []
        potential_parameters = set()

    class CE:
        def __init__(self, *a, **k):
            pass

        async def crawl(self, url):
            return [R()]

    import brsxss.crawler.engine as eng

    monkeypatch.setattr(eng, "CrawlerEngine", CE)
    result = runner.invoke(app, ["http://example.com"])
    assert result.exit_code == 0
    # Ensure tmp_path remains empty
    assert list(tmp_path.iterdir()) == []
