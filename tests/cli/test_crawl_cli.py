#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - CLI crawl command smoke
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:22:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from typer.testing import CliRunner
from cli.commands.crawl import app


def test_crawl_cli_invalid_url():
    runner = CliRunner()
    result = runner.invoke(app, ["not a url"])
    assert result.exit_code != 0
    assert "Invalid URL" in result.stdout


def test_crawl_cli_happy_path(monkeypatch):
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

    import brsxss.detect.crawler.engine as eng

    monkeypatch.setattr(eng, "CrawlerEngine", CE)
    result = runner.invoke(app, ["http://example.com", "--output", "out.json"])
    assert result.exit_code == 0 and "Crawl successful" in result.stdout
