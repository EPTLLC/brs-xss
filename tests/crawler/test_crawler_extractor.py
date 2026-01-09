#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - Crawler Engine and FormExtractor
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:56:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest

from brsxss.crawler.engine import CrawlerEngine, CrawlConfig
from brsxss.crawler.form_extractor import FormExtractor


@pytest.mark.asyncio
async def test_crawler_basic_parsing(monkeypatch):
    html = """
    <html><body>
      <a href="/next?page=2">Next</a>
      <form action="/submit" method="post">
        <input type="text" name="q" value="test" />
        <textarea name="msg">hi</textarea>
      </form>
    </body></html>
    """

    class MResp:
        status_code = 200
        text = html
        headers = {"content-type": "text/html"}

    class MClient:
        async def get(self, url, timeout=10, headers=None):
            return MResp()

        async def close(self):
            return None

    cfg = CrawlConfig(
        max_depth=0,
        max_urls=5,
        max_concurrent=1,
        extract_links=True,
        extract_forms=True,
    )
    eng = CrawlerEngine(config=cfg, http_client=MClient())
    res = await eng.crawl("https://example.com/")
    assert len(res) == 1
    r = res[0]
    assert r.status_code == 200
    assert len(r.extracted_forms) == 1
    assert r.extracted_forms[0].action.endswith("/submit")


def test_form_extractor_regex_path():
    fx = FormExtractor()
    fx.use_beautifulsoup = False
    html = '<form action="/a" method="get"><input name="n" value="v"></form>'
    forms = fx.extract_forms(html, "https://ex.com/path")
    assert len(forms) == 1
    assert forms[0].action.endswith("/a")
    assert any(f.name == "n" for f in forms[0].fields)
