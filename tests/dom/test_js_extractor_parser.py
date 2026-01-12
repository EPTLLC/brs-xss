#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - JS extractor and parser smoke
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 03:55:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.detect.xss.dom.javascript_extractor import JavaScriptExtractor
from brsxss.detect.xss.dom.javascript_parser import JavaScriptParser


def test_extract_from_html_variants():
    html = """
    <html>
      <body onload="alert(1)">
        <a href="javascript:alert(2)">x</a>
        <script>console.log('x')</script>
      </body>
    </html>
    """
    blocks = JavaScriptExtractor.extract_from_html(html)
    kinds = {ctx for _, ctx in blocks}
    assert {"inline_script", "event_handler", "javascript_url"}.issubset(kinds)


def test_parser_stats_on_minimal_code():
    js = "document.body.innerHTML = location.hash;"
    p = JavaScriptParser()
    p.parse_javascript(js)
    # Smoke: parser returns nodes or empty, but stats should be a dict
    assert isinstance(p.get_parsing_stats(), dict)
