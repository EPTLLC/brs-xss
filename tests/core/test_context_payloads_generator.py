#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ContextPayloadGenerator
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 15:00:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.context_payloads import ContextPayloadGenerator


def test_context_payloads_cover_key_contexts():
    g = ContextPayloadGenerator()
    html = g.get_context_payloads("html_content", {})
    assert any("<script>" in p for p in html)

    attr = g.get_context_payloads("html_attribute", {"quote_char": '"', "attribute_name": "src"})
    assert any('" onerror=' in p for p in attr)
    assert any('javascript:alert(1)' in p for p in attr)

    js = g.get_context_payloads("javascript", {})
    assert any(p.startswith("alert(") for p in js)

    jsstr = g.get_context_payloads("js_string", {"quote_char": '"'})
    assert any(p.startswith('";') for p in jsstr)

    css = g.get_context_payloads("css_style", {})
    assert any('expression(' in p or p.startswith('url(') for p in css)

    url = g.get_context_payloads("url_parameter", {})
    assert any(p.startswith('javascript:') for p in url)

    unk = g.get_context_payloads("unknown", {})
    assert len(unk) > 0


