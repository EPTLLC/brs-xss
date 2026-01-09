#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - EvasionTechniques
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:25:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import random
from brsxss.core.evasion_techniques import EvasionTechniques


def test_case_and_url_html_unicode_are_deterministic(monkeypatch):
    et = EvasionTechniques()
    base = "<script>alert(1)</script>"
    # Freeze randomness to make mixed/random branches stable
    monkeypatch.setattr(random, "choice", lambda seq: seq[0])

    case_vars = et.apply_case_variations(base)
    assert base.upper() in case_vars
    assert base.lower() in case_vars
    assert any("ScRiPt" in v or "ALERT" in v for v in case_vars)

    url_vars = et.apply_url_encoding(base)
    assert "%3C" in url_vars[0] or "%3c" in url_vars[0]
    assert "%253C" not in url_vars[0]  # not double yet
    assert any("%3c" in v.lower() or "%3e" in v.lower() for v in url_vars)

    html_vars = et.apply_html_entity_encoding(base)
    # Accept entity encodings even if '&' itself becomes encoded (e.g., '&amp;lt;')
    assert any(
        ("amp;lt" in v.lower()) or ("&#60;" in v) or ("#x3c;" in v.lower())
        for v in html_vars
    )

    uni_vars = et.apply_unicode_escaping(base)
    assert any("\\u003c" in v or "\\x3c" in v for v in uni_vars)


def test_comment_whitespace_mixed_encoding(monkeypatch):
    et = EvasionTechniques()
    base = "<script>alert(1)</script>"
    monkeypatch.setattr(random, "choice", lambda seq: seq[0])

    comment_vars = et.apply_comment_insertions(base)
    assert any("/**/" in v or "<!--" in v for v in comment_vars)

    ws_vars = et.apply_whitespace_variations(base)
    assert any("\t" in v or "\n" in v for v in ws_vars)
    assert base.replace(" ", "") in ws_vars

    mixed_vars = et.apply_mixed_encoding(base)
    assert any("%3d" in v or "&lt;" in v for v in mixed_vars)
