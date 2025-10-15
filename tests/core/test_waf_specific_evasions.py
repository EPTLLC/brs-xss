#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - WAFSpecificEvasions
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:49:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.waf_specific_evasions import WAFSpecificEvasions


def test_apply_waf_specific_evasions_cloudflare():
    base = "<script>alert(1)</script>"
    we = WAFSpecificEvasions()
    out = we.apply_waf_specific_evasions(base, "cloudflare")
    assert out and isinstance(out, list)
    assert any("scr<>ipt" in v or "\x72" in v or "/**/" in v for v in out)


def test_detect_waf_and_suggest_bypasses_signals():
    we = WAFSpecificEvasions()
    headers = {"CF-RAY": "x", "X-Other": "y"}
    body = "... modsecurity and imperva present ..."
    suggestions = we.detect_waf_and_suggest_bypasses(headers, body)
    assert suggestions
    assert any("scr<>ipt" in s or "mod" in body.lower() for s in suggestions)


