#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - WAFSpecificEvasion minimal
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 03:45:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.waf.waf_specific_evasion import WAFSpecificEvasion


def test_cloudflare_evasion_basic():
    payload = "<script>alert(1)</script>"
    out = WAFSpecificEvasion.cloudflare_evasion(payload)
    # Expect several variants including data URI
    assert any("<script/x>" in v or "ale" in v for v in out)
    assert any(v.startswith("data:text/html;base64,") for v in out)


def test_aws_waf_evasion_and_pollution():
    payload = "script=x"
    out = WAFSpecificEvasion.aws_waf_evasion(payload)
    assert any("scr" in v and "\x69pt" in v for v in out) or any("\x3c" in v for v in out)
    assert any("dummy&script=x" in v for v in out)


def test_incapsula_and_modsecurity_variants():
    payload = "<script onload=1>alert(1)</script>"
    inc = WAFSpecificEvasion.incapsula_evasion(payload)
    mod = WAFSpecificEvasion.modsecurity_evasion(payload)
    assert any('window["ale"+"rt"]' in v or 'charset="utf-8"' in v for v in inc)
    assert any("\t" in v or "ScRiPt" in v or "=\x00" in v for v in mod)
