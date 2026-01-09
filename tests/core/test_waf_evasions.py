#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - WAFEvasions
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:26:30 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.waf_evasions import WAFEvasions
from brsxss.waf.models import WAF, WAFBrand


def test_generate_waf_specific_payloads_basic():
    base = "<script>alert(1)</script>"
    we = WAFEvasions()
    wafs = [
        WAF(WAFBrand.CLOUDFLARE, "cf"),
        WAF(WAFBrand.AWS_WAF, "aws"),
        WAF(WAFBrand.INCAPSULA, "incapsula"),
        WAF(WAFBrand.MODSECURITY, "modsec"),
        WAF(WAFBrand.AKAMAI, "akamai"),
        WAF(WAFBrand.BARRACUDA, "barracuda"),
    ]
    out = we.generate_waf_specific_payloads(base, wafs)
    assert out
    texts = [g.payload for g in out]
    assert any("/**/" in t or "%28" in t or "ScRiPt" in t for t in texts)
