#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - AdvancedWAFEvasion
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:40:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import random
from brsxss.core.advanced_waf_evasion import AdvancedWAFEvasion


def test_generate_evasion_variations_deterministic(monkeypatch):
    adv = AdvancedWAFEvasion()
    base = "<script>alert(1)</script>"

    # Make random choices deterministic to avoid flaky tests
    monkeypatch.setattr(random, "random", lambda: 0.0)
    monkeypatch.setattr(random, "randint", lambda a, b: a)
    monkeypatch.setattr(random, "sample", lambda seq, k: list(seq)[:k])
    monkeypatch.setattr(random, "choice", lambda seq: seq[0])

    out = adv.generate_evasion_variations(base, num_variations=5)
    assert out
    assert all(isinstance(x, str) for x in out)
    assert len(out) <= 5

    full = adv.get_comprehensive_bypasses(base, waf_type="cloudflare")
    assert full
    assert any(
        "eval(atob(" in x or "String.fromCharCode" in x or "polyglot" in x.lower()
        for x in full
    )
