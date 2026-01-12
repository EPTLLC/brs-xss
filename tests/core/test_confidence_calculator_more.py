#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ConfidenceCalculator more branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:25:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from types import SimpleNamespace
from brsxss.detect.xss.reflected.confidence_calculator import ConfidenceCalculator


def test_confidence_branches_reflection_and_payload():
    cc = ConfidenceCalculator()
    # No reflection
    c0 = cc.calculate_confidence(None, {"context_type": "unknown"}, "x")
    assert 0 <= c0 <= 1

    # Reflection object without type
    refl_min = SimpleNamespace(
        reflection_type=None, completeness=0.0, characters_preserved=0.0
    )
    c1 = cc.calculate_confidence(refl_min, {"context_type": "html_content"}, "<s>")
    assert c1 > c0

    # Reflection with known type and bonuses
    refl = SimpleNamespace(
        reflection_type=SimpleNamespace(value="partial"),
        completeness=1.0,
        characters_preserved=1.0,
    )
    ctx = {
        "context_type": "html_attribute",
        "tag_name": "a",
        "attribute_name": "href",
        "filters_detected": ["html"],
        "encoding_detected": "html",
    }
    payload = "<script>alert(1)</script> onerror= eval(document.domain)"
    c2 = cc.calculate_confidence(refl, ctx, payload)
    assert c2 > c1 and 0 <= c2 <= 1
