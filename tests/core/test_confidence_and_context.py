#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - Confidence and Context Calculators
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:09:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.confidence_calculator import ConfidenceCalculator
from brsxss.core.context_calculator import ContextCalculator


class DummyRR:
    def __init__(self):
        self.reflection_type = type("T", (), {"value": "exact"})()
        self.completeness = 1.0
        self.characters_preserved = 1.0


def test_confidence_and_context_scores():
    cc = ConfidenceCalculator()
    ctxc = ContextCalculator()
    rr = DummyRR()
    ctx = {"context_type": "html_content", "specific_context": "html_content"}
    c = cc.calculate_confidence(rr, ctx, "<script>alert(1)</script>")
    assert 0.0 <= c <= 1.0
    cs = ctxc.calculate_context_score(ctx)
    assert 0.5 <= cs <= 1.0


