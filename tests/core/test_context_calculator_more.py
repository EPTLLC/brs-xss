#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ContextCalculator more
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:50:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.context_calculator import ContextCalculator


def test_specific_context_override():
    cc = ContextCalculator()
    s1 = cc.calculate_context_score({"context_type": "unknown"})
    s2 = cc.calculate_context_score({"context_type": "html_content"})
    s3 = cc.calculate_context_score(
        {"context_type": "url_parameter", "specific_context": "javascript"}
    )
    assert s2 > s1 and s3 >= s2
