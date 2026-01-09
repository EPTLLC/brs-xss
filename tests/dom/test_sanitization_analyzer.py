#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - SanitizationAnalyzer branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 04:08:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.dom.sanitization_analyzer import SanitizationAnalyzer


def test_sanitization_detects_and_flags_bypass_regex():
    code = "value = input.replace('/script/gi', '')"  # matches current pattern set
    has_san, bypass, funcs = SanitizationAnalyzer.analyze_sanitization(code)
    assert has_san and bypass and "replace" in [f.lower() for f in funcs]


def test_sanitization_detects_incomplete_and_safe_cases():
    safe_code = "output = DOMPurify.sanitize(input); element.textContent = output;"
    has_san, bypass, funcs = SanitizationAnalyzer.analyze_sanitization(safe_code)
    assert has_san and not bypass and any("sanitize" in f.lower() for f in funcs)

    incomplete = "x = s.replace('<', '')"  # incomplete, no global flag markers
    has_san2, bypass2, _ = SanitizationAnalyzer.analyze_sanitization(incomplete)
    assert has_san2 and bypass2
