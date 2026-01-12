#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - PolyglotGenerator
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:48:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.detect.xss.reflected.polyglot_generator import PolyglotGenerator


def test_polyglot_generator_sets():
    pg = PolyglotGenerator()
    base = pg.generate_polyglot_payloads()
    assert isinstance(base, list) and len(base) >= 5
    assert any("svg" in p.lower() or "script" in p.lower() for p in base)

    ctx = pg.generate_context_specific_polyglots("html")
    assert all(isinstance(p, str) for p in ctx) and ctx
    assert any("<script>" in p for p in ctx)

    byp = pg.generate_filter_bypass_polyglots()
    assert any("&#" in p or "\\u" in p for p in byp)
