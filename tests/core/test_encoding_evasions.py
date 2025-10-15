#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - EncodingEvasions
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:38:30 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import random
from brsxss.core.encoding_evasions import EncodingEvasions


def test_encoding_evasions_outputs(monkeypatch):
    ev = EncodingEvasions()
    base = "<script>alert(1)</script>"

    # Make randomness deterministic
    monkeypatch.setattr(random, "random", lambda: 0.0)
    monkeypatch.setattr(random, "choice", lambda seq: seq[0])

    u = ev.apply_unicode_encoding(base)
    h = ev.apply_html_entity_encoding(base)
    ue = ev.apply_url_encoding(base)
    mix = ev.apply_mixed_encoding(base)
    ws = ev.apply_whitespace_manipulation(base)
    many = ev.generate_encoded_payloads(base)

    assert isinstance(u, str) and isinstance(h, str) and isinstance(ue, str)
    assert isinstance(mix, str) and isinstance(ws, str)
    assert len(many) >= 3
    assert any(x in many[-3] for x in ["\\x3c", "\\u003c", "\\074"])  # hex/unicode/oct


