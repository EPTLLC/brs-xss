#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - WAF EncodingEngine minimal
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 02:10:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.detect.waf.encoding_engine import EncodingEngine


def test_encoding_engine_core_methods():
    e = EncodingEngine()
    s = "<a>"
    assert e.url_encode(s) == "%3Ca%3E"
    assert (
        e.url_encode(s, double=True).endswith("253C") is False
    )  # double-encoded percent is lowercase hex
    assert (
        e.html_encode("A") == "&#65;"
        and e.html_encode("A", use_hex=True).lower() == "&#x41;"
    )
    assert e.unicode_encode("A") == "\\u0041"
    assert e.hex_encode("A") == "\\x41"
    assert e.base64_encode("AB") == "QUI="
    mixed = e.mixed_encoding("ABCD")
    assert (
        mixed.startswith("%41")
        and "&#66;" in mixed
        and "\\u0043" in mixed
        and mixed.endswith("D")
    )
