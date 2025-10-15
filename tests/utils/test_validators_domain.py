#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - validators domain helpers
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:46:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.utils.validators import URLValidator


def test_extract_and_same_domain():
    d = URLValidator.extract_domain("https://Sub.Example.com:8080/a")
    assert d == "sub.example.com"
    assert URLValidator.is_same_domain("https://a.b.com/x", "http://a.b.com/y") is True
    assert URLValidator.is_same_domain("https://a.com", "https://b.com") is False


