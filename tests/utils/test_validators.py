#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - utils.validators
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:36:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.utils.validators import URLValidator


def test_urlvalidator_validate_url_basic_and_warnings():
    r1 = URLValidator.validate_url("example.com/path")
    assert r1.valid is True
    assert r1.normalized_value.startswith("http://example.com")
    assert any("Added default HTTP protocol" in w for w in r1.warnings)

    r2 = URLValidator.validate_url("https://127.0.0.1:8080/")
    assert r2.valid is True
    assert any("Localhost URL detected" in w for w in r2.warnings)

    r3 = URLValidator.validate_url("")
    assert r3.valid is False
    assert any("URL cannot be empty" in e for e in r3.errors)
