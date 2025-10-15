#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - validators edge branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:38:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.utils.validators import (
    URLValidator,
    ParameterValidator,
    PayloadValidator,
    ConfigValidator,
)


def test_url_validator_empty_and_invalid_hostname():
    r0 = URLValidator.validate_url("")
    assert not r0.valid and any("cannot be empty" in e for e in r0.errors)
    r1 = URLValidator.validate_url("http://exa mple.com")
    assert not r1.valid and any("Invalid hostname" in e for e in r1.errors)


def test_parameter_analyze_types_and_patterns():
    a1 = ParameterValidator.analyze_parameter_value("2025-01-30")
    assert "date" in a1["type_hints"]
    a2 = ParameterValidator.analyze_parameter_value("javascript:alert(1)")
    assert "javascript_protocol" in a2["patterns"]
    a3 = ParameterValidator.analyze_parameter_value("<script>alert(1)</script>")
    assert "html_tags" in a3["patterns"] and "javascript_functions" in a3["patterns"]


def test_is_testable_parameter_edges():
    assert not ParameterValidator.is_testable_parameter("fileUpload", "x")
    assert not ParameterValidator.is_testable_parameter("q", "x" * 1001)
    assert not ParameterValidator.is_testable_parameter("value", "12345")
    assert ParameterValidator.is_testable_parameter("id", "12345")
    assert not ParameterValidator.is_testable_parameter("password", "secret")


def test_payload_validator_length_and_unicode_and_patterns():
    long = "x" * 1001
    r1 = PayloadValidator.validate_payload(long)
    assert r1.valid and any("very long" in w for w in r1.warnings)
    huge = "x" * 10001
    r2 = PayloadValidator.validate_payload(huge)
    assert not r2.valid and any("too long" in e for e in r2.errors)
    non_ascii = "тест"
    r3 = PayloadValidator.validate_payload(non_ascii)
    assert r3.valid and any("non-ASCII" in w for w in r3.warnings)
    pat = PayloadValidator.validate_payload("<script>document.cookie=1</script>")
    assert any("dangerous pattern" in w for w in pat.warnings)


def test_config_validator_missing_and_numbers_and_user_agent():
    r = ConfigValidator.validate_scan_config({})
    assert not r.valid and any("Missing required field" in e for e in r.errors)
    r2 = ConfigValidator.validate_scan_config({"target_url": "example.com", "max_concurrent": 0})
    assert not r2.valid and any("between" in e for e in r2.errors)
    r3 = ConfigValidator.validate_scan_config({"target_url": "example.com", "user_agent": "u" * 201})
    assert r3.valid and any("very long" in w for w in r3.warnings)


