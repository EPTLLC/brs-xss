#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - utils.validators (extended)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:40:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path

from brsxss.utils.validators import (
    ParameterValidator,
    PayloadValidator,
    ConfigValidator,
    FileValidator,
    InputSanitizer,
)


def test_parameter_validator_name_and_value_analysis():
    # Name validation
    ok = ParameterValidator.validate_parameter_name("param_1")
    assert ok.valid is True and ok.errors == []

    unusual = ParameterValidator.validate_parameter_name("1param")
    assert unusual.valid is True
    assert any("unusual characters" in w for w in unusual.warnings)

    dangerous = ParameterValidator.validate_parameter_name("na<me>")
    assert dangerous.valid is False
    assert any("dangerous characters" in e for e in dangerous.errors)

    long_name = "a" * 101
    ln = ParameterValidator.validate_parameter_name(long_name)
    assert any("very long" in w for w in ln.warnings)

    sensitive = ParameterValidator.validate_parameter_name("password")
    assert any("sensitive data" in w for w in sensitive.warnings)

    # Value analysis
    v = ParameterValidator.analyze_parameter_value("<script>alert(1)</script>")
    assert "html_tags" in v["patterns"]
    assert "javascript_functions" in v["patterns"]
    assert "dangerous_tags" in v["patterns"]
    assert "<" in v["special_chars"] and ">" in v["special_chars"]

    v2 = ParameterValidator.analyze_parameter_value("user@example.com")
    assert "email" in v2["type_hints"]

    v3 = ParameterValidator.analyze_parameter_value("https://ex.com/?q=%3Cscript%3E")
    assert "url" in v3["type_hints"] and "url_encoded" in v3["encoding_detected"]


def test_is_testable_parameter_matrix():
    assert ParameterValidator.is_testable_parameter("file", "abc") is False
    assert ParameterValidator.is_testable_parameter("token", "abc") is False
    assert ParameterValidator.is_testable_parameter("foo", "1234") is False
    assert ParameterValidator.is_testable_parameter("id", "1234") is True
    long_val = "x" * 1001
    assert ParameterValidator.is_testable_parameter("q", long_val) is False


def test_payload_validator_and_sanitizer():
    empty = PayloadValidator.validate_payload("")
    assert empty.valid is False and any("cannot be empty" in e for e in empty.errors)

    long = PayloadValidator.validate_payload("x" * 1500)
    assert long.valid is True and any("very long" in w for w in long.warnings)

    patterns = PayloadValidator.validate_payload("<script>document.cookie;eval(1)</script>")
    assert patterns.valid is True and any("document\\.cookie" in w for w in patterns.warnings)

    non_ascii = PayloadValidator.validate_payload("алерт")
    assert any("non-ASCII" in w for w in non_ascii.warnings)

    sanitized = PayloadValidator.sanitize_payload_for_logging("<script>alert(1)</script><img src=x>")
    # Final sanitizer replaces angle brackets; ensure tokens remain present
    assert "removed" in sanitized and "img" in sanitized


def test_config_and_file_validator(tmp_path):
    cfg_ok = {
        "target_url": "https://example.com",
        "max_depth": 3,
        "max_urls": 100,
        "max_concurrent": 10,
        "timeout": 15,
        "user_agent": "UA"
    }
    res_ok = ConfigValidator.validate_scan_config(cfg_ok)
    assert res_ok.valid is True and res_ok.errors == []

    cfg_bad = {"target_url": "ht!tp://bad[host]", "max_depth": 0, "timeout": 500}
    res_bad = ConfigValidator.validate_scan_config(cfg_bad)
    assert res_bad.valid is False
    assert any("Target URL" in e for e in res_bad.errors)
    assert any("max_depth" in e for e in res_bad.errors)
    assert any("timeout" in e for e in res_bad.errors)

    ua = {"target_url": "http://a", "user_agent": "x" * 300}
    res_ua = ConfigValidator.validate_scan_config(ua)
    assert any("User agent is very long" in w for w in res_ua.warnings)

    # FileValidator
    out = tmp_path / "newdir" / "out.sarif"
    vr = FileValidator.validate_output_path(str(out))
    assert vr.valid is True
    assert Path(vr.normalized_value).name == "out.sarif"
    # Parent should exist now
    assert (tmp_path / "newdir").exists()


def test_input_sanitizer():
    assert InputSanitizer.sanitize_for_shell("rm -rf /; cat /etc/passwd") == "rm -rf / cat /etc/passwd"
    assert InputSanitizer.sanitize_for_filename("bad:name*?|<file>.txt").startswith("bad_name")
    disp = InputSanitizer.sanitize_for_display("<b> & \" '")
    assert "&lt;b&gt;" in disp and "&amp;" in disp and "&quot;" in disp and "&#x27;" in disp


