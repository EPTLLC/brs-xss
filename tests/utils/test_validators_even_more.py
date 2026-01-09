#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - validators additional branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 19:33:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.utils.validators import (
    URLValidator,
    ParameterValidator,
    ConfigValidator,
    FileValidator,
)


def test_url_validator_private_localhost_and_scheme():
    r1 = URLValidator.validate_url("localhost")
    assert r1.valid and any("Localhost" in w for w in r1.warnings)
    r2 = URLValidator.validate_url("192.168.0.1")
    assert r2.valid and any("Private IP" in w for w in r2.warnings)
    r3 = URLValidator.validate_url("ftp://example.com")
    # Current behavior: prepend http:// when scheme is not http/https
    assert r3.valid and r3.normalized_value.startswith("http://ftp://")


def test_parameter_validator_sensitive_and_long():
    p = ParameterValidator.validate_parameter_name("userPassword_long_long_long")
    assert p.valid and any("sensitive" in w for w in p.warnings)


def test_config_validator_ranges_and_user_agent():
    cfg = {
        "target_url": "example.com",
        "max_depth": 0,
        "timeout": 9999,
        "user_agent": "x" * 300,
    }
    r = ConfigValidator.validate_scan_config(cfg)
    assert (
        not r.valid
        and any("between" in e for e in r.errors)
        and any("User agent" in w for w in r.warnings)
    )


def test_file_validator_extension_and_overwrite(tmp_path):
    f = tmp_path / "out.unknown"
    f.write_text("x", encoding="utf-8")
    r = FileValidator.validate_output_path(str(f))
    assert (
        r.valid
        and any("Unusual" in w for w in r.warnings)
        and any("already exists" in w for w in r.warnings)
    )
