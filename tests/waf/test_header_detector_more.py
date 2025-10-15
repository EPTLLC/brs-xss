#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - WAF HeaderDetector (more)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 00:05:00 UTC
Status: Created
Telegram: https://t.me/easyprotech
"""

from brsxss.waf.header_detector import HeaderDetector
from brsxss.waf.waf_types import WAFType


def test_various_header_signatures_and_version():
    d = HeaderDetector()
    # AWS WAF by request id
    info_aws = d.detect_from_headers({"X-Amzn-RequestId": "test"})
    assert info_aws and info_aws.waf_type == WAFType.AWS_WAF
    # Akamai
    info_ak = d.detect_from_headers({"Akamai-Ghost-IP": "1.2.3.4"})
    assert info_ak and info_ak.waf_type == WAFType.AKAMAI
    # Barracuda
    info_ba = d.detect_from_headers({"X-Barracuda": "on"})
    assert info_ba and info_ba.waf_type == WAFType.BARRACUDA
    # F5 BIG-IP (case-insensitive key)
    info_f5 = d.detect_from_headers({"BIGipServer": "pool=app"})
    assert info_f5 and info_f5.waf_type == WAFType.F5_BIG_IP
    # ModSecurity with version extraction through header signature
    info_mod = d.detect_from_headers({"X-Mod-Security-Message": "mod_security v3.2"})
    assert info_mod and info_mod.waf_type == WAFType.MODSECURITY and info_mod.version == "3.2"


def test_server_header_cloudflare_and_value_based_incapsula_branch():
    d = HeaderDetector()
    # Server header path -> cloudflare
    info_cf = d.detect_from_headers({"Server": "cloudflare"})
    assert info_cf and info_cf.waf_type == WAFType.CLOUDFLARE
    # Value-based Incapsula branch in internal checker (bypass header-name signature)
    inc = d._check_header_values({"x-protected-by": "incapsula"})
    assert inc and inc.waf_type == WAFType.INCAPSULA


def test_analyze_header_anomalies_missing_suspicious_and_security_count():
    d = HeaderDetector()
    headers = {
        # Missing content-length will be reported
        "Server": "nginx",
        "Content-Type": "text/html",
        # Suspicious
        "X-Forwarded-For": "1.1.1.1",
        "X-Cache": "HIT",
        # Security headers
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Security-Policy": "default-src 'none'",
    }
    anomalies = d.analyze_header_anomalies(headers)
    assert "content-length" in anomalies["missing_standard_headers"]
    assert any(h.lower() in ("x-forwarded-for", "x-cache") for h in anomalies["suspicious_headers"])
    assert anomalies["security_headers_count"] == 3


def test_generic_security_headers_detection_as_unknown_waf():
    d = HeaderDetector()
    info = d.detect_from_headers({
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=63072000",
        "X-XSS-Protection": "1; mode=block",
    })
    assert info and info.waf_type == WAFType.UNKNOWN and info.detection_method == "security_headers"


def test_server_header_modsecurity_combo_branch():
    d = HeaderDetector()
    info = d.detect_from_headers({"Server": "Apache modsecurity/2.9.6"})
    assert info and info.waf_type == WAFType.MODSECURITY


def test_value_protected_by_non_incapsula_yields_none_in_checker():
    d = HeaderDetector()
    info = d._check_header_values({"x-protected-by": "somewaf"})
    assert info is None


def test_empty_headers_returns_none():
    d = HeaderDetector()
    assert d._check_header_values({}) is None
