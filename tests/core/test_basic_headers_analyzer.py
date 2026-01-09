#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - BasicHeadersAnalyzer
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 21:40:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.basic_headers_analyzer import BasicHeadersAnalyzer
from brsxss.core.header_types import SecurityLevel


def test_basic_headers_analyzer_xss_protection():
    a = BasicHeadersAnalyzer()
    r_missing = a.analyze_xss_protection(None)
    assert (
        r_missing.security_level == SecurityLevel.WEAK and r_missing.value == "MISSING"
    )
    r_off = a.analyze_xss_protection("0")
    assert r_off.security_level == SecurityLevel.VULNERABLE and any(
        "disabled" in v.lower() for v in r_off.vulnerabilities
    )
    r_no_block = a.analyze_xss_protection("1; report=https://x")
    assert r_no_block.security_level == SecurityLevel.WEAK
    r_block = a.analyze_xss_protection("1; mode=block")
    assert r_block.security_level == SecurityLevel.MODERATE


def test_basic_headers_analyzer_frame_and_content_type_and_referrer_and_hsts():
    a = BasicHeadersAnalyzer()
    r_frame_missing = a.analyze_frame_options(None)
    assert (
        r_frame_missing.security_level == SecurityLevel.WEAK
        and r_frame_missing.value == "MISSING"
    )
    r_frame_allowall = a.analyze_frame_options("ALLOWALL")
    assert r_frame_allowall.security_level == SecurityLevel.VULNERABLE
    r_frame_sameorigin = a.analyze_frame_options("SAMEORIGIN")
    assert r_frame_sameorigin.security_level == SecurityLevel.MODERATE
    r_frame_deny = a.analyze_frame_options("DENY")
    assert r_frame_deny.security_level == SecurityLevel.SECURE
    r_frame_bad = a.analyze_frame_options("random")
    assert r_frame_bad.security_level == SecurityLevel.WEAK
    r_xcto = a.analyze_content_type_options("nosniff")
    assert r_xcto.security_level == SecurityLevel.SECURE
    r_xcto_missing = a.analyze_content_type_options(None)
    assert (
        r_xcto_missing.security_level == SecurityLevel.WEAK
        and r_xcto_missing.value == "MISSING"
    )
    r_xcto_bad = a.analyze_content_type_options("sniff")
    assert r_xcto_bad.security_level == SecurityLevel.WEAK
    r_ref = a.analyze_referrer_policy("same-origin")
    assert r_ref and r_ref.security_level == SecurityLevel.SECURE
    assert a.analyze_referrer_policy(None) is None
    r_ref_weak = a.analyze_referrer_policy("unsafe-url")
    assert r_ref_weak and r_ref_weak.security_level == SecurityLevel.WEAK
    r_ref_mod = a.analyze_referrer_policy("origin")
    assert r_ref_mod and r_ref_mod.security_level == SecurityLevel.MODERATE
    assert a.analyze_hsts(None) is None
    r_hsts_short = a.analyze_hsts("max-age=100; includeSubDomains")
    assert r_hsts_short and r_hsts_short.security_level == SecurityLevel.MODERATE
    r_hsts_missing_dirs = a.analyze_hsts("max-age=31536000")
    assert (
        r_hsts_missing_dirs
        and r_hsts_missing_dirs.security_level == SecurityLevel.MODERATE
    )
    r_hsts_ok = a.analyze_hsts("max-age=31536000; includeSubDomains")
    assert r_hsts_ok and r_hsts_ok.security_level == SecurityLevel.SECURE
