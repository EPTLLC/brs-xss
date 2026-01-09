#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - SecurityHeadersInspector
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 21:42:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.security_headers import SecurityHeadersInspector


def test_security_headers_inspector_minimal_secure():
    insp = SecurityHeadersInspector()
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-XSS-Protection": "1; mode=block",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "same-origin",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }
    res = insp.analyze_headers(headers)
    assert "X-Content-Type-Options" in res
    assert "X-Frame-Options" in res
    assert "X-XSS-Protection" in res
    assert "Strict-Transport-Security" in res


def test_security_headers_inspector_missing_and_cors_integration():
    insp = SecurityHeadersInspector()
    headers = {
        # Missing X-XSS-Protection, X-Frame-Options; provide CORS headers
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST",
        "Access-Control-Allow-Headers": "Content-Type, X-Requested-With",
    }
    res = insp.analyze_headers(headers)
    # Basic missing headers filtered: referrer/hsts may be None and thus absent
    # Ensure CORS analyses are present by their header_name (lowercase in analyzer)
    assert any(k.startswith("access-control-allow-") for k in res.keys())
