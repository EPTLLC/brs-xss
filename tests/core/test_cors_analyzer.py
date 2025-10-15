#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - CORSAnalyzer
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 21:46:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.cors_analyzer import CORSAnalyzer
from brsxss.core.header_types import SecurityLevel


def test_cors_analyzer_allow_origin_and_credentials():
    a = CORSAnalyzer()
    headers = {
        'access-control-allow-origin': '*',
        'access-control-allow-credentials': 'true',
    }
    res = a.analyze_cors_headers(headers)
    d = {r.header_name: r for r in res}
    assert d['access-control-allow-origin'].security_level == SecurityLevel.VULNERABLE


def test_cors_analyzer_methods_and_headers():
    a = CORSAnalyzer()
    headers = {
        'access-control-allow-methods': 'GET, PUT',
        'access-control-allow-headers': 'authorization, x-custom',
    }
    res = a.analyze_cors_headers(headers)
    dd = {r.header_name: r for r in res}
    assert dd['access-control-allow-methods'].security_level == SecurityLevel.MODERATE
    assert dd['access-control-allow-headers'].security_level == SecurityLevel.MODERATE


