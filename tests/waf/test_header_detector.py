#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - WAF HeaderDetector
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 21:41:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.waf.header_detector import HeaderDetector
from brsxss.waf.waf_types import WAFType


def test_header_detector_by_header_name():
    d = HeaderDetector()
    info = d.detect_from_headers({"CF-Ray": "abc"})
    assert info and info.waf_type == WAFType.CLOUDFLARE


def test_header_detector_by_server_value_and_protected_by():
    d = HeaderDetector()
    info2 = d.detect_from_headers({"Server": "nginx modsecurity 3.0"})
    assert info2 and info2.waf_type == WAFType.MODSECURITY
    info3 = d.detect_from_headers({"X-Protected-By": "Incapsula"})
    # Current logic maps header name to Fortinet before value-based detection
    assert info3 and info3.waf_type == WAFType.FORTINET


def test_header_detector_extract_version():
    d = HeaderDetector()
    v = d._extract_version("mod_security v3.1.2")
    assert v == "3.1.2"
