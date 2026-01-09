#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - WAF ContentDetector minimal
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 02:05:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.waf.content_detector import ContentDetector
from brsxss.waf.waf_types import WAFType


def test_content_detector_cloudflare_signature_and_blocking_behavior():
    d = ContentDetector()
    # Direct signature hit (cloudflare)
    info = d.detect_from_content("Just a moment... Cloudflare CF-RAY: 123")
    assert (
        info
        and info.waf_type == WAFType.CLOUDFLARE
        and info.detection_method == "content_analysis"
    )

    # Generic blocking behavior (two+ indicators)
    blk = d.detect_from_content(
        "Access denied due to security violation. Request rejected by policy."
    )
    assert (
        blk
        and blk.waf_type == WAFType.UNKNOWN
        and blk.detection_method == "blocking_behavior"
    )


def test_analyze_error_pages_and_js_challenge():
    d = ContentDetector()
    err = d.analyze_error_pages(
        "403 Forbidden - Web Application Firewall: Malicious request"
    )
    assert err["is_error_page"] is True and err["error_type"] == "403_forbidden"
    assert (
        any("security" in i for i in err["waf_indicators"]) or err["security_focused"]
    )

    js = d.detect_javascript_challenges("Checking your browser... CF-RAY: abc123")
    assert js["has_js_challenge"] is True and js["challenge_type"] == "cloudflare"
