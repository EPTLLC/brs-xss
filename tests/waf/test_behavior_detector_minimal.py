#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - WAF BehaviorDetector minimal
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 02:06:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from types import SimpleNamespace
from brsxss.waf.behavior_detector import BehaviorDetector


def _resp(code: int, ct: str = "text/html", body: bytes = b"hi"):
    return SimpleNamespace(status_code=code, headers={"content-type": ct}, content=body)


def test_behavior_detector_analysis_and_confidence():
    d = BehaviorDetector()
    responses = [_resp(200), _resp(403), _resp(503)]
    timings = [0.3, 2.1, 2.5]
    info = d.analyze_response_behavior(responses, timings)
    assert (
        info
        and info.detection_method == "behavioral_analysis"
        and info.confidence > 0.6
    )

    # Geo blocking detection
    geo = d.detect_geo_blocking([SimpleNamespace(text="Blocked in your country")])
    assert geo["likely_geo_blocked"] is True and geo["confidence"] > 0.0

    # Progressive blocking escalation presence
    prog = d.analyze_progressive_blocking([_resp(200), _resp(403), _resp(503)])
    assert prog["has_progressive_blocking"] is True and prog["pattern_detected"] is True
