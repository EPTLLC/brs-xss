#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - FilterDetector
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 00:20:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.detect.xss.reflected.filter_detector import FilterDetector
from brsxss.detect.xss.reflected.context_types import EncodingType, FilterType


def test_detect_filters_content_removed_and_indicators_and_keyword():
    fd = FilterDetector()
    original = "<script>alert('x')</script>"
    rendered = "&lt;script&gt;[truncated]"  # content filtered and encoded and truncated
    filters = fd.detect_filters(original, rendered)
    assert FilterType.CONTENT_FILTERING.value in filters
    assert FilterType.HTML_ENTITY_ENCODING.value in filters
    assert "length_filtering" in filters
    # keyword filtering: 'alert' not present
    assert "keyword_filtering" in fd.detect_filters("alert(1)", "AL...")


def test_detect_character_substitutions_and_url_encoding():
    fd = FilterDetector()
    original = "<tag>"
    rendered = "%3Ctag%3E"
    filters = fd.detect_filters(original, rendered)
    assert FilterType.URL_ENCODING.value in filters


def test_detect_encoding_patterns_and_none():
    fd = FilterDetector()
    assert fd.detect_encoding("&lt;div&gt;") == EncodingType.HTML_ENTITIES.value
    assert fd.detect_encoding("%3Cdiv%3E") == EncodingType.URL_ENCODING.value
    assert (
        fd.detect_encoding("\\u003Cdiv\\u003E") == EncodingType.UNICODE_ESCAPING.value
    )
    assert fd.detect_encoding("plain text") == EncodingType.NONE.value


def test_analyze_filter_strength_levels_and_recommendations():
    fd = FilterDetector()
    # none
    a0 = fd.analyze_filter_strength([])
    assert a0["strength_level"] == "none" and a0["bypassable"] is True
    # medium
    a1 = fd.analyze_filter_strength([FilterType.HTML_ENTITY_ENCODING.value])
    assert a1["strength_level"] == "medium" and a1["risk_assessment"] == "high"
    # high
    a2 = fd.analyze_filter_strength([FilterType.CONTENT_FILTERING.value])
    assert a2["strength_level"] == "high" and a2["risk_assessment"] == "medium"
    # very_high when includes WAF filtering
    a3 = fd.analyze_filter_strength([FilterType.WAF_FILTERING.value])
    assert a3["strength_level"] == "very_high" and a3["bypassable"] is False
    # recommendations include bypass techniques from analysis
    recs = fd.get_filter_recommendations(
        [FilterType.HTML_ENTITY_ENCODING.value, FilterType.URL_ENCODING.value]
    )
    assert any("entities" in r.lower() for r in recs) and any(
        "url" in r.lower() for r in recs
    )
