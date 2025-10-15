#!/usr/bin/env python3

"""
Project: BRS-XSS Tests
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 15:00:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest
from brsxss.core.reflection_detector import ReflectionDetector
from brsxss.core.reflection_types import ReflectionType

@pytest.fixture
def detector():
    """Provides a ReflectionDetector instance for tests."""
    return ReflectionDetector()

def test_detects_exact_reflection(detector):
    """
    Test that the detector finds a payload that is perfectly reflected in the response.
    """
    payload = "<script>alert(1)</script>"
    response_text = f"<html><body>Search results for: {payload}</body></html>"
    
    result = detector.detect_reflections(payload, response_text)
    
    assert result is not None
    assert result.total_reflections == 1
    assert result.overall_reflection_type == ReflectionType.EXACT
    
    reflection_point = result.reflection_points[0]
    assert reflection_point.reflected_value == payload
    assert reflection_point.position == response_text.find(payload)

def test_no_reflection_found(detector):
    """
    Test that the detector correctly reports no reflections when the payload is absent.
    """
    payload = "<script>alert(1)</script>"
    response_text = "<html><body>Search results for: query</body></html>"
    
    result = detector.detect_reflections(payload, response_text)
    
    assert result is not None
    assert result.total_reflections == 0
    assert result.overall_reflection_type == ReflectionType.NOT_REFLECTED

def test_detects_html_encoded_reflection(detector):
    """
    Test that the detector identifies a payload that has been HTML-encoded in the response.
    """
    payload = "<script>alert(1)</script>"
    encoded_payload = "&lt;script&gt;alert(1)&lt;/script&gt;"
    response_text = f"<html><body>Your input was: {encoded_payload}</body></html>"
    
    result = detector.detect_reflections(payload, response_text)
    
    assert result is not None
    assert result.total_reflections == 1
    assert result.overall_reflection_type == ReflectionType.ENCODED
    
    reflection_point = result.reflection_points[0]
    assert reflection_point.reflected_value == encoded_payload
    assert "html_encoding" in reflection_point.encoding_applied
