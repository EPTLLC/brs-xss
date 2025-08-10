#!/usr/bin/env python3

from brsxss.utils.validators import PayloadValidator


def test_payload_sanitize_for_logging():
    raw = '<script>alert("xss")</script>'
    sanitized = PayloadValidator.sanitize_payload_for_logging(raw)
    assert isinstance(sanitized, str)
    assert len(sanitized) <= 256
    # Should reduce dangerous characters
    assert 'script' not in sanitized.lower() or '<' not in sanitized or '>' not in sanitized


