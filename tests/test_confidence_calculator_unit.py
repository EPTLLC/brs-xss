from types import SimpleNamespace

from brsxss.core.confidence_calculator import ConfidenceCalculator


def test_confidence_calculator_low_and_high():
    calc = ConfidenceCalculator()

    # Low confidence: no reflection, unknown context, simple payload
    c_low = calc.calculate_confidence(None, {"context_type": "unknown"}, "a")
    assert 0.0 <= c_low < 0.5

    # High confidence: exact reflection, detailed context, complex payload
    rr = SimpleNamespace(
        reflection_type="exact",
        completeness=0.95,
        characters_preserved=0.95,
    )
    ctx = {
        "context_type": "javascript",
        "tag_name": "script",
        "attribute_name": "onload",
        "filters_detected": ["html_escape", "strip_tags"],
        "encoding_detected": "url",
    }
    payload = "<script>document.write('x'); alert(1);</script>"
    c_high = calc.calculate_confidence(rr, ctx, payload)
    assert 0.5 < c_high <= 1.0
