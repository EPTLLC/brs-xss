#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - RiskAnalyzer
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 00:45:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from types import SimpleNamespace
from brsxss.core.risk_analyzer import RiskAnalyzer
from brsxss.core.scoring_types import SeverityLevel


def test_identify_risk_and_mitigating_factors_boundaries():
    ra = RiskAnalyzer()
    context = {
        "context_type": "html_content",
        "tag_name": "script",
        "page_sensitive": True,
        "filters_detected": [],
        "encoding_detected": "none",
        "user_controllable": True,
    }
    payload = "document.cookie; document.write('x'); new XMLHttpRequest()"
    reflection = SimpleNamespace(reflection_type=SimpleNamespace(value="exact"))
    risks = ra.identify_risk_factors(context, payload, reflection)
    assert any("HTML injection" in r or "High-risk" in r for r in risks)
    assert any("data exfiltration" in r.lower() for r in risks)
    assert any("network requests" in r.lower() for r in risks)
    # mitigating factors with headers and encoding
    resp = SimpleNamespace(
        headers={
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-xss-protection": "1; mode=block",
            "x-content-type-options": "nosniff",
        }
    )
    context2 = {
        **context,
        "filters_detected": ["html_entity_encoding"],
        "encoding_detected": "url_encoding",
    }
    m = ra.identify_mitigating_factors(context2, resp)
    assert any("Content Security Policy" in x for x in m)
    assert any("Input filtering detected" in x for x in m)
    assert any("Output encoding detected" in x for x in m)


def test_generate_recommendations_by_severity_and_context():
    ra = RiskAnalyzer()
    context_js = {"context_type": "javascript"}
    rec_high = ra.generate_recommendations(
        SeverityLevel.HIGH, context_js, ["data exfiltration"], []
    )
    assert any("CSP" in r or "script-src" in r.lower() for r in rec_high)
    assert any("Monitor" in r for r in rec_high)
    context_html = {"context_type": "html_content"}
    rec_med = ra.generate_recommendations(
        SeverityLevel.MEDIUM, context_html, ["session hijacking"], []
    )
    assert any("HTML entity encoding" in r for r in rec_med)
    assert any("HttpOnly" in r or "Secure cookie" in r for r in rec_med)
    # Ensure duplicates removed by set
    assert len(rec_high) == len(set(rec_high))
