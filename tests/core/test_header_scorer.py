#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - HeaderSecurityScorer
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 21:49:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.header_scorer import HeaderSecurityScorer
from brsxss.core.header_types import HeaderAnalysis, SecurityLevel


def test_header_scorer_calculates_and_describes():
    scorer = HeaderSecurityScorer()
    analyses = {
        'Content-Security-Policy': HeaderAnalysis('Content-Security-Policy', 'default-src self', SecurityLevel.SECURE, [], []),
        'X-XSS-Protection': HeaderAnalysis('X-XSS-Protection', '1; mode=block', SecurityLevel.MODERATE, [], []),
        'X-Frame-Options': HeaderAnalysis('X-Frame-Options', 'SAMEORIGIN', SecurityLevel.MODERATE, [], []),
        'X-Content-Type-Options': HeaderAnalysis('X-Content-Type-Options', 'nosniff', SecurityLevel.SECURE, [], []),
    }
    score, desc = scorer.calculate_security_score(analyses)
    assert 60 <= score <= 100 and isinstance(desc, str) and len(desc) > 0


def test_header_scorer_recommendations_and_compare():
    scorer = HeaderSecurityScorer()
    before = {
        'X-XSS-Protection': HeaderAnalysis('X-XSS-Protection', '0', SecurityLevel.VULNERABLE, ['off'], []),
    }
    after = {
        'X-XSS-Protection': HeaderAnalysis('X-XSS-Protection', '1; mode=block', SecurityLevel.MODERATE, [], []),
        'Content-Security-Policy': HeaderAnalysis('Content-Security-Policy', 'default-src self', SecurityLevel.SECURE, [], []),
    }
    recs = scorer.get_priority_recommendations(before)
    assert any(r['priority'] == 'HIGH' for r in recs)
    cmp = scorer.compare_configurations(before, after)
    assert 'Content-Security-Policy' in cmp and 'X-XSS-Protection' in cmp


