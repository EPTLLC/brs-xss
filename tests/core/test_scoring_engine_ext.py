#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ScoringEngine Extended
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:05:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from unittest.mock import MagicMock

from brsxss.core.scoring_engine import ScoringEngine
from brsxss.core.scoring_types import ScoringWeights


def _mk_reflection(exact=True):
    class RP:
        def __init__(self):
            self.reflection_type = type(
                "T", (), {"value": "exact" if exact else "filtered"}
            )()
            self.accuracy = 1.0 if exact else 0.5
            self.completeness = 1.0 if exact else 0.5
            self.special_chars_preserved = ["<", ">", '"', "'"] if exact else []
            self.filters_detected = []
            self.position = 0
            self.context = "html_content"

    class RR:
        def __init__(self):
            self.reflection_points = [RP()]
            self.overall_reflection_type = type(
                "T", (), {"value": "exact" if exact else "filtered"}
            )()
            self.exploitation_confidence = 1.0 if exact else 0.3

    return RR()


def test_scoring_engine_stats_and_weights():
    se = ScoringEngine()
    # Update weights via dataclass
    se.update_weights(
        ScoringWeights(impact=0.5, exploitability=0.4, context=0.1, reflection=0.0)
    )
    stats = se.get_statistics()
    assert "weights" in stats
    # score one vuln
    reflection = _mk_reflection(exact=True)
    ctx = {"context_type": "html_content", "specific_context": "html_content"}
    res = se.score_vulnerability(
        "<script>alert(1)</script>", reflection, ctx, MagicMock(status_code=200)
    )
    assert res.score >= 7.0
    stats2 = se.get_statistics()
    assert stats2["total_assessments"] == 1
    se.reset_statistics()
    assert se.get_statistics()["total_assessments"] == 0


def test_bulk_scoring_runs_through():
    se = ScoringEngine()
    ctx = {"context_type": "html_content", "specific_context": "html_content"}
    vulns = [
        {
            "payload": "<script>alert(1)</script>",
            "reflection_result": _mk_reflection(exact=True),
            "context_info": ctx,
            "response": MagicMock(status_code=200),
        },
        {
            "payload": "<!--test-->",
            "reflection_result": _mk_reflection(exact=False),
            "context_info": {
                "context_type": "html_comment",
                "specific_context": "html_comment",
            },
            "response": MagicMock(status_code=200),
        },
    ]
    out = se.bulk_score_vulnerabilities(vulns)
    assert len(out) == 2
    assert out[0].score >= out[1].score
