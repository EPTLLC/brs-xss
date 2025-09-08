import types
import pytest

from brsxss.core.scoring_engine import ScoringEngine
from brsxss.core.scoring_types import ScoringWeights, SeverityLevel


def test_determine_severity_thresholds():
    engine = ScoringEngine()
    assert engine._determine_severity(0.0) == SeverityLevel.NONE
    assert engine._determine_severity(0.5) == SeverityLevel.INFO
    assert engine._determine_severity(1.0) == SeverityLevel.LOW
    assert engine._determine_severity(4.0) == SeverityLevel.MEDIUM
    assert engine._determine_severity(7.0) == SeverityLevel.HIGH
    assert engine._determine_severity(9.0) == SeverityLevel.CRITICAL


def test_score_vulnerability_with_mocks(monkeypatch):
    engine = ScoringEngine(weights=ScoringWeights())

    # Mock calculators to return deterministic values
    engine.impact_calculator.calculate_impact_score = lambda ctx, p: 8.0
    engine.exploitability_calculator.calculate_exploitability_score = (
        lambda p, r, c: 6.0
    )
    engine.context_calculator.calculate_context_score = lambda ctx: 7.0
    engine.reflection_calculator.calculate_reflection_score = lambda r: 4.0
    engine.confidence_calculator.calculate_confidence = (
        lambda r, c, p: 0.91
    )

    # Mock risk analyzer outputs
    engine.risk_analyzer.identify_risk_factors = lambda c, p, r: [
        "No input filtering detected",
        "Potential for data exfiltration",
    ]
    engine.risk_analyzer.identify_mitigating_factors = (
        lambda c, resp: ["Content Security Policy implemented"]
    )
    engine.risk_analyzer.generate_recommendations = (
        lambda s, c, rf, mf: ["Implement proper HTML entity encoding"]
    )

    res = engine.score_vulnerability(
        payload="alert(1)",
        reflection_result=object(),
        context_info={"context_type": "javascript", "position": "head"},
        response=types.SimpleNamespace(headers={"content-security-policy": "x"}),
    )

    # 8*0.4 + 6*0.3 + 7*0.2 + 4*0.1 = 6.8 -> MEDIUM
    assert 6.79 < res.score < 6.81
    assert res.severity == SeverityLevel.MEDIUM
    assert 0.9 <= res.confidence <= 0.91
    assert engine.get_statistics()["total_assessments"] == 1
    assert engine.get_statistics()["vulnerability_counts"]["medium"] == 1


def test_reset_and_update_weights():
    engine = ScoringEngine()
    engine.total_assessments = 3
    engine.vulnerability_counts[SeverityLevel.HIGH] = 2
    engine.reset_statistics()
    stats = engine.get_statistics()
    assert stats["total_assessments"] == 0
    assert all(v == 0 for v in stats["vulnerability_counts"].values())

    new_weights = ScoringWeights(impact=0.25, exploitability=0.25, context=0.25, reflection=0.25)
    engine.update_weights(new_weights)
    assert engine.get_statistics()["weights"]["impact"] == 0.25


def test_bulk_score_handles_exceptions(monkeypatch):
    engine = ScoringEngine()

    call_count = {"n": 0}

    def fake_score(**kwargs):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("boom")
        return types.SimpleNamespace(
            score=1.0,
            severity=SeverityLevel.LOW,
            confidence=0.5,
            impact_score=1.0,
            exploitability_score=1.0,
            context_score=1.0,
            reflection_score=1.0,
            risk_factors=[],
            mitigating_factors=[],
            recommendations=[],
        )

    monkeypatch.setattr(engine, "score_vulnerability", fake_score)

    data = [
        {"payload": "a", "reflection_result": None, "context_info": {}},
        {"payload": "b", "reflection_result": None, "context_info": {}},
        {"payload": "c", "reflection_result": None, "context_info": {}},
    ]

    results = engine.bulk_score_vulnerabilities(data)
    assert len(results) == 2
    assert call_count["n"] == 3
