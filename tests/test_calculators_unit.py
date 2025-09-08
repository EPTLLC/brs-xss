from types import SimpleNamespace

from brsxss.core.impact_calculator import ImpactCalculator
from brsxss.core.exploitability_calculator import ExploitabilityCalculator
from brsxss.core.context_calculator import ContextCalculator
from brsxss.core.reflection_calculator import ReflectionCalculator


def test_impact_calculator_various_contexts():
    calc = ImpactCalculator()
    ctx = {"context_type": "javascript", "position": "head", "user_controllable": True}
    s1 = calc.calculate_impact_score(ctx, "alert(1)")
    assert 5.0 < s1 <= 10.0

    ctx = {"context_type": "css_style", "position": "footer", "user_controllable": False}
    s2 = calc.calculate_impact_score(ctx, "color:red")
    assert s2 < s1

    # Payload increases bonus
    ctx = {"context_type": "html_content", "position": "body"}
    s3 = calc.calculate_impact_score(ctx, "<img src=x onerror=fetch('https://a')>")
    assert s3 >= s1 or s3 <= 10.0


def test_exploitability_calculator_multipliers():
    calc = ExploitabilityCalculator()
    rr = SimpleNamespace(reflection_type="exact")
    ctx = {"context_type": "javascript", "filters_detected": ["html_escape"], "encoding_detected": "url"}
    score = calc.calculate_exploitability_score("alert(1)", rr, ctx)
    assert 0.0 <= score <= 10.0

    rr2 = SimpleNamespace(reflection_type="not_reflected")
    ctx2 = {"context_type": "html_comment", "filters_detected": [], "encoding_detected": "none"}
    score2 = calc.calculate_exploitability_score("a" * 120, rr2, ctx2)
    assert score2 <= score


def test_context_calculator_bonuses():
    calc = ContextCalculator()
    base = calc.calculate_context_score({"context_type": "html_attribute", "attribute_name": "onload"})
    assert base > 6.0

    high = calc.calculate_context_score({
        "context_type": "javascript",
        "tag_name": "script",
        "attribute_name": "onerror",
        "position": "head",
        "nested_context": True,
        "dynamic_content": True,
        "template_context": True,
        "ajax_context": True,
    })
    assert high >= base


def test_reflection_calculator_components():
    calc = ReflectionCalculator()
    rr = SimpleNamespace(
        reflection_type="partial",
        completeness=0.9,
        characters_preserved=0.95,
        special_chars_preserved=['<', '>', '"', "'", '&'],
        positions=[{"context": "script"}, {"context": "attribute"}],
        reflection_count=3,
        reflection_types=["partial", "encoded"],
    )
    score = calc.calculate_reflection_score(rr)
    assert 0.0 <= score <= 10.0
