#!/usr/bin/env python3

"""
Project: BRS-XSS Tests for ScoringEngine
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 16:20:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest
from brsxss.core.scoring_engine import ScoringEngine
from brsxss.core.reflection_types import ReflectionResult, ReflectionPoint, ReflectionType, ReflectionContext
from brsxss.core.context_types import ContextAnalysisResult, ContextType, InjectionPoint
from unittest.mock import MagicMock

@pytest.fixture
def scoring_engine():
    """Provides a ScoringEngine instance for tests."""
    return ScoringEngine()

def test_scores_high_risk_vulnerability_highly(scoring_engine):
    """
    Test that a clear, high-risk vulnerability gets a high score.
    """
    # Arrange: Simulate a perfect reflection in a dangerous context
    payload = "<script>alert(1)</script>"
    
    reflection_point = ReflectionPoint(
        position=10,
        reflected_value=payload,
        original_value=payload,
        reflection_type=ReflectionType.EXACT,
        context=ReflectionContext.HTML_CONTENT,
        accuracy=1.0,
        completeness=1.0,
        special_chars_preserved=['<', '>', '"', "'"] # Crucial for high score
    )
    reflection_result = ReflectionResult(
        input_value=payload, 
        reflection_points=[reflection_point]
    )
    
    context_info = {
        'context_type': 'html_content',
        'specific_context': 'html_content'
    }

    mock_response = MagicMock()
    mock_response.status_code = 200

    # Act
    vulnerability_score = scoring_engine.score_vulnerability(
        payload, reflection_result, context_info, mock_response
    )

    # Assert
    assert vulnerability_score.score > 8.0 # Expect a very high score
    assert vulnerability_score.severity.value == "high"

def test_scores_low_risk_vulnerability_lowly(scoring_engine):
    """
    Test that a weak, low-risk finding gets a low score.
    """
    # Arrange: Simulate a filtered reflection in a safe context (comment)
    payload = "<!-- test -->"
    
    reflection_point = ReflectionPoint(
        position=20,
        reflected_value="-- test --", # Chars removed
        original_value=payload,
        reflection_type=ReflectionType.FILTERED,
        context=ReflectionContext.HTML_COMMENT,
        accuracy=0.5,
        completeness=0.8,
        special_chars_preserved=[] # No critical chars
    )
    reflection_result = ReflectionResult(
        input_value=payload,
        reflection_points=[reflection_point]
    )
    
    context_info = {
        'context_type': 'html_comment',
        'specific_context': 'html_comment'
    }

    mock_response = MagicMock()
    mock_response.status_code = 200

    # Act
    vulnerability_score = scoring_engine.score_vulnerability(
        payload, reflection_result, context_info, mock_response
    )

    # Assert
    assert vulnerability_score.score < 3.0
    assert vulnerability_score.severity.value == "low"
