#!/usr/bin/env python3

"""
Project: BRS-XSS Tests
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 15:15:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest
from brsxss.detect.xss.reflected.context_analyzer import ContextAnalyzer
from brsxss.detect.xss.reflected.context_types import ContextType


@pytest.fixture
def analyzer():
    """Provides a ContextAnalyzer instance for tests."""
    return ContextAnalyzer()


def test_identifies_html_content_context(analyzer):
    """
    Test that the analyzer correctly identifies a reflection within plain HTML content.
    """
    param_name = "query"
    param_value = "test_payload"
    response_text = f"<html><body><div>{param_value}</div></body></html>"

    result = analyzer.analyze_context(param_name, param_value, response_text)

    assert result is not None
    assert result.primary_context == ContextType.HTML_CONTENT
    assert len(result.injection_points) == 1

    injection_point = result.injection_points[0]
    assert injection_point.context_type == ContextType.HTML_CONTENT
    assert injection_point.tag_name == "div"


def test_identifies_html_attribute_context(analyzer):
    """
    Test that the analyzer correctly identifies a reflection within an HTML attribute.
    """
    param_name = "q"
    param_value = "search_term"
    response_text = (
        f'<html><body><input type="text" value="{param_value}"></body></html>'
    )

    result = analyzer.analyze_context(param_name, param_value, response_text)

    assert result is not None
    assert result.primary_context == ContextType.HTML_ATTRIBUTE
    assert len(result.injection_points) == 1

    injection_point = result.injection_points[0]
    assert injection_point.context_type == ContextType.HTML_ATTRIBUTE
    assert injection_point.tag_name == "input"
    assert injection_point.attribute_name == "value"
    assert injection_point.quote_char == '"'


def test_identifies_javascript_context(analyzer):
    """
    Test that the analyzer correctly identifies a reflection within a script block.
    """
    param_name = "user_input"
    param_value = "some_value"
    response_text = f"""
    <html>
    <script>
        var userInput = '{param_value}';
        console.log(userInput);
    </script>
    </html>
    """

    result = analyzer.analyze_context(param_name, param_value, response_text)

    assert result is not None
    assert result.primary_context == ContextType.JAVASCRIPT
    assert len(result.injection_points) == 1

    injection_point = result.injection_points[0]
    assert injection_point.context_type == ContextType.JS_STRING
    assert injection_point.quote_char == "'"
