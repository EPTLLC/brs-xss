#!/usr/bin/env python3

"""
Project: BRS-XSS Regression Tests
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 08 Jan 2026 21:52:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.context_analyzer import ContextAnalyzer
from brsxss.core.context_types import ContextType
from brsxss.core.result_manager import ResultManager
from brsxss.dom.headless_detector import DOMXSSResult


def test_xssgame_level1_reflection_context_html():
    """Ensure Level1 reflection lands in pure HTML content, not JavaScript."""
    sample_html = """
    <!doctype html>
    <html>
      <head>
        <script src="/static/game-frame.js"></script>
      </head>
      <body id="level1">
        <div>
          Sorry, no results were found for <b>__BRSXSS__</b>. <a href='?'>Try again</a>.
        </div>
      </body>
    </html>
    """
    analyzer = ContextAnalyzer()
    result = analyzer.analyze_context("query", "__BRSXSS__", sample_html)

    assert result.primary_context == ContextType.HTML_CONTENT
    assert result.injection_points, "Expected at least one injection point"
    first = result.injection_points[0]
    assert first.context_type == ContextType.HTML_CONTENT
    assert first.tag_name == "b"


def test_dom_aggregation_includes_context_chain():
    """Aggregated DOM findings must expose reflection_type/context chain for reports."""

    dom_results = [
        DOMXSSResult(
            url="https://xss-game.appspot.com/level1/frame",
            vulnerable=True,
            payload="<script>alert('DOM_XSS_FRAGMENT')</script>",
            trigger_method="parameter",
            execution_context="URL parameter: query",
            source="location.search (query)",
            sink="innerHTML/DOM",
            score=0.9,
        )
    ]

    aggregated = ResultManager.aggregate_dom_findings(dom_results[0].url, dom_results)

    assert aggregated["reflection_type"] == "dom_based"
    assert aggregated["context_type"] == "dom_flow"
    assert aggregated["context"] == "location.search (query) -> innerHTML/DOM"
