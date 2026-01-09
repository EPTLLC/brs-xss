#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - DOMAnalyzer unit (mocked)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 04:00:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.dom.dom_analyzer import DOMAnalyzer
from brsxss.dom.ast_types import ASTNode, NodeType, SourceSinkMapping
from brsxss.dom.vulnerability_types import VulnerabilityType, RiskLevel


def _node(nt: NodeType, value: str, ln: int, col: int, **kw) -> ASTNode:
    return ASTNode(
        node_type=nt, value=value, children=[], line_number=ln, column=col, **kw
    )


def test_dom_analyzer_classification_and_recommendations(monkeypatch):
    analyzer = DOMAnalyzer()

    # Create synthetic source/sink nodes
    src = _node(
        NodeType.FUNCTION_CALL, "location.hash", 1, 1, function_name="location.hash"
    )
    sink = _node(
        NodeType.PROPERTY_ACCESS,
        "document.body.innerHTML",
        2,
        5,
        object_name="document.body",
        property_name="innerHTML",
    )
    mapping = SourceSinkMapping(
        source_node=src,
        sink_node=sink,
        data_path=[src, sink],
        vulnerability_confidence=0.9,
        risk_factors=["hash", "innerHTML"],
    )

    # Patch JS parser inside analyzer
    monkeypatch.setattr(
        analyzer,
        "js_parser",
        type(
            "P",
            (),
            {
                "parse_javascript": lambda self, code: [src, sink],
                "find_data_flows": lambda self=None: [mapping],
                "ast_nodes": [src, sink],
                "get_parsing_stats": lambda self=None: {"total_nodes": 2},
            },
        )(),
    )

    # Force classifier output
    monkeypatch.setattr(
        analyzer.vulnerability_classifier,
        "classify_vulnerability",
        lambda s, k, d: (VulnerabilityType.DIRECT_ASSIGNMENT, RiskLevel.HIGH),
    )

    vulns = analyzer.analyze_javascript("document.body.innerHTML = location.hash;")
    assert (
        vulns
        and vulns[0].vulnerability_type == VulnerabilityType.DIRECT_ASSIGNMENT
        and vulns[0].risk_level == RiskLevel.HIGH
    )
    assert "textContent" in vulns[0].fix_recommendation

    # Summary should reflect counts
    summary = analyzer.get_analysis_summary()
    assert isinstance(summary, dict) and summary.get("total_vulnerabilities", 0) >= 1
