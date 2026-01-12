#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - JavaScriptParser minimal unit test
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 04:12:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.detect.xss.dom.javascript_parser import JavaScriptParser
from brsxss.detect.xss.dom.ast_types import ASTNode, NodeType


def test_js_parser_tracks_assignments_and_stats(monkeypatch):
    parser = JavaScriptParser()

    # Fake extractor to return one assignment and one call
    assign_node = ASTNode(
        node_type=NodeType.VARIABLE_ASSIGNMENT,
        value="x = y",
        children=[],
        line_number=1,
        column=1,
        variable_name="x",
    )
    call_node = ASTNode(
        node_type=NodeType.FUNCTION_CALL,
        value="eval(x)",
        children=[],
        line_number=2,
        column=1,
        function_name="eval",
    )

    class FakeExtractor:
        @staticmethod
        def parse_line(line, ln):
            return [assign_node] if ln == 1 else [call_node]

    class FakeAnalyzer:
        def __init__(self, nodes, assigns):
            self.source_nodes = []
            self.sink_nodes = []

        def classify_nodes(self):
            # leave empty
            return None

        def find_data_flows(self):
            return []

    monkeypatch.setattr(
        "brsxss.detect.xss.dom.javascript_parser.ASTExtractor", FakeExtractor
    )
    monkeypatch.setattr(
        "brsxss.detect.xss.dom.javascript_parser.DataFlowAnalyzer", FakeAnalyzer
    )

    nodes = parser.parse_javascript("x = y\neval(x)")
    assert len(nodes) == 2 and "x" in parser.variable_assignments
    stats = parser.get_parsing_stats()
    assert stats["total_nodes"] == 2 and stats["variable_assignments"] == 1
