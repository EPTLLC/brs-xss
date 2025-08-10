#!/usr/bin/env python3

"""
BRS-XSS DOM Parser

JavaScript parser with AST-based approach for DOM XSS analysis.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .ast_types import NodeType, ASTNode, SourceSinkMapping
from .dom_sources_sinks import DOM_SOURCES, DOM_SINKS
from .ast_extractor import ASTExtractor
from .data_flow_analyzer import DataFlowAnalyzer
from .javascript_parser import JavaScriptParser

__all__ = [
    "NodeType",
    "ASTNode", 
    "SourceSinkMapping",
    "DOM_SOURCES",
    "DOM_SINKS",
    "ASTExtractor",
    "DataFlowAnalyzer",
    "JavaScriptParser"
]