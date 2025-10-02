#!/usr/bin/env python3

"""
BRS-XSS DOM Module

DOM XSS vulnerability analysis with AST-based approach.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .vulnerability_types import VulnerabilityType, RiskLevel
from .data_models import DataFlow, DOMVulnerability
from .sanitization_analyzer import SanitizationAnalyzer
from .vulnerability_classifier import VulnerabilityClassifier
from .payload_generator import PayloadGenerator
from .dom_analyzer import DOMAnalyzer
from .parser import (
    NodeType, ASTNode, SourceSinkMapping, 
    DOM_SOURCES, DOM_SINKS,
    ASTExtractor, DataFlowAnalyzer, JavaScriptParser
)
from .detector import DOMScanResult, JavaScriptExtractor, DOMXSSDetector

__all__ = [
    "VulnerabilityType",
    "RiskLevel", 
    "DataFlow",
    "DOMVulnerability",
    "SanitizationAnalyzer",
    "VulnerabilityClassifier", 
    "PayloadGenerator",
    "DOMAnalyzer",
    "NodeType",
    "ASTNode", 
    "SourceSinkMapping",
    "DOM_SOURCES",
    "DOM_SINKS",
    "ASTExtractor",
    "DataFlowAnalyzer",
    "JavaScriptParser",
    "DOMScanResult",
    "JavaScriptExtractor",
    "DOMXSSDetector"
]