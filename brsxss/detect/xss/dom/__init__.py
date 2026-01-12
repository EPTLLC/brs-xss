#!/usr/bin/env python3

"""
BRS-XSS DOM Module - COMPATIBILITY LAYER

This module re-exports from detect/xss/dom/ for backward compatibility.
New code should import from brsxss.detect.xss.dom directly.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 10:00 UTC
Telegram: https://t.me/EasyProTech

DEPRECATED: Use brsxss.detect.xss.dom instead
"""

from .vulnerability_types import VulnerabilityType, RiskLevel
from .data_models import DataFlow, DOMVulnerability
from .sanitization_analyzer import SanitizationAnalyzer
from .vulnerability_classifier import VulnerabilityClassifier
from .payload_generator import PayloadGenerator
from .dom_analyzer import DOMAnalyzer
from .parser import (
    NodeType,
    ASTNode,
    SourceSinkMapping,
    DOM_SOURCES,
    DOM_SINKS,
    ASTExtractor,
    DataFlowAnalyzer,
    JavaScriptParser,
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
    "DOMXSSDetector",
]
