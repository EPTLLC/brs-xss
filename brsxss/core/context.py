#!/usr/bin/env python3

"""
BRS-XSS Context Module

Exports for context analysis system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from .context_analyzer import ContextAnalyzer
from .context_types import (
    ContextType,
    InjectionPoint,
    ContextAnalysisResult,
    FilterType,
    EncodingType
)
from .html_context_detector import HTMLContextDetector
from .javascript_context_detector import JavaScriptContextDetector
from .css_context_detector import CSSContextDetector
from .filter_detector import FilterDetector

__all__ = [
    "ContextAnalyzer",
    "ContextType",
    "InjectionPoint",
    "ContextAnalysisResult",
    "FilterType",
    "EncodingType",
    "HTMLContextDetector",
    "JavaScriptContextDetector",
    "CSSContextDetector",
    "FilterDetector"
]