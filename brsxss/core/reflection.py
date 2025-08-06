#!/usr/bin/env python3

"""
BRS-XSS Reflection Module

Exports for reflection detection system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: @easyprotech
"""

from .reflection_detector import ReflectionDetector
from .reflection_types import (
    ReflectionResult,
    ReflectionPoint,
    ReflectionConfig,
    ReflectionType,
    ReflectionContext
)
from .reflection_analyzer import ReflectionAnalyzer
from .similarity_matcher import SimilarityMatcher

__all__ = [
    "ReflectionDetector",
    "ReflectionResult", 
    "ReflectionPoint",
    "ReflectionConfig",
    "ReflectionType",
    "ReflectionContext",
    "ReflectionAnalyzer",
    "SimilarityMatcher"
]