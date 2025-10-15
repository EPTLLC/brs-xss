#!/usr/bin/env python3

"""
BRS-XSS Core Module

Core scanning engine with vulnerability detection and analysis.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .config_manager import ConfigManager
from .http_client import HTTPClient, HTTPResponse
from .scanner import XSSScanner
from .context_analyzer import ContextType, InjectionPoint, ContextAnalyzer
from .payload_generator import GeneratedPayload, PayloadGenerator
from .reflection import ReflectionDetector, ReflectionResult, ReflectionType
from .scoring_engine import SeverityLevel, ScoringResult, ScoringEngine
from .ml_integration import MLIntegration

__all__ = [
    "ConfigManager",
    "HTTPClient",
    "HTTPResponse",
    "XSSScanner",
    "ContextType",
    "InjectionPoint",
    "ContextAnalyzer",
    "GeneratedPayload",
    "PayloadGenerator",
    "ReflectionType",
    "ReflectionResult",
    "ReflectionDetector",
    "SeverityLevel",
    "ScoringResult",
    "ScoringEngine",
    "MLIntegration"
]