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

# v3.0.0: Advanced context detection
from .advanced_context_detector import (
    AdvancedContextDetector,
    WebSocketContext,
    GraphQLContext,
    SSEContext,
    WebComponentContext,
)

# v3.1.0: Core engine components
from .response_diff import ResponseDiffEngine, ReflectionStatus, FilterType, DiffResult
from .callback_server import CallbackServer, CallbackEvent, get_callback_server
from .mutation_fuzzer import MutationFuzzer, MutationType, MutatedPayload
from .parameter_miner import ParameterMiner, DiscoveredParameter
from .encoding_engine import EncodingEngine, EncodingType, EncodedPayload

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
    # v3.0.0: Advanced contexts
    "AdvancedContextDetector",
    "WebSocketContext",
    "GraphQLContext",
    "SSEContext",
    "WebComponentContext",
    # v3.1.0: Core engine components
    "ResponseDiffEngine",
    "ReflectionStatus",
    "FilterType",
    "DiffResult",
    "CallbackServer",
    "CallbackEvent",
    "get_callback_server",
    "MutationFuzzer",
    "MutationType",
    "MutatedPayload",
    "ParameterMiner",
    "DiscoveredParameter",
    "EncodingEngine",
    "EncodingType",
    "EncodedPayload",
]
