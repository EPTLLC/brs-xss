#!/usr/bin/env python3

"""
BRS-XSS WAF Module

Web Application Firewall detection and evasion system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .waf_types import WAFType, WAFInfo
from .detector import WAFDetectionEngine, WAFDetector
from .evasion import (
    EvasionTechnique,
    EvasionResult,
    EncodingEngine,
    ObfuscationEngine,
    WAFSpecificEvasion,
    EvasionEngine,
)
from .fingerprinter import WAFSignature, SignatureDatabase, WAFFingerprinter
from .confidence_engine import (
    ConfidenceEngine,
    ConfidenceLevel,
    ConfidenceResult,
    EvidenceItem,
)
from .adaptive_bypass import AdaptiveBypassSelector, BypassTechnique, BypassStrategy

__all__ = [
    # Types
    "WAFType",
    "WAFInfo",
    # Detection
    "WAFDetectionEngine",
    "WAFDetector",
    # Evasion
    "EvasionTechnique",
    "EvasionResult",
    "EncodingEngine",
    "ObfuscationEngine",
    "WAFSpecificEvasion",
    "EvasionEngine",
    # Fingerprinting
    "WAFSignature",
    "SignatureDatabase",
    "WAFFingerprinter",
    # Confidence scoring
    "ConfidenceEngine",
    "ConfidenceLevel",
    "ConfidenceResult",
    "EvidenceItem",
    # Adaptive bypass
    "AdaptiveBypassSelector",
    "BypassTechnique",
    "BypassStrategy",
]
