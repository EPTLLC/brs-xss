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
    EvasionTechnique, EvasionResult, EncodingEngine, 
    ObfuscationEngine, WAFSpecificEvasion, EvasionEngine
)
from .fingerprinter import WAFSignature, SignatureDatabase, WAFFingerprinter

__all__ = [
    "WAFType",
    "WAFInfo",
    "WAFDetectionEngine",
    "WAFDetector",
    "EvasionTechnique",
    "EvasionResult",
    "EncodingEngine",
    "ObfuscationEngine", 
    "WAFSpecificEvasion",
    "EvasionEngine",
    "WAFSignature",
    "SignatureDatabase",
    "WAFFingerprinter"
]