#!/usr/bin/env python3

"""
BRS-XSS WAF Evasion

Adaptive WAF evasion system with machine learning approach.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .evasion_types import EvasionTechnique, EvasionResult
from .encoding_engine import EncodingEngine
from .obfuscation_engine import ObfuscationEngine
from .waf_specific_evasion import WAFSpecificEvasion
from .evasion_engine import EvasionEngine

__all__ = [
    "EvasionTechnique",
    "EvasionResult",
    "EncodingEngine",
    "ObfuscationEngine",
    "WAFSpecificEvasion",
    "EvasionEngine"
]