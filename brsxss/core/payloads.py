#!/usr/bin/env python3

"""
BRS-XSS Payloads Module

Exports for payload generation system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Вс 10 авг 2025 19:31:00 MSK
Telegram: https://t.me/EasyProTech
"""

from .payload_generator import PayloadGenerator
from .payload_types import (
    GeneratedPayload,
    PayloadTemplate,
    GenerationConfig,
    ContextType,
    EvasionTechnique
)
from .context_payloads import ContextPayloadGenerator
from .evasion_techniques import EvasionTechniques
from .waf_evasions import WAFEvasions

__all__ = [
    "PayloadGenerator",
    "GeneratedPayload",
    "PayloadTemplate",
    "GenerationConfig",
    "ContextType",
    "EvasionTechnique",
    "ContextPayloadGenerator",
    "EvasionTechniques",
    "WAFEvasions"
]