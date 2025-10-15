#!/usr/bin/env python3

"""
BRS-XSS Payload Library

XSS payload collection with broad coverage.
Organized by context, evasion technique, and target type.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Вс 10 авг 2025 19:35:00 MSK
Telegram: https://t.me/EasyProTech
"""

from .basic_xss import BasicXSSPayloads
from .advanced_xss import AdvancedXSSPayloads
from .context_specific import ContextSpecificPayloads
from .waf_bypass import WAFBypassPayloads
from .dom_xss import DOMXSSPayloads
from .filter_evasion import FilterEvasionPayloads
from .encoding_payloads import EncodingPayloads
from .polyglot_payloads import PolyglotPayloads
from .blind_xss import BlindXSSPayloads
from .framework_specific import FrameworkSpecificPayloads
from .payload_manager import PayloadManager

__all__ = [
    "BasicXSSPayloads",
    "AdvancedXSSPayloads", 
    "ContextSpecificPayloads",
    "WAFBypassPayloads",
    "DOMXSSPayloads",
    "FilterEvasionPayloads",
    "EncodingPayloads",
    "PolyglotPayloads",
    "BlindXSSPayloads",
    "FrameworkSpecificPayloads",
    "PayloadManager"
]