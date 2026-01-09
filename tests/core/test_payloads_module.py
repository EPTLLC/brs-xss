#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - core.payloads exports
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 19:28:30 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.payloads import (
    PayloadGenerator,
    GeneratedPayload,
    PayloadTemplate,
    GenerationConfig,
    ContextType,
    EvasionTechnique,
    ContextPayloadGenerator,
    EvasionTechniques,
    WAFEvasions,
)


def test_payloads_module_exports():
    assert PayloadGenerator and GeneratedPayload and PayloadTemplate
    assert GenerationConfig and ContextType and EvasionTechnique
    assert ContextPayloadGenerator and EvasionTechniques and WAFEvasions
