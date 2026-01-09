#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - payload_types edges
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:53:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest
from brsxss.core.payload_types import GeneratedPayload, PayloadTemplate, ContextType


def test_generated_payload_validation():
    with pytest.raises(ValueError):
        GeneratedPayload(
            payload="",
            context_type="html_content",
            evasion_techniques=[],
            effectiveness_score=0.5,
        )
    with pytest.raises(ValueError):
        GeneratedPayload(
            payload="x",
            context_type="html_content",
            evasion_techniques=[],
            effectiveness_score=2.0,
        )
    ok = GeneratedPayload(
        payload="x",
        context_type="html_content",
        evasion_techniques=None,
        effectiveness_score=0.5,
    )
    assert ok.evasion_techniques == []


def test_payload_template_defaults():
    t = PayloadTemplate(template="<x>", context_type=ContextType.HTML_CONTENT)
    assert t.variables == []
