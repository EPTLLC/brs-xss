#!/usr/bin/env python3

"""
Project: BRS-XSS Tests for PayloadGenerator
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 17:15:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest
from brsxss.core.payload_generator import PayloadGenerator
from brsxss.waf.models import WAF, WAFBrand


@pytest.fixture
def generator():
    """Provides a PayloadGenerator instance for tests."""
    return PayloadGenerator()


def test_generates_for_html_context(generator):
    """
    Test that the generator produces a valid set of payloads for a standard HTML context.
    """
    context_info = {"context_type": "html_content"}
    payloads = generator.generate_payloads(context_info, detected_wafs=[])

    assert len(payloads) > 50  # Should generate a substantial number of payloads

    # Check for presence of basic HTML payloads
    payload_strings = [p.payload for p in payloads]
    assert any("<script>" in p for p in payload_strings)
    assert any("<img src=x onerror" in p for p in payload_strings)


def test_generates_for_js_context(generator):
    """
    Test that the generator produces JS-specific payloads for a JavaScript context.
    """
    context_info = {"context_type": "js_string"}
    payloads = generator.generate_payloads(context_info, detected_wafs=[])

    assert len(payloads) > 20

    # Check for presence of JS-specific payloads
    payload_strings = [p.payload for p in payloads]
    assert any("';alert" in p for p in payload_strings)  # Breaking out of a string
    assert any("Function(" in p for p in payload_strings)


def test_generates_waf_bypass_payloads(generator):
    """
    Test that WAF-specific bypasses are included when a WAF is detected.
    """
    context_info = {"context_type": "html_content"}
    mock_waf = WAF(brand=WAFBrand.CLOUDFLARE, name="Cloudflare")

    payloads = generator.generate_payloads(context_info, detected_wafs=[mock_waf])

    payload_strings = [p.payload for p in payloads]

    # Check that it includes both normal payloads and WAF bypasses
    assert any("<script>" in p for p in payload_strings)
    # Check for a known Cloudflare bypass technique
    assert any("<!--" in p and "-->" in p for p in payload_strings)


def test_generates_blind_xss_payloads():
    """
    Test that blind XSS payloads are generated with the correct callback URL.
    """
    webhook = "https://my-webhook.com/xss"
    generator = PayloadGenerator(blind_xss_webhook=webhook)

    context_info = {"context_type": "html_content"}
    payloads = generator.generate_payloads(context_info, detected_wafs=[])

    payload_strings = [p.payload for p in payloads]
    assert any(webhook in p for p in payload_strings)


def test_generates_polyglot_payloads_for_unknown_context(generator):
    """
    Test that polyglot payloads are returned for an unknown context.
    """
    context_info = {"context_type": "some_weird_unknown_context"}
    payloads = generator.generate_payloads(context_info, detected_wafs=[])

    payload_strings = [p.payload for p in payloads]

    # Check for a known polyglot payload
    assert any("javascript:/*--></title></style>" in p for p in payload_strings)
