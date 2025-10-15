#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - PayloadGenerator Blind XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:18:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.payload_generator import PayloadGenerator
from brsxss.core.payload_types import GenerationConfig


def test_blind_with_explicit_webhook_in_safe_mode(monkeypatch):
    webhook = "https://my-webhook.com/x"
    cfg = GenerationConfig(include_blind_xss=True, safe_mode=True, max_payloads=20)
    gen = PayloadGenerator(config=cfg, blind_xss_webhook=webhook)
    # Some base to avoid empty pool
    monkeypatch.setattr(gen.context_generator, "get_context_payloads", lambda ctx, info: ["BASE"]) 
    out = gen.generate_payloads({"context_type": "html_content"}, detected_wafs=[], max_payloads=20)
    payloads = [p.payload for p in out]
    assert any("my-webhook.com" in p for p in payloads)


def test_no_blind_when_safe_mode_without_webhook(monkeypatch):
    cfg = GenerationConfig(include_blind_xss=True, safe_mode=True, max_payloads=20)
    gen = PayloadGenerator(config=cfg)
    monkeypatch.setattr(gen.context_generator, "get_context_payloads", lambda ctx, info: ["BASE"]) 
    out = gen.generate_payloads({"context_type": "html_content"}, detected_wafs=[], max_payloads=20)
    payloads = [p.payload for p in out]
    # Blind payloads contain id= in query
    assert not any("id=" in p and "?" in p for p in payloads)


def test_blind_when_not_safe_mode_with_manager(monkeypatch):
    cfg = GenerationConfig(include_blind_xss=True, safe_mode=False, max_payloads=20)
    gen = PayloadGenerator(config=cfg)
    monkeypatch.setattr(gen.context_generator, "get_context_payloads", lambda ctx, info: ["BASE"]) 
    # Inject dummy manager
    class DummyBlind:
        def generate_payloads(self, ctx, info):
            return ["BLIND_PAYLOAD"]
    gen.blind_xss = DummyBlind()
    out = gen.generate_payloads({"context_type": "html_content"}, detected_wafs=[], max_payloads=20)
    assert any(p.payload == "BLIND_PAYLOAD" for p in out)


