#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - PayloadGenerator Limits & Stability
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 18:15:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""


from brsxss.core.payload_generator import PayloadGenerator
from brsxss.core.payload_types import GenerationConfig


def test_pool_cap_is_enforced(monkeypatch):
    cfg = GenerationConfig(max_payloads=500, effectiveness_threshold=0.0, pool_cap=100)
    gen = PayloadGenerator(config=cfg)
    # 200 base payloads
    monkeypatch.setattr(
        gen.context_generator,
        "get_context_payloads",
        lambda ctx, info: [f"P{i}" for i in range(200)],
    )
    # No other sources
    monkeypatch.setattr(gen.payload_manager, "get_all_payloads", lambda: iter([]))
    gen.context_matrix = type(
        "M",
        (),
        {"get_context_payloads": lambda *_: [], "get_polyglot_payloads": lambda *_: []},
    )()
    out = gen.generate_payloads(
        {"context_type": "html_content"}, detected_wafs=[], max_payloads=500
    )
    assert len(out) <= 100


def test_evasion_base_limit(monkeypatch):
    cfg = GenerationConfig(
        include_evasions=True,
        max_payloads=50,
        effectiveness_threshold=0.0,
        max_evasion_bases=1,
        evasion_variants_per_tech=1,
    )
    gen = PayloadGenerator(config=cfg)
    # Two bases, but evasion should only apply to first due to limit
    monkeypatch.setattr(
        gen.context_generator,
        "get_context_payloads",
        lambda ctx, info: ["<script>alert(1)</script>", "<script>alert(2)</script>"],
    )
    # Only one technique yields variant (comment insertion creates non-normalizing-equal variant)
    monkeypatch.setattr(
        gen.evasion_techniques,
        "apply_comment_insertions",
        lambda p: [p.replace("script", "scr/**/ipt")],
    )
    for name in [
        "apply_url_encoding",
        "apply_html_entity_encoding",
        "apply_unicode_escaping",
        "apply_whitespace_variations",
        "apply_mixed_encoding",
        "apply_case_variations",
    ]:
        monkeypatch.setattr(gen.evasion_techniques, name, lambda p: [])
    monkeypatch.setattr(gen.payload_manager, "get_all_payloads", lambda: iter([]))
    gen.context_matrix = type(
        "M",
        (),
        {"get_context_payloads": lambda *_: [], "get_polyglot_payloads": lambda *_: []},
    )()
    out = gen.generate_payloads(
        {"context_type": "html_content"}, detected_wafs=[], max_payloads=50
    )
    variants = [p.payload for p in out if "scr/**/ipt" in p.payload]
    # Only one base should receive evasion variant
    assert len(variants) == 1


def test_norm_hash_dedup(monkeypatch):
    cfg = GenerationConfig(
        max_payloads=10,
        effectiveness_threshold=0.0,
        norm_hash=True,
        include_evasions=False,
        include_waf_specific=False,
    )
    gen = PayloadGenerator(config=cfg)
    bases = ["<script>    alert(1)</script>", "<script> alert(1)</script>"]
    monkeypatch.setattr(
        gen.context_generator, "get_context_payloads", lambda ctx, info: bases
    )
    monkeypatch.setattr(gen.payload_manager, "get_all_payloads", lambda: iter([]))
    gen.context_matrix = type(
        "M",
        (),
        {"get_context_payloads": lambda *_: [], "get_polyglot_payloads": lambda *_: []},
    )()
    out = gen.generate_payloads(
        {"context_type": "html_content"}, detected_wafs=[], max_payloads=10
    )
    keys = {gen._norm_key_cached(p.payload) for p in out}
    assert len(out) == len(keys) == 1


def test_empty_sources_stable(monkeypatch):
    cfg = GenerationConfig(max_payloads=10)
    gen = PayloadGenerator(config=cfg)
    monkeypatch.setattr(
        gen.context_generator, "get_context_payloads", lambda ctx, info: []
    )
    monkeypatch.setattr(gen.payload_manager, "get_all_payloads", lambda: iter([]))
    gen.context_matrix = type(
        "M",
        (),
        {"get_context_payloads": lambda *_: [], "get_polyglot_payloads": lambda *_: []},
    )()
    out = gen.generate_payloads(
        {"context_type": "html_content"}, detected_wafs=[], max_payloads=10
    )
    assert isinstance(out, list)


def test_generate_single_payload_none(monkeypatch):
    gen = PayloadGenerator()
    monkeypatch.setattr(
        gen.context_generator, "get_context_payloads", lambda ctx, info: []
    )
    assert gen.generate_single_payload({"context_type": "html_content"}) is None
