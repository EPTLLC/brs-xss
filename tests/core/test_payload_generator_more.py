#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - PayloadGenerator Coverage
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:05:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import pytest

from brsxss.core.payload_generator import PayloadGenerator


def test_norm_key_and_cached_behave_consistently():
    gen = PayloadGenerator()

    s1 = "  <ScRiPt> alert(1) </ScRiPt>  "
    s2 = "<script>alert(1)</script>"

    norm1 = gen._norm_key(s1)
    norm2 = gen._norm_key(s2)

    # _norm_key collapses whitespace but preserves single spaces between tokens
    assert norm1 == "<script> alert(1) </script>"
    assert norm2 == "<script>alert(1)</script>"

    # Cached version returns identical output per input
    assert gen._norm_key_cached(s1) == norm1
    assert gen._norm_key_cached(s2) == norm2

    # No duplicates expected across generated pool
    context_info = {"context_type": "html_content"}
    payloads = gen.generate_payloads(context_info, detected_wafs=[], max_payloads=10)
    keys = {gen._norm_key_cached(p.payload) for p in payloads}
    assert len(keys) == len(payloads)


def test_wrap_caps_length_and_sets_metadata():
    from brsxss.core.payload_types import GenerationConfig
    gen = PayloadGenerator(config=GenerationConfig(payload_max_len=10))
    long_payload = "x" * 50
    wrapped = gen._wrap("html_content", long_payload, "Tag", 0.9)
    assert len(wrapped.payload) == 10
    assert wrapped.context_type == "html_content"
    assert wrapped.effectiveness_score == 0.9
    assert wrapped.description == "Tag"


def test_weights_resolution_and_update_config_validation():
    from brsxss.core.payload_types import GenerationConfig, Weights
    # Defaults
    gen_default = PayloadGenerator()
    w = gen_default._get_weights()
    assert w["context_specific"] == 0.92
    # From object
    gen_obj = PayloadGenerator(config=GenerationConfig(weights=Weights(context_specific=0.5)))
    w2 = gen_obj._get_weights()
    assert w2["context_specific"] == 0.5
    # From dict via config attribute override
    gen_obj.config.weights = {"context_specific": 0.33}
    w3 = gen_obj._get_weights()
    assert w3["context_specific"] == 0.33
    # update_config validation error keeps old config
    bad = GenerationConfig(pool_cap=50)  # invalid (<100)
    old = gen_obj.config
    with pytest.raises(ValueError):
        gen_obj.update_config(bad)
    assert gen_obj.config is old


def test_generation_flows_with_mocks(monkeypatch):
    from brsxss.core.payload_types import GenerationConfig, Weights
    # Configure to avoid heavy pools
    cfg = GenerationConfig(
        max_payloads=10,
        max_manager_payloads=2,
        include_evasions=False,
        include_waf_specific=False,
        effectiveness_threshold=0.0,
        weights=Weights(context_specific=0.9, context_matrix=0.8, comprehensive=0.7)
    )
    gen = PayloadGenerator(config=cfg)

    # Mock sources
    monkeypatch.setattr(gen.context_generator, "get_context_payloads", lambda ctx, info: ["A", "A"])  # duplicate
    class DummyMatrix:
        def get_context_payloads(self, *_):
            return ["B"]
        def get_polyglot_payloads(self):
            return []
    gen.context_matrix = DummyMatrix()
    monkeypatch.setattr(gen.payload_manager, "get_all_payloads", lambda: iter(["C1", "C2"]))

    out = gen.generate_payloads({"context_type": "html_content"}, detected_wafs=[], max_payloads=10)
    outs = [p.payload for p in out]
    # Dedup removed duplicate A
    assert outs.count("A") == 1
    # All sources included
    assert any(p == "B" for p in outs)
    assert any(p.startswith("C") for p in outs)


def test_evasion_and_waf_generation(monkeypatch):
    from brsxss.core.payload_types import GenerationConfig, GeneratedPayload
    gen = PayloadGenerator(config=GenerationConfig(include_evasions=True, include_waf_specific=True, max_payloads=10))
    monkeypatch.setattr(gen.context_generator, "get_context_payloads", lambda ctx, info: ["<script>alert(1)</script>"])
    # Reduce other sources to ensure evasion stays within top max_payloads
    monkeypatch.setattr(gen.payload_manager, "get_all_payloads", lambda: iter([]))
    class _EmptyMatrix:
        def get_context_payloads(self, *_):
            return []
        def get_polyglot_payloads(self):
            return []
    gen.context_matrix = _EmptyMatrix()
    # Patch evasion techniques to emit a comment-insertion variant that survives normalization
    monkeypatch.setattr(gen.evasion_techniques, "apply_comment_insertions", lambda payload: [payload.replace("script", "scr/**/ipt")])
    # Keep other techniques minimal
    for name in [
        "apply_url_encoding","apply_html_entity_encoding","apply_unicode_escaping",
        "apply_whitespace_variations","apply_mixed_encoding","apply_case_variations"
    ]:
        monkeypatch.setattr(gen.evasion_techniques, name, lambda payload: [])
    # Patch WAF-specific to a known payload
    monkeypatch.setattr(gen.waf_evasions, "generate_waf_specific_payloads", lambda base, wafs: [
        GeneratedPayload(payload="<!--X-->"+base, context_type="unknown", evasion_techniques=["cloudflare_specific"], effectiveness_score=0.8, description="waf")
    ])
    class DummyWAF:
        class T:
            value = "cloudflare"
        waf_type = T()
    out = gen.generate_payloads({"context_type": "html_content"}, detected_wafs=[DummyWAF()], max_payloads=20)
    outs = [p.payload for p in out]
    assert any("scr/**/ipt" in p for p in outs)  # evasion (comment insertion)
    assert any(p.startswith("<!--X-->") for p in outs)  # waf-specific


def test_blind_xss_behavior(monkeypatch):
    from brsxss.core.payload_types import GenerationConfig, GeneratedPayload
    # Safe mode: no blind payloads added
    gen1 = PayloadGenerator(config=GenerationConfig(include_blind_xss=True, safe_mode=True, max_payloads=5))
    gen1.blind_xss = type("B", (), {"generate_payloads": lambda self, ctx, info: [
        GeneratedPayload(payload="BLIND", context_type=ctx, evasion_techniques=[], effectiveness_score=0.9, description="blind")
    ]})()
    base1 = len(gen1.generate_payloads({"context_type": "html_content"}, detected_wafs=[], max_payloads=5))
    # Not safe mode: blind payloads included
    gen2 = PayloadGenerator(config=GenerationConfig(include_blind_xss=True, safe_mode=False, max_payloads=5))
    gen2.blind_xss = gen1.blind_xss
    base2 = len(gen2.generate_payloads({"context_type": "html_content"}, detected_wafs=[], max_payloads=5))
    assert base2 >= base1


def test_generate_single_payload_and_technique(monkeypatch):
    from brsxss.core.payload_types import EvasionTechnique
    gen = PayloadGenerator()
    monkeypatch.setattr(gen.context_generator, "get_context_payloads", lambda ctx, info: ["<script>alert(1)</script>"])
    monkeypatch.setattr(gen.evasion_techniques, "apply_url_encoding", lambda payload: [payload.replace("(", "%28").replace(")", "%29")])
    res = gen.generate_single_payload({"context_type": "html_content"}, EvasionTechnique.URL_ENCODING)
    assert "%28" in res.payload and "%29" in res.payload
    assert "url_encoding" in res.evasion_techniques[0]


def test_statistics_update_and_reset(monkeypatch):
    from brsxss.core.payload_types import GenerationConfig
    gen = PayloadGenerator(config=GenerationConfig(max_payloads=5))
    monkeypatch.setattr(gen.context_generator, "get_context_payloads", lambda ctx, info: ["A","B","C"]) 
    before = gen.get_statistics()
    out = gen.generate_payloads({"context_type": "html_content"}, detected_wafs=[], max_payloads=5)
    after = gen.get_statistics()
    assert after["total_generated"] == before["total_generated"] + len(out)
    gen.reset_statistics()
    again = gen.get_statistics()
    assert again["total_generated"] == 0


