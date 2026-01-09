#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - PayloadGenerator tail branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 19:40:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.payload_generator import PayloadGenerator
from brsxss.core.payload_types import GenerationConfig, EvasionTechnique


def _cfg(**kw):
    base = GenerationConfig()
    for k, v in kw.items():
        setattr(base, k, v)
    return base


def test_context_generator_exception_path(monkeypatch):
    gen = PayloadGenerator(config=_cfg(max_payloads=5))

    def boom(ctx, info):
        raise RuntimeError("x")

    monkeypatch.setattr(gen.context_generator, "get_context_payloads", boom)
    out = gen.generate_payloads(
        {"context_type": "html_content"}, detected_wafs=[], max_payloads=5
    )
    assert isinstance(out, list)


def test_aggressive_matrix_and_pool_cap(monkeypatch):
    cfg = _cfg(max_payloads=50)
    setattr(cfg, "enable_aggressive", True)
    setattr(cfg, "pool_cap", 100)
    gen = PayloadGenerator(config=cfg)

    # Over-inflate managers to test cap
    class DummyMgr:
        def get_all_payloads(self):
            for i in range(1000):
                yield f"P{i}"

    gen.payload_manager = DummyMgr()
    out = gen.generate_payloads(
        {"context_type": "html_content"}, detected_wafs=[], max_payloads=50
    )
    assert len(out) <= 50


def test_specific_technique_application(monkeypatch):
    gen = PayloadGenerator(config=_cfg(max_payloads=5))
    monkeypatch.setattr(
        gen.context_generator,
        "get_context_payloads",
        lambda c, i: ["<script>alert(1)</script>"],
    )
    r = gen.generate_single_payload(
        {"context_type": "html_content"}, technique=EvasionTechnique.URL_ENCODING
    )
    assert r and "%3C" in r.payload or "%3c" in r.payload


def test_bulk_generation_quota_and_error(monkeypatch):
    cfg = _cfg(max_payloads=9)
    gen = PayloadGenerator(config=cfg)

    # First ok, second raises
    def get_ctx(ctx, info):
        if ctx == "html_content":
            return ["A"]
        raise ValueError("boom")

    monkeypatch.setattr(gen.context_generator, "get_context_payloads", get_ctx)
    res = gen.bulk_generate_payloads(
        [{"context_type": "html_content"}, {"context_type": "javascript"}]
    )
    assert set(res.keys()) == {"html_content", "javascript"}
    assert len(res["html_content"]) <= cfg.max_payloads // 2
    # javascript still receives polyglot matrix payloads despite context error
    assert res["javascript"]
    assert all(
        p.description in ("Context-matrix", "Comprehensive") for p in res["javascript"]
    )


def test_bulk_generation_catches_waf_exception(monkeypatch):
    cfg = _cfg(max_payloads=6)
    gen = PayloadGenerator(config=cfg)
    # Force waf-specific stage to raise
    monkeypatch.setattr(
        gen.waf_evasions,
        "generate_waf_specific_payloads",
        lambda base, wafs: (_ for _ in ()).throw(RuntimeError("waf boom")),
    )
    out = gen.bulk_generate_payloads(
        [
            {"context_type": "html_content"},
        ],
        detected_wafs=[object()],
    )
    # Should catch and return empty list for the context
    assert out["html_content"] == []


def test_evasion_exception_is_logged(monkeypatch):
    cfg = _cfg(max_payloads=5)
    gen = PayloadGenerator(config=cfg)
    monkeypatch.setattr(
        gen.context_generator,
        "get_context_payloads",
        lambda c, i: ["<svg onload=alert(1)>"],
    )
    # Break one technique
    monkeypatch.setattr(
        gen.evasion_techniques,
        "apply_case_variations",
        lambda s: (_ for _ in ()).throw(RuntimeError("evasion boom")),
    )
    res = gen.generate_payloads(
        {"context_type": "html_content"}, detected_wafs=[], max_payloads=5
    )
    assert res  # other techniques still produce results


def test_high_threshold_filters_out_all(monkeypatch):
    cfg = _cfg(max_payloads=5)
    setattr(cfg, "effectiveness_threshold", 0.99)
    gen = PayloadGenerator(config=cfg)
    monkeypatch.setattr(
        gen.context_generator, "get_context_payloads", lambda c, i: ["A"]
    )
    res = gen.generate_payloads(
        {"context_type": "html_content"}, detected_wafs=[], max_payloads=5
    )
    assert res == []


def test_blind_context_mapping(monkeypatch):
    cfg = _cfg(max_payloads=5)
    setattr(cfg, "include_blind_xss", True)
    setattr(cfg, "safe_mode", False)
    gen = PayloadGenerator(config=cfg)

    # Inject dummy blind manager
    class DummyBlind:
        def generate_blind_payloads(self, ctx):
            return [f"BLIND-{ctx}"]

    gen.blind_xss = DummyBlind()
    for ctx_in, ctx_out in [
        ("html_content", "html"),
        ("html_attribute", "attribute"),
        ("javascript", "javascript"),
        ("css", "css"),
        ("unknown", "html"),
    ]:
        res = gen.generate_payloads(
            {"context_type": ctx_in}, detected_wafs=[], max_payloads=5
        )
        texts = [p.payload for p in res]
        assert any(f"BLIND-{ctx_out}" in t for t in texts)


def test_private_helpers_and_update_config_errors():
    cfg = _cfg(max_payloads=5)
    gen = PayloadGenerator(config=cfg)
    # _safe_list
    assert gen._safe_list(None) == []
    assert gen._safe_list((x for x in [1, 2])) == [1, 2]
    # _apply_specific_technique fallback
    assert gen._apply_specific_technique("X", None) == ["X"]
    # update_config rollback on invalid config
    bad = _cfg(max_payloads=5)
    setattr(bad, "pool_cap", 50)  # invalid (<100)
    old = gen.config
    try:
        gen.update_config(bad)
        assert False, "Expected ValueError"
    except ValueError:
        pass
    assert gen.config is old
