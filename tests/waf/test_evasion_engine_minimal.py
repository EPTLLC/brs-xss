#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - WAF EvasionEngine minimal
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 02:11:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.waf.evasion_engine import EvasionEngine
from brsxss.waf.detector import WAFInfo, WAFType
from brsxss.waf.evasion_types import EvasionTechnique


def test_generate_evasions_generic_and_waf_specific(monkeypatch):
    eng = EvasionEngine()
    payload = "<script>alert(1)</script>"

    # No WAF -> generic + + combined present
    res = eng.generate_evasions(payload, detected_wafs=[], max_variations=10)
    techs = {r.technique for r in res}
    assert EvasionTechnique.URL_ENCODING in techs and EvasionTechnique.JS_OBFUSCATION in techs

    # WAF-specific (Cloudflare) path
    class DummyWAFSpec:
        def cloudflare_evasion(self, p):
            return [p + "_cf"]
        def aws_waf_evasion(self, p):
            return []
        def incapsula_evasion(self, p):
            return []
        def modsecurity_evasion(self, p):
            return []

    monkeypatch.setattr(eng, "waf_specific", DummyWAFSpec())
    cf = WAFInfo(waf_type=WAFType.CLOUDFLARE, name="cf", confidence=0.9, detection_method="t")
    res2 = eng.generate_evasions(payload, detected_wafs=[cf], max_variations=5)
    assert any(r.evaded_payload.endswith("_cf") for r in res2)

    # Learning and stats
    eng.learn_from_success(WAFType.CLOUDFLARE, EvasionTechnique.URL_ENCODING)
    best = eng.get_best_techniques_for_waf(WAFType.CLOUDFLARE)
    assert EvasionTechnique.URL_ENCODING in best
    stats = eng.get_evasion_stats()
    assert stats["total_learned_wafs"] >= 1 and stats["most_successful_technique"]

