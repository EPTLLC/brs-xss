#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - SimilarityMatcher
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 00:28:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.core.similarity_matcher import SimilarityMatcher


def test_find_similar_reflections_exact_partial_fuzzy_and_threshold():
    m = SimilarityMatcher(threshold=0.6)
    hay = "__prefix__hello world__suffix__"
    # exact
    res_exact = m.find_similar_reflections("hello", hay)
    assert any(score == 1.0 and match == "hello" for _, match, score in res_exact)
    # no exact -> partial
    res_partial = m.find_similar_reflections("hellox", "xxheLLo world", min_length=3)
    assert any(match.lower() == "hello"[: len(match)] for _, match, _ in res_partial)
    # no exact/partial -> fuzzy (use high threshold to force fuzzy)
    # choose strings with no partial contiguous substrings >=3 to force fuzzy
    mf = SimilarityMatcher(threshold=0.6)
    res_fuzzy = mf.find_similar_reflections("abcde", "axcye", min_length=3)
    assert any(score >= 0.6 for _, __, score in res_fuzzy)
    # below min_length returns empty
    assert m.find_similar_reflections("hi", hay, min_length=3) == []


def test_encoded_reflections_and_encoders():
    m = SimilarityMatcher()
    needle = "<script>"
    hay = " ".join(
        [
            m._url_encode(needle),
            m._html_entity_encode(needle),
            m._hex_escape(needle),
        ]
    )
    enc = m.find_encoded_reflections(needle, hay)
    kinds = {k for _, _, k in enc}
    assert (
        "url_encoding" in kinds and "html_entities" in kinds and "hex_escape" in kinds
    )


def test_calculate_reflection_quality_metrics():
    m = SimilarityMatcher()
    q0 = m.calculate_reflection_quality("", "")
    assert q0["similarity"] == 0.0 and q0["completeness"] == 0.0
    q1 = m.calculate_reflection_quality("abc", "abc")
    assert (
        q1["similarity"] == 1.0 and q1["completeness"] == 1.0 and q1["accuracy"] == 1.0
    )
    q2 = m.calculate_reflection_quality("abcdef", "abc")
    assert (
        0.0 < q2["similarity"] < 1.0
        and 0.0 < q2["completeness"] <= 1.0
        and 0.0 < q2["char_preservation"] <= 1.0
    )
