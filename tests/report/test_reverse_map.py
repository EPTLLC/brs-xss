#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - Knowledge Base reverse_map
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27
Status: Updated - Uses BRS-KB as single source of truth
Telegram: https://t.me/EasyProTech
"""

# BRS-KB is the single source of truth
from brs_kb.reverse_map import (
    find_contexts_for_payload,
    get_defenses_for_context,
    get_defense_info,
    find_payload_bypasses,
    reverse_lookup,
)


def test_reverse_map_apis():
    ctx = find_contexts_for_payload("<script>alert(1)</script>")
    assert "contexts" in ctx and "severity" in ctx

    defs_html = get_defenses_for_context("html_content")
    assert isinstance(defs_html, list)

    info = get_defense_info("csp")
    assert "effective_against" in info

    bypasses = find_payload_bypasses("<svg onload=alert(1)>")
    assert isinstance(bypasses, list)

    rl1 = reverse_lookup("payload", "javascript:alert(1)")
    rl2 = reverse_lookup("context", "url")  # Updated to new context name
    rl3 = reverse_lookup("defense", "sanitization")
    rl4 = reverse_lookup("unknown", "x")
    assert (
        isinstance(rl1, dict)
        and isinstance(rl2, dict)
        and isinstance(rl3, dict)
        and rl4 == {}
    )
