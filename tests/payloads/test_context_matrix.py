#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - payloads.context_matrix
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:20:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.detect.payloads.context_matrix import ContextMatrix, Context


def test_context_matrix_stats_and_accessors():
    cm = ContextMatrix()
    assert cm.get_context_payloads(Context.HTML)
    assert cm.get_polyglot_payloads()
    assert cm.get_aggr_payloads()
    assert Context.HTML in cm.get_all_contexts()
    assert cm.get_payload_count(Context.HTML) > 0
    stats = cm.get_total_payload_count()
    assert (
        stats["context_specific"] > 0
        and stats["polyglot"] > 0
        and stats["aggressive"] > 0
    )
