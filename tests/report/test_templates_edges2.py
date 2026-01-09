#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - templates additional edges
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:41:30 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import json
from brsxss.report.templates import JSONTemplate


def test_json_template_summary_defaults():
    t = JSONTemplate()
    out = json.loads(t.generate_summary({"statistics": {}}))
    assert "scan_summary" in out and "timestamp" in out
