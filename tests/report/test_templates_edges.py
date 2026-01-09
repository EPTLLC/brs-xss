#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - templates edge branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:33:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.report.templates import HTMLTemplate


def test_html_template_no_vulns_section_presence():
    t = HTMLTemplate()
    out = t.generate(
        {"vulnerabilities": [], "statistics": {}, "target_info": {"url": "u"}}
    )
    assert "Total Vulnerabilities" in out and "Vulnerabilities Found" not in out
