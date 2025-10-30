#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - i18n messages and _
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 21:00:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss import _
from brsxss.i18n.messages import Messages


def test_messages_get_and_formatting():
    m = Messages()
    assert m.get("scan.started", "d").startswith("Started")
    assert m.get("unknown.key", "fallback") == "fallback"

    # translation helper _ uses Messages under the hood
    s = _("scan.completed", duration=1.23)
    assert "completed" in s


