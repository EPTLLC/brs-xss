#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ConfigManager tails
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:04:30 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path
from brsxss.core.config_manager import ConfigManager


def test_get_section_and_has_and_summary(tmp_path: Path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("logging:\n  level: INFO\n", encoding="utf-8")
    cm = ConfigManager(str(cfg))
    sec = cm.get_section("logging")
    assert isinstance(sec, dict) and cm.has("logging.level")
    s = cm.get_config_summary()
    assert "config_exists" in s


