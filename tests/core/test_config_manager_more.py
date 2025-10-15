#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ConfigManager extended
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 19:03:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import os
from pathlib import Path

from brsxss.core.config_manager import ConfigManager


def test_env_overrides_and_get_set_update(monkeypatch, tmp_path: Path):
    # Create minimal YAML config file
    cfg_file = tmp_path / "default.yaml"
    cfg_file.write_text("scanner:\n  max_depth: 2\nreporting:\n  format: html\n", encoding="utf-8")

    monkeypatch.setenv("BRS_XSS_CONFIG_PATH", str(cfg_file))
    monkeypatch.setenv("BRSXSS_MAX_DEPTH", "5")
    monkeypatch.setenv("BRSXSS_OUTPUT_FORMAT", "json")

    cm = ConfigManager()
    assert cm.get("scanner.max_depth") == 5
    assert cm.get("reporting.format") == "json"

    cm.set("scanner.request_timeout", 7)
    assert cm.get("scanner.request_timeout") == 7
    cm.update({"logging.level": "DEBUG"})
    assert cm.get("logging.level") == "DEBUG"


def test_user_toml_merge_and_save_reload(monkeypatch, tmp_path: Path):
    base = tmp_path / "base.yaml"
    base.write_text("scanner:\n  max_urls: 10\n", encoding="utf-8")
    user = tmp_path / "user.toml"
    user.write_text("""
[scanner]
max_urls = 25
request_delay = 0.2
""".strip(), encoding="utf-8")

    monkeypatch.setenv("BRS_XSS_CONFIG_PATH", str(base))
    monkeypatch.setenv("BRS_XSS_USER_CONFIG_PATH", str(user))

    cm = ConfigManager()
    assert cm.get("scanner.max_urls") == 25
    assert cm.get("scanner.request_delay") == 0.2

    # Save and reload cycle
    out = tmp_path / "out.yaml"
    cm.save(str(out))
    assert out.exists()
    cm2 = ConfigManager(str(out))
    assert cm2.get("scanner.max_urls") == 25


def test_validate_and_summary(tmp_path: Path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("scanner:\n  max_depth: 0\n  max_urls: 0\n  request_timeout: 0\n  request_delay: -1\nlogging:\n  level: BAD\nreporting:\n  format: bad\n", encoding="utf-8")
    cm = ConfigManager(str(cfg))
    errs = cm.validate()
    assert any("must be >= 1" in e or "one of" in e for e in errs)
    summary = cm.get_config_summary()
    assert "sections" in summary and isinstance(summary["sections"], list)


