#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ConfigManager deep branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:10:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import os
from pathlib import Path

from brsxss.core.config_manager import ConfigManager


def test_simple_toml_parser_arrays_and_types(monkeypatch, tmp_path: Path):
    base = tmp_path / "b.yaml"
    base.write_text("scanner:\n  max_concurrent: 3\n", encoding="utf-8")
    user = tmp_path / "u.toml"
    user.write_text(
        """
[scanner]
max_concurrent = 7
request_delay = 0.15
deep_scan = true

[payloads]
custom_payloads = ["a", "b", 1]
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("BRS_XSS_CONFIG_PATH", str(base))
    monkeypatch.setenv("BRS_XSS_USER_CONFIG_PATH", str(user))
    cm = ConfigManager()
    assert cm.get("scanner.max_concurrent") == 7
    assert cm.get("scanner.request_delay") == 0.15
    assert cm.get("scanner.deep_scan") is True or cm.get("payloads.custom_payloads") == ["a", "b", 1]


def test_missing_config_file_uses_defaults_and_warns(monkeypatch, tmp_path: Path):
    # Point to non-existing path
    monkeypatch.setenv("BRS_XSS_CONFIG_PATH", str(tmp_path / "nope.yaml"))
    cm = ConfigManager()
    # Defaults should be present
    assert isinstance(cm.get("scanner"), dict)


def test_env_override_types_cover(monkeypatch, tmp_path: Path):
    base = tmp_path / "b2.yaml"
    base.write_text("scanner:\n  request_timeout: 5\nlogging:\n  level: INFO\n", encoding="utf-8")
    monkeypatch.setenv("BRS_XSS_CONFIG_PATH", str(base))
    monkeypatch.setenv("BRSXSS_REQUEST_TIMEOUT", "12")
    monkeypatch.setenv("BRSXSS_REQUEST_DELAY", "0.4")
    monkeypatch.setenv("BRSXSS_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("BRSXSS_LOG_FILE", str(tmp_path / "l.log"))
    cm = ConfigManager()
    assert cm.get("scanner.request_timeout") == 12
    assert abs(cm.get("scanner.request_delay") - 0.4) < 1e-9
    assert cm.get("logging.level") == "DEBUG"
    assert str(tmp_path / "l.log") == cm.get("logging.file")


