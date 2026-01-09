#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - ConfigManager edge branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:31:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import yaml
from pathlib import Path

from brsxss.core.config_manager import ConfigManager


def test_simple_toml_parser_edges(monkeypatch, tmp_path: Path):
    base = tmp_path / "b.yaml"
    base.write_text("scanner:\n  max_urls: 5\n", encoding="utf-8")
    user = tmp_path / "u.toml"
    user.write_text(
        """
# comment line
[section]
key = "value" # trailing comment

[flags]
x = false
y = true

[numbers]
i = 42
f = 3.14

[arr]
items = ["a", 2, 3.0] # mixed
bad = # invalid -> ignored
noeq
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("BRS_XSS_CONFIG_PATH", str(base))
    monkeypatch.setenv("BRS_XSS_USER_CONFIG_PATH", str(user))
    cm = ConfigManager()
    assert cm.get("section.key") == "value"
    assert cm.get("flags.x") is False and cm.get("flags.y") is True
    assert cm.get("numbers.i") == 42 and abs(cm.get("numbers.f") - 3.14) < 1e-9
    assert cm.get("arr.items") == ["a", 2, 3.0]


def test_set_nested_and_get_default(tmp_path: Path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("{}", encoding="utf-8")
    cm = ConfigManager(str(cfg))
    assert cm.get("unknown.path", default=123) == 123
    cm.set("a.b.c", 1)
    assert cm.get("a.b.c") == 1


def test_reload_and_save_exception(monkeypatch, tmp_path: Path):
    cfg = tmp_path / "c2.yaml"
    cfg.write_text("scanner:\n  max_depth: 2\n", encoding="utf-8")
    cm = ConfigManager(str(cfg))
    cm.set("scanner.max_depth", 3)
    # Force yaml.dump to raise to cover error path
    monkeypatch.setattr(
        yaml, "dump", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("yaml boom"))
    )
    try:
        cm.save()  # should not crash
    except RuntimeError:
        assert False, "save should handle yaml exception"
    # Reload should work
    cm.reload()
    assert isinstance(cm.get("scanner"), dict)
