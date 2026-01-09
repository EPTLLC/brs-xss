#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - utils.paths additional
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:01:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path
from brsxss.utils.paths import build_result_path, ensure_dir


def test_build_result_path_and_ensure(tmp_path):
    base = tmp_path / "out"
    p = build_result_path(str(base), "https://ex/../a?b", ".json")
    assert p.endswith(".json") and Path(p).name.startswith("ex")
    # ensure_dir should create the base dir
    ensure_dir(str(base))
    assert base.exists()
