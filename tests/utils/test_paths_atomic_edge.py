#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - paths.atomic_write edge
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:13:30 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import os
from pathlib import Path

from brsxss.utils.paths import atomic_write


def test_atomic_write_cleans_tmp_on_exception(monkeypatch, tmp_path: Path):
    target = tmp_path / "a.txt"
    # Spy on os.replace to raise once, then ensure temp gets cleaned
    orig_replace = os.replace
    calls = {"n": 0}

    def bad_replace(src, dst):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("boom")
        return orig_replace(src, dst)

    monkeypatch.setattr(os, "replace", bad_replace)
    try:
        try:
            atomic_write(str(target), "x")
        except OSError:
            pass
        # Second attempt should work
        atomic_write(str(target), "x")
    finally:
        monkeypatch.setattr(os, "replace", orig_replace)
    assert target.exists() and target.read_text(encoding="utf-8") == "x"
