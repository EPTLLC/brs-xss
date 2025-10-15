#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - utils.paths
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:33:00 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import os
from brsxss.utils.paths import sanitize_filename, atomic_write


def test_sanitize_filename_basic_and_max_len():
    # Protocols are stripped
    assert sanitize_filename("https://example.com/a/b") == "example.com_a_b"
    assert sanitize_filename("http://example.com//a///b") == "example.com_a_b"

    # Invalid characters replaced and collapsed underscores
    s = "exa mple:com/a*b?c|<d>e\\f\n"
    out = sanitize_filename(s)
    assert " " not in out and ":" not in out and "?" not in out
    assert "__" not in out

    # Max length respected
    long = "x" * 300
    out2 = sanitize_filename(long, max_len=50)
    assert len(out2) <= 50 and out2 != ""


def test_atomic_write_replaces_safely(tmp_path):
    target = tmp_path / "file.txt"
    # initial write
    atomic_write(str(target), "v1")
    assert target.read_text() == "v1"

    # replace with new content
    atomic_write(str(target), "v2")
    assert target.read_text() == "v2"

    # ensure no temp leftovers in directory
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith("file_") and p.suffix == ".txt"]
    assert leftovers == []
