#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - JS extractor file branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 04:05:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import builtins

from brsxss.detect.xss.dom.javascript_extractor import JavaScriptExtractor


def test_extract_from_file_js(tmp_path):
    p = tmp_path / "code.js"
    p.write_text("console.log('a')", encoding="utf-8")
    blocks = JavaScriptExtractor.extract_from_file(str(p))
    assert blocks and blocks[0][1] == "js_file"


def test_extract_from_file_html(tmp_path):
    p = tmp_path / "page.html"
    p.write_text("<script>alert(1)</script>", encoding="utf-8")
    blocks = JavaScriptExtractor.extract_from_file(str(p))
    kinds = {ctx for _, ctx in blocks}
    assert "inline_script" in kinds


def test_extract_from_file_php_as_html(tmp_path):
    p = tmp_path / "index.php"
    p.write_text("<?php echo '<script>x()</script>'; ?>", encoding="utf-8")
    blocks = JavaScriptExtractor.extract_from_file(str(p))
    kinds = {ctx for _, ctx in blocks}
    assert "inline_script" in kinds


def test_extract_from_file_unknown_with_no_js(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("no js here", encoding="utf-8")
    blocks = JavaScriptExtractor.extract_from_file(str(p))
    assert blocks and blocks[0][1] == "unknown"


def test_extract_from_file_error(monkeypatch):
    # Simulate exception in open()
    def boom(*args, **kwargs):
        raise OSError("boom")

    monkeypatch.setattr(builtins, "open", boom)
    # Any path will do; method should swallow and return []
    assert JavaScriptExtractor.extract_from_file("/nonexistent.xyz") == []
