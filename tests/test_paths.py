#!/usr/bin/env python3

from brsxss.utils.paths import sanitize_filename, atomic_write, ensure_dir


def test_sanitize_filename_basic():
    assert sanitize_filename('http://example.com/a/b?x=1')
    assert '/' not in sanitize_filename('http://example.com/a/b')
    assert len(sanitize_filename('a'*500)) <= 128


def test_atomic_write(tmp_path):
    target = tmp_path / 'out.json'
    atomic_write(str(target), '{"ok":true}')
    assert target.exists()
    assert target.read_text() == '{"ok":true}'


def test_ensure_dir(tmp_path):
    d = tmp_path / 'a' / 'b' / 'c'
    ensure_dir(str(d))
    assert d.exists() and d.is_dir()


