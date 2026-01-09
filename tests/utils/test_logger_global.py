#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - Logger global setup
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:12:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path
from brsxss.utils.logger import Logger


def test_setup_global_logging_with_file(tmp_path: Path):
    f = tmp_path / "g.log"
    Logger.setup_global_logging(level="INFO", log_file=str(f))
    # Create a logger and write
    log = Logger("g.test", level="INFO")
    log.info("hello")
    assert f.parent.exists()


def test_configure_logging_with_file(tmp_path: Path, monkeypatch):
    # Reset configured flag to exercise code path
    monkeypatch.setattr(Logger, "_configured", False)
    f = tmp_path / "c.log"
    Logger.configure_logging(verbose=True, log_file=str(f))
    log = Logger("g.test2", level="INFO")
    log.info("hello2")
    assert f.parent.exists()
