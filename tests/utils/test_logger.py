#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - utils.logger
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 19:05:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from pathlib import Path
from brsxss.utils.logger import Logger, get_logger


def test_logger_basic_and_file(tmp_path: Path):
    log = Logger("t.logger", level="INFO")
    log.debug("d")
    log.info("i")
    log.warning("w")
    log.error("e")
    log.success("s")

    fp = tmp_path / "x.log"
    log.add_file_handler(str(fp), level="INFO")
    log.info("to_file")
    assert fp.exists()

    gl = get_logger("g.logger")
    gl.set_level("ERROR")
    gl.error("boom")


