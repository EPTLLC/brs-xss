#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - logger edge branches
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:40:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

import logging
from brsxss.utils.logger import Logger


def test_color_formatter_levels_dont_crash(caplog):
    log = Logger("t.edge", level="DEBUG")
    with caplog.at_level(logging.DEBUG):
        log.debug("d")
        log.info("i")
        log.warning("w")
        log.error("e")
        log.critical("c")
        log.success("s")
    assert caplog.records


