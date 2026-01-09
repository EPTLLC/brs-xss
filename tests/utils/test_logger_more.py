#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - utils.logger more
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:02:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.utils.logger import Logger


def test_logger_set_level_and_configure_logging():
    log = Logger("t.more", level="WARNING")
    log.set_level("DEBUG")
    log.debug("dbg")
    # configure_logging should be idempotent
    Logger.configure_logging(verbose=False)
    Logger.configure_logging(verbose=True)
