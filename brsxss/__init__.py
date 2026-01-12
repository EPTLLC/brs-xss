#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 10:00 UTC
Status: Beta
Telegram: https://t.me/EasyProTech
"""

# Import version from single source of truth
from .version import VERSION as __version__
from .version import VERSION_STRING, USER_AGENT, BUILD_INFO

__author__ = "Brabus"
__contact__ = "https://t.me/EasyProTech"
__license__ = "MIT"
__description__ = "Context-aware async XSS scanner powered by BRS-KB"

# Core components - from new detect/ structure
from .detect.xss.reflected import ConfigManager, HTTPClient, XSSScanner
from .detect.xss.dom import DOMAnalyzer, DOMVulnerability
from .detect.waf import WAFDetector, EvasionEngine
from .detect.crawler import CrawlerEngine, FormExtractor

# Reporting
from .report import ReportGenerator, ReportFormat

# Utilities
from .utils import Logger, URLValidator

# Internationalization
from .i18n.messages import Messages

# Initialize internationalization
_messages = Messages()


def _(message_key: str, **kwargs) -> str:
    """
    Translation function for internationalization.

    Args:
        message_key: Message key in format "category.key"
        **kwargs: Parameters for string formatting

    Returns:
        Translated and formatted message
    """
    message = _messages.get(message_key, message_key)
    if kwargs:
        try:
            return message.format(**kwargs)
        except (KeyError, ValueError):
            return message
    return message


__all__ = [
    # Metadata
    "__version__",
    "__author__",
    "__contact__",
    "__license__",
    "__description__",
    "VERSION_STRING",
    "USER_AGENT",
    "BUILD_INFO",
    # Core components
    "ConfigManager",
    "HTTPClient",
    "XSSScanner",
    # DOM analysis
    "DOMAnalyzer",
    "DOMVulnerability",
    # Reporting
    "ReportGenerator",
    "ReportFormat",
    # WAF handling
    "WAFDetector",
    "EvasionEngine",
    # Web crawling
    "CrawlerEngine",
    "FormExtractor",
    # Utilities
    "Logger",
    "URLValidator",
    # Internationalization
    "_",
]
