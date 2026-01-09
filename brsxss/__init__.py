#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Beta - v4.0.0-beta.1
Telegram: https://t.me/EasyProTech
"""

# Import version from single source of truth
from .version import VERSION as __version__
from .version import VERSION_STRING, USER_AGENT, BUILD_INFO

__author__ = "Brabus"
__contact__ = "https://t.me/EasyProTech"
__license__ = "MIT"
__description__ = "Context-aware async XSS scanner powered by BRS-KB"

# Core components
from .core import ConfigManager, HTTPClient, XSSScanner
from .dom import DOMAnalyzer, DOMVulnerability
from .report import ReportGenerator, ReportFormat
from .waf import WAFDetector, EvasionEngine
from .crawler import CrawlerEngine, FormExtractor
from .utils import Logger, URLValidator

# API and GUI removed - terminal-only mode
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
