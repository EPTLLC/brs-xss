#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 26 Oct 2025 14:15:00 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

__version__ = "2.1.1"
__author__ = "Brabus"
__contact__ = "https://t.me/EasyProTech"
__license__ = "MIT"
__description__ = "Context-aware async XSS scanner for CI/CD"

# Core components
from .core import ConfigManager, HTTPClient, XSSScanner, MLIntegration
from .dom import DOMAnalyzer, DOMVulnerability
from .ml import MLPredictor, PredictionResult
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
    "__version__", "__author__", "__email__", "__license__", "__description__",
    
    # Core components
    "ConfigManager", "HTTPClient", "XSSScanner", "MLIntegration",
    
    # DOM analysis
    "DOMAnalyzer", "DOMVulnerability",
    
    # Machine Learning
    "MLPredictor", "PredictionResult",
    
    # Reporting
    "ReportGenerator", "ReportFormat",
    
    # WAF handling
    "WAFDetector", "EvasionEngine",
    
    # Web crawling
    "CrawlerEngine", "FormExtractor",
    
    # Utilities
    "Logger", "URLValidator",
    
    # Terminal-only mode (API & GUI removed)
    
    # Internationalization
    "_"
]