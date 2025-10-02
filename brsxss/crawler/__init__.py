#!/usr/bin/env python3

"""
BRS-XSS Crawler Module

Asynchronous web crawler with form extraction and URL discovery.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .scope import ScopeManager, ScopeRule
from .form_parser import FieldType, FormField, ExtractedForm, FormExtractor
from .url_discovery import URLType, DiscoveredURL, URLDiscovery
from .engine import CrawlConfig, CrawlResult, CrawlerEngine

__all__ = [
    "ScopeManager",
    "ScopeRule",
    "FieldType",
    "FormField",
    "ExtractedForm", 
    "FormExtractor",
    "URLType",
    "DiscoveredURL",
    "URLDiscovery",
    "CrawlConfig",
    "CrawlResult",
    "CrawlerEngine"
]