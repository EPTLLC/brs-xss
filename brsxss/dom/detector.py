#!/usr/bin/env python3

"""
BRS-XSS DOM Detector

Integrated DOM XSS detector combining all DOM module components.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .scan_result import DOMScanResult
from .javascript_extractor import JavaScriptExtractor
from .dom_detector import DOMXSSDetector

__all__ = [
    "DOMScanResult",
    "JavaScriptExtractor",
    "DOMXSSDetector"
]