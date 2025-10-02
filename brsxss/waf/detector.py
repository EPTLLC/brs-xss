#!/usr/bin/env python3

"""
BRS-XSS WAF Detector

Web Application Firewall detection system with ML support.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .waf_types import WAFType, WAFInfo
from .detection_engine import WAFDetectionEngine
from .waf_detector import WAFDetector

__all__ = [
    "WAFType",
    "WAFInfo",
    "WAFDetectionEngine",
    "WAFDetector"
]