#!/usr/bin/env python3

"""
BRS-XSS Report Module

Reporting system with support for multiple formats.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .report_types import ReportFormat, ReportConfig
from .data_models import VulnerabilityData, ScanStatistics
from .report_generator import ReportGenerator

__all__ = [
    "ReportFormat",
    "ReportConfig",
    "VulnerabilityData", 
    "ScanStatistics",
    "ReportGenerator"
]