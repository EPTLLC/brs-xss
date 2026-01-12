#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 10:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Report Module - All report generation functionality.

Formats:
    - HTML
    - JSON
    - SARIF
    - JUnit
    - PDF
"""

from .report_types import ReportFormat, ReportConfig
from .data_models import VulnerabilityData, ScanStatistics
from .report_generator import ReportGenerator
from .pdf_report import PDFReportGenerator, VulnItem

__all__ = [
    "ReportFormat",
    "ReportConfig",
    "VulnerabilityData",
    "ScanStatistics",
    "ReportGenerator",
    "PDFReportGenerator",
    "VulnItem",
]
