"""
BRS-XSS Integrations
Telegram notifications

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 10:00 UTC
Telegram: https://t.me/EasyProTech

Note: PDF reports moved to brsxss.report.pdf_report
"""

from .telegram_bot import TelegramBot, TelegramConfig

# Re-export from new location for backward compatibility
from ..report.pdf_report import PDFReportGenerator, VulnItem

__all__ = ["TelegramBot", "TelegramConfig", "PDFReportGenerator", "VulnItem"]
