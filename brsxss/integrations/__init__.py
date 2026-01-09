"""
BRS-XSS Integrations
Telegram notifications and PDF reports

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
"""

from .telegram_bot import TelegramBot, TelegramConfig
from .pdf_report import PDFReportGenerator, VulnItem

__all__ = ["TelegramBot", "TelegramConfig", "PDFReportGenerator", "VulnItem"]
