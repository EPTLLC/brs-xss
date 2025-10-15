#!/usr/bin/env python3

"""
BRS-XSS Form Parser

HTML form extraction and parsing with field analysis.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .form_field_types import FieldType, FormField
from .extracted_form import ExtractedForm
from .form_extractor import FormExtractor

__all__ = [
    "FieldType",
    "FormField",
    "ExtractedForm",
    "FormExtractor"
]