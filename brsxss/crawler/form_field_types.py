#!/usr/bin/env python3

"""
BRS-XSS Form Field Types

Data structures for HTML form fields and types.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class FieldType(Enum):
    """HTML form field types"""
    TEXT = "text"
    PASSWORD = "password"
    EMAIL = "email"
    HIDDEN = "hidden"
    SUBMIT = "submit"
    BUTTON = "button"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    SELECT = "select"
    TEXTAREA = "textarea"
    FILE = "file"
    NUMBER = "number"
    URL = "url"
    TEL = "tel"
    SEARCH = "search"
    DATE = "date"
    TIME = "time"
    DATETIME = "datetime-local"
    MONTH = "month"
    WEEK = "week"
    COLOR = "color"
    RANGE = "range"


@dataclass
class FormField:
    """HTML form field"""
    name: str
    field_type: FieldType
    value: str = ""
    placeholder: str = ""
    required: bool = False
    max_length: Optional[int] = None
    min_length: Optional[int] = None
    pattern: Optional[str] = None
    
    # Select/Radio options
    options: List[Tuple[str, str]] = field(default_factory=list)  # (value, text)
    
    # Security attributes
    autocomplete: Optional[str] = None
    readonly: bool = False
    disabled: bool = False
    
    def __post_init__(self):
        if self.options is None:
            self.options = []
    
    @property
    def is_testable(self) -> bool:
        """Field can be tested for XSS"""
        return self.field_type in [
            FieldType.TEXT, FieldType.EMAIL, FieldType.SEARCH,
            FieldType.URL, FieldType.TEL, FieldType.TEXTAREA,
            FieldType.HIDDEN  # Hidden fields can also be vulnerable
        ]
    
    @property
    def is_file_upload(self) -> bool:
        """Field for file uploads"""
        return self.field_type == FieldType.FILE