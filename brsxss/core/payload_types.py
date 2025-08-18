#!/usr/bin/env python3

"""
BRS-XSS Payload Types

Data types for payload generation system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum


class ContextType(Enum):
    """Payload context types"""
    HTML_CONTENT = "html_content"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    JS_STRING = "js_string"
    CSS_STYLE = "css_style"
    URL_PARAMETER = "url_parameter"
    HTML_COMMENT = "html_comment"
    UNKNOWN = "unknown"


class EvasionTechnique(Enum):
    """Evasion technique types"""
    CASE_VARIATION = "case_variation"
    URL_ENCODING = "url_encoding"
    HTML_ENTITY_ENCODING = "html_entity_encoding"
    UNICODE_ESCAPING = "unicode_escaping"
    COMMENT_INSERTION = "comment_insertion"
    WHITESPACE_VARIATION = "whitespace_variation"
    MIXED_ENCODING = "mixed_encoding"
    WAF_SPECIFIC = "waf_specific"


@dataclass
class GeneratedPayload:
    """Generated XSS payload"""
    payload: str
    context_type: str
    evasion_techniques: List[str]
    effectiveness_score: float
    description: str = ""
    
    def __post_init__(self):
        """Validate payload data"""
        if not self.payload:
            raise ValueError("Payload cannot be empty")
        
        if not 0.0 <= self.effectiveness_score <= 1.0:
            raise ValueError("Effectiveness score must be between 0.0 and 1.0")
        
        if self.evasion_techniques is None:
            self.evasion_techniques = []


@dataclass
class PayloadTemplate:
    """Template for payload generation"""
    template: str
    context_type: ContextType
    variables: List[str] = None
    description: str = ""
    
    def __post_init__(self):
        if self.variables is None:
            self.variables = []


@dataclass
class GenerationConfig:
    """Configuration for payload generation"""
    max_payloads: int = 2000  # Allow for comprehensive testing (901 base + evasions + WAF-specific)
    include_evasions: bool = True
    include_waf_specific: bool = True
    effectiveness_threshold: float = 0.3
    context_specific_only: bool = False
    
    def __post_init__(self):
        """Validate configuration"""
        if self.max_payloads <= 0:
            raise ValueError("max_payloads must be positive")
        
        if not 0.0 <= self.effectiveness_threshold <= 1.0:
            raise ValueError("effectiveness_threshold must be between 0.0 and 1.0")