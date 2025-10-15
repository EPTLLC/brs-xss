#!/usr/bin/env python3

"""
BRS-XSS Payload Types

Data types for payload generation system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional
from dataclasses import dataclass, field
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
    variables: List[str] = field(default_factory=list)
    description: str = ""
    
    def __post_init__(self):
        if self.variables is None:
            self.variables = []


@dataclass
class GenerationConfig:
    """Configuration for payload generation"""
    max_payloads: int = 500  # Reduced default for better performance
    include_evasions: bool = True
    include_waf_specific: bool = True
    include_blind_xss: bool = False
    effectiveness_threshold: float = 0.65  # Higher threshold for quality
    context_specific_only: bool = False
    
    # New performance-oriented settings
    seed: int = 1337
    max_manager_payloads: int = 2000
    max_evasion_bases: int = 10
    evasion_variants_per_tech: int = 2
    waf_bases: int = 3
    enable_aggressive: bool = False
    
    # Additional safety and performance settings
    pool_cap: int = 10000
    norm_hash: bool = False
    safe_mode: bool = True
    
    # Magic number constants
    payload_max_len: int = 4096
    evasion_base_limit: int = 5
    blind_batch_limit: int = 10
    
    # Configurable weights for payload sources (optional)
    weights: Optional['Weights'] = None


@dataclass
class Weights:
    """Weights for different payload sources"""
    context_specific: float = 0.92
    context_matrix: float = 0.90
    comprehensive: float = 0.70
    evasion: float = 0.75

