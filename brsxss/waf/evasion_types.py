#!/usr/bin/env python3

"""
BRS-XSS WAF Evasion Types

Types and data structures for WAF evasion techniques.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional
from dataclasses import dataclass, field
from enum import Enum

from .detector import WAFType


class EvasionTechnique(Enum):
    """WAF evasion techniques"""
    # Encoding techniques
    URL_ENCODING = "url_encoding"
    DOUBLE_URL_ENCODING = "double_url_encoding"
    HTML_ENCODING = "html_encoding"
    UNICODE_ENCODING = "unicode_encoding"
    HEX_ENCODING = "hex_encoding"
    BASE64_ENCODING = "base64_encoding"
    
    # Case variations
    CASE_VARIATION = "case_variation"
    MIXED_CASE = "mixed_case"
    RANDOM_CASE = "random_case"
    
    # Character manipulation
    WHITESPACE_INJECTION = "whitespace_injection"
    COMMENT_INSERTION = "comment_insertion"
    NULL_BYTE_INJECTION = "null_byte_injection"
    TAB_VARIATION = "tab_variation"
    
    # Payload fragmentation
    PAYLOAD_SPLITTING = "payload_splitting"
    PARAMETER_POLLUTION = "parameter_pollution"
    CONCATENATION = "concatenation"
    
    # JavaScript obfuscation
    JS_OBFUSCATION = "js_obfuscation"
    STRING_CONCAT = "string_concat"
    UNICODE_ESCAPE = "unicode_escape"
    EVAL_OBFUSCATION = "eval_obfuscation"
    
    # Protocol manipulation
    PROTOCOL_VARIATION = "protocol_variation"
    DATA_URI = "data_uri"
    JAVASCRIPT_URI = "javascript_uri"
    
    # techniques
    POLYGLOT_PAYLOAD = "polyglot_payload"
    CONTEXT_BREAKING = "context_breaking"
    MUTATION_FUZZING = "mutation_fuzzing"
    WAF_SPECIFIC = "waf_specific"


@dataclass
class EvasionResult:
    """Result of applying evasion technique"""
    original_payload: str
    evaded_payload: str
    technique: EvasionTechnique
    success_probability: float        # Success probability (0-1)
    stealth_level: float             # Stealth level (0-1)
    complexity: int                  # Complexity (1-10)
    target_wafs: List[WAFType]       # Target WAFs
    
    # Metadata
    transformation_steps: List[str]   # Transformation steps
    encoding_used: Optional[str] = None     # Used encoding
    obfuscation_level: int = 0          # Obfuscation level (1-10)