#!/usr/bin/env python3

"""
BRS-XSS Evasion Types

Data types and constants for WAF evasion techniques.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus  
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

from enum import Enum


class EvasionTechnique(Enum):
    """Types of evasion techniques"""
    UNICODE_ENCODING = "unicode_encoding"
    HTML_ENTITY_ENCODING = "html_entity_encoding"
    URL_ENCODING = "url_encoding"
    COMMENT_INSERTION = "comment_insertion"
    CASE_MANIPULATION = "case_manipulation"
    WHITESPACE_MANIPULATION = "whitespace_manipulation"
    STRING_CONCATENATION = "string_concatenation"
    CHARACTER_CONSTRUCTION = "character_construction"


class WAFType(Enum):
    """Supported WAF types for specific evasions"""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    MOD_SECURITY = "mod_security"
    IMPERVA = "imperva"
    F5_ASM = "f5_asm"
    AKAMAI = "akamai"


# Unicode alternatives for common characters
UNICODE_ALTERNATIVES = {
    '<': ['\\u003c', '\\x3c', '&lt;', '%3C', '\\074'],
    '>': ['\\u003e', '\\x3e', '&gt;', '%3E', '\\076'],
    '"': ['\\u0022', '\\x22', '&quot;', '%22', '\\042'],
    "'": ['\\u0027', '\\x27', '&apos;', '%27', '\\047'],
    '(': ['\\u0028', '\\x28', '%28', '\\050'],
    ')': ['\\u0029', '\\x29', '%29', '\\051'],
    '=': ['\\u003d', '\\x3d', '%3D', '\\075'],
    ' ': ['\\u0020', '\\x20', '%20', '+', '\\040'],
    '/': ['\\u002f', '\\x2f', '%2F', '\\057']
}

# Comment insertion patterns
COMMENT_PATTERNS = [
    '/**/',
    '/**//**/',
    '<!---->',
    '<!-- -->',
    '//*/',
    '/*<!--*/',
    '<!--/*-->',
]

# HTML entity alternatives
HTML_ENTITY_MAP = {
    '<': ['&lt;', '&#60;', '&#x3c;', '&#x3C;'],
    '>': ['&gt;', '&#62;', '&#x3e;', '&#x3E;'],
    '"': ['&quot;', '&#34;', '&#x22;'],
    "'": ['&apos;', '&#39;', '&#x27;'],
    '&': ['&amp;', '&#38;', '&#x26;'],
    '(': ['&#40;', '&#x28;'],
    ')': ['&#41;', '&#x29;'],
    '=': ['&#61;', '&#x3d;'],
    ' ': ['&#32;', '&#x20;']
}

# Whitespace characters for manipulation
WHITESPACE_CHARS = [
    ' ', '\t', '\n', '\r', '\f', '\v',
    '&#9;', '&#10;', '&#13;', '&#12;', '&#11;'
]