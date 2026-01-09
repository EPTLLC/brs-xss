#!/usr/bin/env python3

"""
BRS-XSS WAF Signature

WAF signature data structure for fingerprinting.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Optional
from dataclasses import dataclass, field

from .waf_types import WAFType


@dataclass
class WAFSignature:
    """WAF signature for fingerprinting"""

    waf_type: WAFType
    name: str

    # Header signatures
    header_patterns: list[str]  # Header patterns
    required_headers: list[str]  # Required headers

    # Content signatures
    content_patterns: list[str]  # Content patterns
    error_page_patterns: list[str]  # Error page patterns

    # Behavioral signatures
    status_codes: list[int]  # Characteristic status codes
    response_timing: Optional[float] = None  # Characteristic response time

    # signatures
    ssl_fingerprint: Optional[str] = None  # SSL fingerprint
    server_signature: Optional[str] = None  # Server signature
    cdn_indicators: list[str] = field(default_factory=list)  # CDN indicators

    # Metadata
    confidence_weight: float = 1.0  # Signature weight for confidence
    last_updated: Optional[str] = None  # Last update date
    source: str = "brsxss"  # Signature source

    def __post_init__(self):
        if self.cdn_indicators is None:
            self.cdn_indicators = []
