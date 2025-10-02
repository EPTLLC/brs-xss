#!/usr/bin/env python3

"""
BRS-XSS WAF Types

WAF types and data structures for detection results.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class WAFType(Enum):
    """WAF types"""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    INCAPSULA = "incapsula"
    SUCURI = "sucuri"
    BARRACUDA = "barracuda"
    F5_BIG_IP = "f5_big_ip"
    FORTINET = "fortinet"
    MODSECURITY = "modsecurity"
    NGINX_WAF = "nginx_waf"
    APACHE_WAF = "apache_waf"
    CUSTOM = "custom"
    UNKNOWN = "unknown"
    NONE = "none"


@dataclass
class WAFInfo:
    """WAF information"""
    waf_type: WAFType
    name: str
    version: Optional[str] = None
    confidence: float = 0.0               # Detection confidence (0-1)
    detection_method: str = "unknown"     # Detection method
    vendor: Optional[str] = None
    blocking_level: str = "unknown"       # low/medium/high/extreme
    detected_features: List[str] = None   # Detected features
    
    # Technical details
    response_headers: Dict[str, str] = None
    error_pages: List[str] = None
    rate_limiting: bool = False
    geo_blocking: bool = False
    
    def __post_init__(self):
        if self.detected_features is None:
            self.detected_features = []
        if self.response_headers is None:
            self.response_headers = {}
        if self.error_pages is None:
            self.error_pages = []