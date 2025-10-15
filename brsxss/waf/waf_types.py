#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 13:33:15 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
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
    detected_features: List[str] = field(default_factory=list)   # Detected features
    
    # Technical details
    response_headers: Dict[str, str] = field(default_factory=dict)
    error_pages: List[str] = field(default_factory=list)
    rate_limiting: bool = False
    geo_blocking: bool = False
    
    def __post_init__(self):
        if self.detected_features is None:
            self.detected_features = []
        if self.response_headers is None:
            self.response_headers = {}
        if self.error_pages is None:
            self.error_pages = []

    @property
    def brand(self) -> "WAFBrand":  # type: ignore[name-defined]
        """Compatibility layer exposing WAF brand for tests."""
        # Lazy import to avoid circular dependency during module init
        from .models import WAFBrand as _WAFBrand
        mapping = {
            WAFType.CLOUDFLARE: _WAFBrand.CLOUDFLARE,
            WAFType.AWS_WAF: _WAFBrand.AWS_WAF,
            WAFType.AKAMAI: _WAFBrand.AKAMAI,
            WAFType.INCAPSULA: getattr(_WAFBrand, "IMPERVA", _WAFBrand.INCAPSULA),
            WAFType.SUCURI: getattr(_WAFBrand, "SUCURI", _WAFBrand.UNKNOWN),
            WAFType.BARRACUDA: _WAFBrand.BARRACUDA,
            WAFType.F5_BIG_IP: getattr(_WAFBrand, "F5_BIG_IP", _WAFBrand.UNKNOWN),
            WAFType.FORTINET: getattr(_WAFBrand, "FORTINET", _WAFBrand.UNKNOWN),
            WAFType.MODSECURITY: _WAFBrand.MODSECURITY,
        }
        return mapping.get(self.waf_type, _WAFBrand.UNKNOWN)