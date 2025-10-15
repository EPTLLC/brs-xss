#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 13:33:15 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .waf_types import WAFType as _WAFType


class WAFBrand(Enum):
    """Backwards-compatible brand enum used by tests.
    Maps to internal WAFType values.
    """
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    INCAPSULA = "incapsula"
    SUCURI = "sucuri"
    BARRACUDA = "barracuda"
    MODSECURITY = "modsecurity"
    IMPERVA = "incapsula"
    UNKNOWN = "unknown"


@dataclass
class WAF:
    """Minimal WAF model expected by payload generator tests."""
    brand: WAFBrand
    name: str
    version: Optional[str] = None

    @property
    def waf_type(self) -> _WAFType:
        """Provide internal WAFType view for core generators/evasions."""
        try:
            # Map by value where possible
            return _WAFType(self.brand.value)
        except Exception:
            return _WAFType.UNKNOWN


