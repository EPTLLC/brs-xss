#!/usr/bin/env python3

"""
BRS-XSS WAF Fingerprinter

WAF signature analysis and behavior analysis with ML approach.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .waf_signature import WAFSignature
from .signature_database import SignatureDatabase
from .waf_fingerprinter import WAFFingerprinter

__all__ = [
    "WAFSignature",
    "SignatureDatabase",
    "WAFFingerprinter"
]