#!/usr/bin/env python3

"""
BRS-XSS Basic Headers Analyzer

Analyzer for basic security headers (non-CSP).

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from typing import Optional
from .header_types import HeaderAnalysis, SecurityLevel

from ..utils.logger import Logger

logger = Logger("core.basic_headers_analyzer")


class BasicHeadersAnalyzer:
    """
    Analyzer for basic security headers.
    
    Handles:
    - X-XSS-Protection
    - X-Frame-Options
    - X-Content-Type-Options
    - Referrer-Policy
    - Strict-Transport-Security
    """
    
    def __init__(self):
        """Initialize basic headers analyzer"""
        logger.debug("Basic headers analyzer initialized")
    
    def analyze_xss_protection(self, value: Optional[str]) -> HeaderAnalysis:
        """Analyze X-XSS-Protection header"""
        
        if not value:
            return HeaderAnalysis(
                header_name="X-XSS-Protection",
                value="MISSING",
                security_level=SecurityLevel.WEAK,
                vulnerabilities=["No XSS protection header"],
                recommendations=["Add 'X-XSS-Protection: 1; mode=block'"]
            )
        
        vulnerabilities = []
        bypass_techniques = []
        
        if value == "0":
            vulnerabilities.append("XSS protection explicitly disabled")
            bypass_techniques.append("Standard reflected XSS attacks will work")
            level = SecurityLevel.VULNERABLE
        elif "mode=block" not in value:
            vulnerabilities.append("XSS filter not set to block mode")
            bypass_techniques.append("XSS may still execute with sanitization attempts")
            level = SecurityLevel.WEAK
        else:
            level = SecurityLevel.MODERATE
        
        return HeaderAnalysis(
            header_name="X-XSS-Protection",
            value=value,
            security_level=level,
            vulnerabilities=vulnerabilities,
            recommendations=["Use 'X-XSS-Protection: 1; mode=block' for maximum protection"],
            bypass_techniques=bypass_techniques
        )
    
    def analyze_frame_options(self, value: Optional[str]) -> HeaderAnalysis:
        """Analyze X-Frame-Options header"""
        
        if not value:
            return HeaderAnalysis(
                header_name="X-Frame-Options",
                value="MISSING",
                security_level=SecurityLevel.WEAK,
                vulnerabilities=["No frame protection - vulnerable to clickjacking"],
                recommendations=["Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'"]
            )
        
        vulnerabilities = []
        bypass_techniques = []
        
        if value.upper() == "ALLOWALL":
            vulnerabilities.append("Allows framing from any origin")
            bypass_techniques.append("Clickjacking attacks via iframe embedding")
            level = SecurityLevel.VULNERABLE
        elif value.upper() == "SAMEORIGIN":
            level = SecurityLevel.MODERATE
        elif value.upper() == "DENY":
            level = SecurityLevel.SECURE
        else:
            vulnerabilities.append("Invalid or unrecognized value")
            level = SecurityLevel.WEAK
        
        return HeaderAnalysis(
            header_name="X-Frame-Options",
            value=value,
            security_level=level,
            vulnerabilities=vulnerabilities,
            recommendations=["Use 'DENY' for maximum protection"],
            bypass_techniques=bypass_techniques
        )
    
    def analyze_content_type_options(self, value: Optional[str]) -> HeaderAnalysis:
        """Analyze X-Content-Type-Options header"""
        
        if not value:
            return HeaderAnalysis(
                header_name="X-Content-Type-Options",
                value="MISSING",
                security_level=SecurityLevel.WEAK,
                vulnerabilities=["No MIME type protection - vulnerable to MIME sniffing"],
                recommendations=["Add 'X-Content-Type-Options: nosniff'"]
            )
        
        if value.lower() == "nosniff":
            level = SecurityLevel.SECURE
            vulnerabilities = []
        else:
            level = SecurityLevel.WEAK
            vulnerabilities = ["Invalid value - MIME sniffing may occur"]
        
        return HeaderAnalysis(
            header_name="X-Content-Type-Options",
            value=value,
            security_level=level,
            vulnerabilities=vulnerabilities,
            recommendations=["Use 'nosniff' value"]
        )
    
    def analyze_referrer_policy(self, value: Optional[str]) -> Optional[HeaderAnalysis]:
        """Analyze Referrer-Policy header"""
        
        if not value:
            return None  # Not critical for XSS, skip if missing
        
        secure_policies = ['no-referrer', 'same-origin', 'strict-origin']
        weak_policies = ['unsafe-url', 'origin-when-cross-origin']
        
        if value in secure_policies:
            level = SecurityLevel.SECURE
            vulnerabilities = []
        elif value in weak_policies:
            level = SecurityLevel.WEAK
            vulnerabilities = ["May leak sensitive information in referrer"]
        else:
            level = SecurityLevel.MODERATE
            vulnerabilities = []
        
        return HeaderAnalysis(
            header_name="Referrer-Policy",
            value=value,
            security_level=level,
            vulnerabilities=vulnerabilities,
            recommendations=["Use 'no-referrer' or 'same-origin' for better privacy"]
        )
    
    def analyze_hsts(self, value: Optional[str]) -> Optional[HeaderAnalysis]:
        """Analyze Strict-Transport-Security header"""
        
        if not value:
            return None  # Not critical for XSS analysis
        
        vulnerabilities = []
        
        # Check max-age
        if 'max-age=' not in value:
            vulnerabilities.append("Missing max-age directive")
        else:
            max_age_match = re.search(r'max-age=(\d+)', value)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:  # 1 year
                    vulnerabilities.append("HSTS max-age too short (< 1 year)")
        
        # Check for includeSubDomains
        if 'includeSubDomains' not in value:
            vulnerabilities.append("Missing includeSubDomains directive")
        
        level = SecurityLevel.SECURE if not vulnerabilities else SecurityLevel.MODERATE
        
        return HeaderAnalysis(
            header_name="Strict-Transport-Security",
            value=value,
            security_level=level,
            vulnerabilities=vulnerabilities,
            recommendations=["Use max-age=31536000; includeSubDomains; preload"]
        )