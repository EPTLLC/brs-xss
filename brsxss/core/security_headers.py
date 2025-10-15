#!/usr/bin/env python3

"""
BRS-XSS Security Headers Inspector

Main security headers analysis module.

Company: EasyProTech LLC (www.easypro.tech)  
Dev: Brabus
Modified: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict
from .header_types import HeaderAnalysis
from .csp_analyzer import CSPAnalyzer  
from .header_scorer import HeaderSecurityScorer
from .basic_headers_analyzer import BasicHeadersAnalyzer
from .cors_analyzer import CORSAnalyzer

from ..utils.logger import Logger

logger = Logger("core.security_headers")


class SecurityHeadersInspector:
    """
    Main security headers inspector.
    
    Analyzes:
    - X-XSS-Protection
    - X-Frame-Options
    - X-Content-Type-Options
    - Referrer-Policy
    - Strict-Transport-Security
    - Access-Control-* (CORS)
    """
    
    def __init__(self):
        """Initialize security headers inspector"""
        self.csp_analyzer = CSPAnalyzer()
        self.basic_analyzer = BasicHeadersAnalyzer()
        self.cors_analyzer = CORSAnalyzer()
        self.scorer = HeaderSecurityScorer()
        
        logger.info("Security headers inspector initialized")
    
    def analyze_headers(self, headers: Dict[str, str]) -> Dict[str, HeaderAnalysis]:
        """header security analysis"""
        
        results = {}
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        
        # Analyze each security header
        analyses = [
            self.csp_analyzer.analyze_csp(normalized_headers.get('content-security-policy', 'MISSING')),
            self.basic_analyzer.analyze_xss_protection(normalized_headers.get('x-xss-protection')),
            self.basic_analyzer.analyze_frame_options(normalized_headers.get('x-frame-options')),
            self.basic_analyzer.analyze_content_type_options(normalized_headers.get('x-content-type-options')),
            self.basic_analyzer.analyze_referrer_policy(normalized_headers.get('referrer-policy')),
            self.basic_analyzer.analyze_hsts(normalized_headers.get('strict-transport-security')),
            *self.cors_analyzer.analyze_cors_headers(normalized_headers)
        ]
        
        # Filter out None results
        for analysis in analyses:
            if analysis:
                results[analysis.header_name] = analysis
        
        return results