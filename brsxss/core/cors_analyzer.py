#!/usr/bin/env python3

"""
BRS-XSS CORS Analyzer

Specialized CORS headers analyzer.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, List, Optional
from .header_types import HeaderAnalysis, SecurityLevel

from ..utils.logger import Logger

logger = Logger("core.cors_analyzer")


class CORSAnalyzer:
    """
    CORS (Cross-Origin Resource Sharing) headers analyzer.
    
    Analyzes:
    - Access-Control-Allow-Origin
    - Access-Control-Allow-Credentials
    - Access-Control-Allow-Methods
    - Access-Control-Allow-Headers
    """
    
    def __init__(self):
        """Initialize CORS analyzer"""
        logger.debug("CORS analyzer initialized")
    
    def analyze_cors_headers(self, headers: Dict[str, str]) -> List[HeaderAnalysis]:
        """Analyze all CORS headers"""
        
        cors_headers = [
            'access-control-allow-origin',
            'access-control-allow-credentials', 
            'access-control-allow-methods',
            'access-control-allow-headers'
        ]
        
        analyses = []
        
        for header in cors_headers:
            value = headers.get(header)
            if not value:
                continue
            
            analysis = self._analyze_cors_header(header, value, headers)
            if analysis:
                analyses.append(analysis)
        
        return analyses
    
    def _analyze_cors_header(self, header: str, value: str, all_headers: Dict[str, str]) -> HeaderAnalysis:
        """Analyze individual CORS header"""
        
        vulnerabilities = []
        bypass_techniques = []
        
        if header == 'access-control-allow-origin':
            level, vulns, bypasses = self._analyze_allow_origin(value, all_headers)
            vulnerabilities.extend(vulns)
            bypass_techniques.extend(bypasses)
        
        elif header == 'access-control-allow-credentials':
            level, vulns = self._analyze_allow_credentials(value)
            vulnerabilities.extend(vulns)
        
        elif header == 'access-control-allow-methods':
            level, vulns = self._analyze_allow_methods(value)
            vulnerabilities.extend(vulns)
        
        elif header == 'access-control-allow-headers':
            level, vulns = self._analyze_allow_headers(value)
            vulnerabilities.extend(vulns)
        
        else:
            level = SecurityLevel.MODERATE
        
        return HeaderAnalysis(
            header_name=header,
            value=value,
            security_level=level,
            vulnerabilities=vulnerabilities,
            recommendations=["Review CORS policy for security implications"],
            bypass_techniques=bypass_techniques
        )
    
    def _analyze_allow_origin(self, value: str, all_headers: Dict[str, str]) -> tuple:
        """Analyze Access-Control-Allow-Origin"""
        
        vulnerabilities = []
        bypass_techniques = []
        
        if value == '*':
            if all_headers.get('access-control-allow-credentials') == 'true':
                vulnerabilities.append("Wildcard origin with credentials - security risk")
                bypass_techniques.append("Cross-origin requests from any domain with credentials")
                level = SecurityLevel.VULNERABLE
            else:
                level = SecurityLevel.WEAK
                vulnerabilities.append("Wildcard origin allows any domain")
        elif value.startswith('*.'):
            vulnerabilities.append("Wildcard subdomain may be vulnerable to subdomain takeover")
            level = SecurityLevel.WEAK
        else:
            level = SecurityLevel.MODERATE
        
        return level, vulnerabilities, bypass_techniques
    
    def _analyze_allow_credentials(self, value: str) -> tuple:
        """Analyze Access-Control-Allow-Credentials"""
        
        vulnerabilities = []
        
        if value.lower() == 'true':
            level = SecurityLevel.MODERATE
            vulnerabilities.append("Credentials allowed in cross-origin requests")
        else:
            level = SecurityLevel.SECURE
        
        return level, vulnerabilities
    
    def _analyze_allow_methods(self, value: str) -> tuple:
        """Analyze Access-Control-Allow-Methods"""
        
        vulnerabilities = []
        dangerous_methods = ['PUT', 'DELETE', 'PATCH']
        
        if '*' in value:
            vulnerabilities.append("Wildcard allows all HTTP methods")
            level = SecurityLevel.WEAK
        elif any(method in value.upper() for method in dangerous_methods):
            vulnerabilities.append("Allows potentially dangerous HTTP methods")
            level = SecurityLevel.MODERATE
        else:
            level = SecurityLevel.SECURE
        
        return level, vulnerabilities
    
    def _analyze_allow_headers(self, value: str) -> tuple:
        """Analyze Access-Control-Allow-Headers"""
        
        vulnerabilities = []
        
        if '*' in value:
            vulnerabilities.append("Wildcard allows all headers")
            level = SecurityLevel.WEAK
        elif 'authorization' in value.lower():
            vulnerabilities.append("Authorization header allowed in CORS")
            level = SecurityLevel.MODERATE
        else:
            level = SecurityLevel.SECURE
        
        return level, vulnerabilities