#!/usr/bin/env python3

"""
BRS-XSS CSP Analyzer

Specialized Content Security Policy analysis module.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional
from .header_types import HeaderAnalysis, CSPAnalysis, SecurityLevel

from ..utils.logger import Logger

logger = Logger("core.csp_analyzer")


class CSPAnalyzer:
    """
    Specialized CSP (Content Security Policy) analyzer.
    
    Analyzes:
    - CSP directives and sources
    - Unsafe keywords detection
    - Bypass opportunities
    - Security level assessment
    """
    
    def __init__(self):
        """Initialize CSP analyzer"""
        self.dangerous_keywords = [
            'unsafe-inline', 'unsafe-eval', 'data:', '*', 'blob:',
            'unsafe-hashes', 'strict-dynamic'
        ]
        
        logger.debug("CSP analyzer initialized")
    
    def analyze_csp(self, csp_value: str) -> HeaderAnalysis:
        """Analyze Content Security Policy header"""
        
        if not csp_value or csp_value == "MISSING":
            return HeaderAnalysis(
                header_name="Content-Security-Policy",
                value="MISSING",
                security_level=SecurityLevel.VULNERABLE,
                vulnerabilities=["No CSP header present - XSS attacks unrestricted"],
                recommendations=["Implement Content-Security-Policy header"]
            )
        
        vulnerabilities: List[str] = []
        bypass_techniques = []
        
        # Check for dangerous directives
        if 'unsafe-inline' in csp_value:
            vulnerabilities.append("'unsafe-inline' allows inline scripts and styles")
            bypass_techniques.append("Inject inline <script> tags or event handlers")
        
        if 'unsafe-eval' in csp_value:
            vulnerabilities.append("'unsafe-eval' allows eval() and similar functions")
            bypass_techniques.append("Use eval(), setTimeout(), setInterval() with strings")
        
        if "'*'" in csp_value or csp_value.count('*') > 0:
            vulnerabilities.append("Wildcard (*) allows any source")
            bypass_techniques.append("Load scripts from any external domain")
        
        if 'data:' in csp_value:
            vulnerabilities.append("'data:' scheme allows data URLs")
            bypass_techniques.append("Use data: URLs for script injection")
        
        # Check for missing critical directives
        critical_directives = ['script-src', 'object-src', 'default-src']
        missing_directives = [d for d in critical_directives if d not in csp_value]
        if missing_directives:
            vulnerabilities.append(f"Missing critical directives: {', '.join(missing_directives)}")
        
        # Determine security level
        if len(vulnerabilities) == 0:
            level = SecurityLevel.SECURE
        elif len(vulnerabilities) <= 2:
            level = SecurityLevel.MODERATE
        else:
            level = SecurityLevel.VULNERABLE
        
        recommendations = [
            "Remove 'unsafe-inline' and 'unsafe-eval'",
            "Use nonce or hash-based CSP for inline content",
            "Restrict script sources to trusted domains only",
            "Add 'object-src none' to prevent plugin injection"
        ]
        
        return HeaderAnalysis(
            header_name="Content-Security-Policy",
            value=csp_value,
            security_level=level,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            bypass_techniques=bypass_techniques
        )
    
    def analyze_csp_detailed(self, csp_policy: str) -> CSPAnalysis:
        """Detailed CSP analysis with directive breakdown"""
        
        directives = {}
        policy_parts = [part.strip() for part in csp_policy.split(';') if part.strip()]
        
        for part in policy_parts:
            if ' ' in part:
                directive, sources = part.split(' ', 1)
                directives[directive] = sources.split()
            else:
                directives[part] = []
        
        vulnerabilities: List[str] = []
        bypass_opportunities = []
        unsafe_sources = []
        
        # Analyze each directive
        for directive, sources in directives.items():  # type: ignore[assignment]
            for source in sources:
                if source in self.dangerous_keywords:
                    unsafe_sources.append(f"{directive}: {source}")
                    
                    if source == 'unsafe-inline':
                        bypass_opportunities.append(f"Inline injection via {directive}")
                    elif source == 'unsafe-eval':
                        bypass_opportunities.append(f"eval() injection via {directive}")
                    elif source == '*':
                        bypass_opportunities.append(f"External resource injection via {directive}")
        
        # Determine overall security level
        if len(unsafe_sources) == 0:
            security_level = SecurityLevel.SECURE
        elif len(unsafe_sources) <= 2:
            security_level = SecurityLevel.MODERATE
        else:
            security_level = SecurityLevel.VULNERABLE
        
        return CSPAnalysis(
            policy=csp_policy,
            directives=directives,
            security_level=security_level,
            vulnerabilities=vulnerabilities,
            bypass_opportunities=bypass_opportunities,
            unsafe_sources=unsafe_sources
        )
    
    def find_csp_bypasses(self, csp_policy: str) -> List[str]:
        """Find potential CSP bypass techniques"""
        
        bypasses = []
        policy_lower = csp_policy.lower()
        
        # Check for common bypass patterns
        if 'unsafe-inline' in policy_lower:
            bypasses.append("Inline script/style injection")
        
        if 'unsafe-eval' in policy_lower:
            bypasses.append("eval() based injection")
        
        if 'data:' in policy_lower:
            bypasses.append("Data URI injection")
        
        if "'self'" in policy_lower and 'jsonp' not in policy_lower:
            bypasses.append("JSONP callback injection if available")
        
        # Check for wildcard subdomains
        if '*.example.com' in policy_lower:
            bypasses.append("Subdomain takeover potential")
        
        # Check for weak sources
        weak_sources = ['http:', 'https:', 'ws:', 'wss:']
        for source in weak_sources:
            if source in policy_lower:
                bypasses.append(f"Broad {source} scheme allows many sources")
        
        return bypasses