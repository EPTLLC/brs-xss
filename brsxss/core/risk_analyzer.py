#!/usr/bin/env python3

"""
BRS-XSS Risk Analyzer

Analyzes risk factors and generates recommendations.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, List, Any, Optional
from .scoring_types import SeverityLevel
from ..utils.logger import Logger

logger = Logger("core.risk_analyzer")


class RiskAnalyzer:
    """Analyzes risk factors and generates recommendations"""
    
    def identify_risk_factors(
        self,
        context_info: Dict[str, Any],
        payload: str,
        reflection_result: Any
    ) -> List[str]:
        """
        Identify risk factors for vulnerability.
        
        Args:
            context_info: Context information
            payload: XSS payload
            reflection_result: Reflection analysis result
            
        Returns:
            List of risk factors
        """
        risk_factors = []
        
        # Context-based risks
        risk_factors.extend(self._analyze_context_risks(context_info))
        
        # Payload-based risks
        risk_factors.extend(self._analyze_payload_risks(payload))
        
        # Reflection-based risks
        risk_factors.extend(self._analyze_reflection_risks(reflection_result))
        
        # Environment risks
        risk_factors.extend(self._analyze_environment_risks(context_info))
        
        logger.debug(f"Identified {len(risk_factors)} risk factors")
        return risk_factors
    
    def identify_mitigating_factors(
        self,
        context_info: Dict[str, Any],
        response: Any
    ) -> List[str]:
        """
        Identify mitigating factors that reduce risk.
        
        Args:
            context_info: Context information
            response: HTTP response
            
        Returns:
            List of mitigating factors
        """
        mitigating_factors = []
        
        # Security headers
        if response and hasattr(response, 'headers'):
            headers = response.headers
            
            if 'content-security-policy' in headers:
                mitigating_factors.append("Content Security Policy implemented")
            
            if 'x-frame-options' in headers:
                mitigating_factors.append("X-Frame-Options header present")
            
            if 'x-xss-protection' in headers:
                mitigating_factors.append("X-XSS-Protection header present")
            
            if 'x-content-type-options' in headers:
                mitigating_factors.append("X-Content-Type-Options header present")
        
        # Input filtering
        filters_detected = context_info.get('filters_detected', [])
        if filters_detected:
            mitigating_factors.append(f"Input filtering detected: {', '.join(filters_detected)}")
        
        # Output encoding
        encoding_detected = context_info.get('encoding_detected', 'none')
        if encoding_detected != 'none':
            mitigating_factors.append(f"Output encoding detected: {encoding_detected}")
        
        # Context restrictions
        if context_info.get('context_type') == 'html_comment':
            mitigating_factors.append("Limited to HTML comment context")
        
        logger.debug(f"Identified {len(mitigating_factors)} mitigating factors")
        return mitigating_factors
    
    def generate_recommendations(
        self,
        severity: SeverityLevel,
        context_info: Dict[str, Any],
        risk_factors: List[str],
        mitigating_factors: List[str]
    ) -> List[str]:
        """
        Generate security recommendations.
        
        Args:
            severity: Vulnerability severity
            context_info: Context information
            risk_factors: Identified risk factors
            mitigating_factors: Identified mitigating factors
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Severity-based recommendations
        if severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            recommendations.extend([
                "Implement immediate input validation and sanitization",
                "Deploy Content Security Policy (CSP) with strict directives",
                "Review and fix vulnerable code immediately"
            ])
        
        # Context-specific recommendations
        context_type = context_info.get('context_type', 'unknown')
        
        if context_type == 'javascript':
            recommendations.extend([
                "Avoid dynamic JavaScript generation",
                "Use safe JSON encoding for data insertion",
                "Implement strict CSP script-src directives"
            ])
        
        elif context_type in ['html_content', 'html_attribute']:
            recommendations.extend([
                "Implement proper HTML entity encoding",
                "Use templating engines with auto-escaping",
                "Validate and sanitize all user input"
            ])
        
        # Risk-specific recommendations
        if any('data exfiltration' in factor.lower() for factor in risk_factors):
            recommendations.append("Monitor for data exfiltration attempts")
        
        if any('session hijacking' in factor.lower() for factor in risk_factors):
            recommendations.extend([
                "Implement secure session management",
                "Use HttpOnly and Secure cookie flags"
            ])
        
        # General recommendations
        recommendations.extend([
            "Perform regular security testing and code reviews",
            "Keep web application frameworks updated",
            "Train developers on secure coding practices"
        ])
        
        logger.debug(f"Generated {len(recommendations)} recommendations")
        return list(set(recommendations))  # Remove duplicates
    
    def _analyze_context_risks(self, context_info: Dict[str, Any]) -> List[str]:
        """Analyze context-based risks"""
        risks: List[str] = []
        
        context_type = context_info.get('context_type', 'unknown')
        
        if context_type == 'javascript':
            risks.append("Direct JavaScript execution possible")
        
        if context_type == 'html_content':
            risks.append("HTML injection and DOM manipulation possible")
        
        tag_name = context_info.get('tag_name', '').lower()
        if tag_name in ['script', 'iframe', 'object']:
            risks.append(f"High-risk HTML tag: {tag_name}")
        
        if context_info.get('page_sensitive', False):
            risks.append("Injection in sensitive page context")
        
        return risks
    
    def _analyze_payload_risks(self, payload: str) -> List[str]:
        """Analyze payload-based risks"""
        risks: List[str] = []
        payload_lower = payload.lower()
        
        # Data exfiltration patterns
        if any(pattern in payload_lower for pattern in [
            'document.cookie', 'document.location', 'window.location'
        ]):
            risks.append("Potential for data exfiltration")
        
        # Session hijacking
        if 'document.cookie' in payload_lower:
            risks.append("Potential for session hijacking")
        
        # DOM manipulation
        if any(pattern in payload_lower for pattern in [
            'document.write', 'innerhtml', 'outerhtml'
        ]):
            risks.append("DOM manipulation capabilities")
        
        # Network requests
        if any(pattern in payload_lower for pattern in [
            'xmlhttprequest', 'fetch(', 'websocket'
        ]):
            risks.append("Potential for unauthorized network requests")
        
        return risks
    
    def _analyze_reflection_risks(self, reflection_result: Any) -> List[str]:
        """Analyze reflection-based risks"""
        risks: List[str] = []
        
        if not reflection_result:
            return risks
        
        reflection_type = getattr(reflection_result, 'reflection_type', None)
        
        if reflection_type:
            reflection_value = (
                reflection_type.value 
                if hasattr(reflection_type, 'value') 
                else str(reflection_type)
            )
            
            if reflection_value == 'exact':
                risks.append("Perfect payload reflection enables exploitation")
            
            elif reflection_value == 'partial':
                risks.append("Partial reflection may allow bypasses")
        
        return risks
    
    def _analyze_environment_risks(self, context_info: Dict[str, Any]) -> List[str]:
        """Analyze environment-based risks"""
        risks: List[str] = []
        
        # Missing security controls
        if not context_info.get('filters_detected'):
            risks.append("No input filtering detected")
        
        if context_info.get('encoding_detected', 'none') == 'none':
            risks.append("No output encoding detected")
        
        # User interaction requirements
        if context_info.get('user_controllable', True):
            risks.append("User-controllable input vector")
        
        return risks