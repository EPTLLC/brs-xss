#!/usr/bin/env python3

"""
BRS-XSS Header Security Scorer

Security scoring system for HTTP headers analysis.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, Tuple
from .header_types import HeaderAnalysis, SecurityLevel

from ..utils.logger import Logger

logger = Logger("core.header_scorer")


class HeaderSecurityScorer:
    """
    Security scoring system for HTTP headers.
    
    Calculates scores based on:
    - Header presence and configuration
    - Security levels
    - Weighted importance
    """
    
    def __init__(self):
        """Initialize header scorer"""
        
        # Header importance weights (total 100)
        self.weights = {
            'Content-Security-Policy': 40,
            'X-XSS-Protection': 20,
            'X-Frame-Options': 15,
            'X-Content-Type-Options': 10,
            'Strict-Transport-Security': 10,
            'Referrer-Policy': 5
        }
        
        logger.debug("Header security scorer initialized")
    
    def calculate_security_score(self, header_analyses: Dict[str, HeaderAnalysis]) -> Tuple[int, str]:
        """
        Calculate overall security score based on header analysis.
        
        Args:
            header_analyses: Dictionary of header analyses
            
        Returns:
            Tuple of (score, description) where score is 0-100
        """
        
        if not header_analyses:
            return 0, "No security headers analyzed"
        
        total_score = 0
        max_possible = 0
        
        for header_name, analysis in header_analyses.items():
            weight = self.weights.get(header_name, 5)
            max_possible += weight
            
            if analysis.security_level == SecurityLevel.SECURE:
                total_score += weight
            elif analysis.security_level == SecurityLevel.MODERATE:
                total_score += weight * 0.7
            elif analysis.security_level == SecurityLevel.WEAK:
                total_score += weight * 0.3
            # VULNERABLE = 0 points
        
        if max_possible == 0:
            return 0, "No relevant headers found"
        
        score = int((total_score / max_possible) * 100)
        description = self._get_score_description(score)
        
        logger.info(f"Security score calculated: {score}/100 - {description}")
        return score, description
    
    def _get_score_description(self, score: int) -> str:
        """Get human-readable score description"""
        
        if score >= 80:
            return "Strong security header configuration"
        elif score >= 60:
            return "Moderate security header protection"
        elif score >= 40:
            return "Weak security header protection"
        else:
            return "Poor security header configuration"
    
    def get_priority_recommendations(self, header_analyses: Dict[str, HeaderAnalysis]) -> list:
        """Get prioritized security recommendations"""
        
        recommendations = []
        
        # Critical missing headers
        critical_headers = ['Content-Security-Policy', 'X-XSS-Protection']
        for header in critical_headers:
            if header not in header_analyses:
                recommendations.append({
                    'priority': 'HIGH',
                    'header': header,
                    'action': f'Add {header} header',
                    'impact': 'Prevents XSS attacks'
                })
        
        # Vulnerable configurations
        for header_name, analysis in header_analyses.items():
            if analysis.security_level == SecurityLevel.VULNERABLE:
                recommendations.append({
                    'priority': 'HIGH',
                    'header': header_name,
                    'action': f'Fix {header_name} configuration',
                    'impact': 'Current configuration is unsafe',
                    'details': analysis.vulnerabilities  # type: ignore[dict-item]
                })
        
        # Weak configurations
        for header_name, analysis in header_analyses.items():
            if analysis.security_level == SecurityLevel.WEAK:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'header': header_name,
                    'action': f'Improve {header_name} configuration',
                    'impact': 'Enhanced security',
                    'details': analysis.recommendations  # type: ignore[dict-item]
                })
        
        return recommendations
    
    def compare_configurations(self, before: Dict[str, HeaderAnalysis], 
                             after: Dict[str, HeaderAnalysis]) -> Dict[str, str]:
        """Compare two header configurations"""
        
        comparison = {}
        
        all_headers = set(before.keys()) | set(after.keys())
        
        for header in all_headers:
            before_analysis = before.get(header)
            after_analysis = after.get(header)
            
            if not before_analysis and after_analysis:
                comparison[header] = "ADDED"
            elif before_analysis and not after_analysis:
                comparison[header] = "REMOVED"
            elif before_analysis and after_analysis:
                if before_analysis.security_level != after_analysis.security_level:
                    comparison[header] = f"CHANGED: {before_analysis.security_level.value} → {after_analysis.security_level.value}"
                else:
                    comparison[header] = "UNCHANGED"
        
        return comparison