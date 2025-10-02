#!/usr/bin/env python3

"""
BRS-XSS Impact Calculator

Calculates vulnerability impact scores.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, Any
from ..utils.logger import Logger

logger = Logger("core.impact_calculator")


class ImpactCalculator:
    """Calculates vulnerability impact scores"""
    
    def __init__(self):
        """Initialize impact calculator"""
        self.impact_factors = self._load_impact_factors()
    
    def calculate_impact_score(self, context_info: Dict[str, Any], payload: str) -> float:
        """
        Calculate impact score (0-10) based on context and payload.
        
        Args:
            context_info: Context information
            payload: XSS payload
            
        Returns:
            Impact score
        """
        base_score = 5.0
        impact_multiplier = 1.0
        
        # Context type affects impact
        context_type = context_info.get('context_type', 'unknown')
        
        context_impacts = {
            'javascript': 1.5,      # Direct JS execution - high impact
            'html_content': 1.3,    # HTML injection - high impact
            'js_string': 1.2,       # JS string context - medium-high impact
            'html_attribute': 1.1,  # Attribute injection - medium impact
            'url_parameter': 1.0,   # URL context - medium impact
            'css_style': 0.8,       # CSS injection - lower impact
            'html_comment': 0.5,    # Comment context - low impact
            'unknown': 0.7          # Unknown context - conservative estimate
        }
        
        impact_multiplier *= context_impacts.get(context_type, 0.7)
        
        # Page sensitivity affects impact
        if context_info.get('page_sensitive', False):
            impact_multiplier += 0.3
        
        # User controllable inputs have higher impact
        if context_info.get('user_controllable', True):
            impact_multiplier += 0.2
        
        # Position in document affects impact
        position = context_info.get('position', 'unknown')
        position_impacts = {
            'head': 1.2,
            'body': 1.0,
            'footer': 0.8,
            'unknown': 0.9
        }
        
        impact_multiplier *= position_impacts.get(position, 0.9)
        
        # Payload characteristics affect impact
        impact_multiplier += self._analyze_payload_impact(payload)
        
        # HTML injection context
        if context_type in ['html_content', 'html_attribute']:
            impact_multiplier += 0.2
        
        final_score = min(10.0, base_score * impact_multiplier)
        logger.debug(f"Impact score: {final_score:.2f} (base: {base_score}, multiplier: {impact_multiplier:.2f})")
        
        return final_score
    
    def _analyze_payload_impact(self, payload: str) -> float:
        """Analyze payload characteristics for impact assessment"""
        impact_bonus = 0.0
        payload_lower = payload.lower()
        
        # High-impact payload patterns
        high_impact_patterns = [
            'document.cookie',
            'document.location',
            'window.location',
            'eval(',
            'function(',
            'settimeout',
            'setinterval',
            'xmlhttprequest',
            'fetch(',
            'import(',
            'websocket'
        ]
        
        for pattern in high_impact_patterns:
            if pattern in payload_lower:
                impact_bonus += 0.1
        
        # Data exfiltration patterns
        exfiltration_patterns = [
            'new image',
            'document.body.appendchild',
            'navigator.sendbeacon',
            'postmessage',
            'localstorage',
            'sessionstorage'
        ]
        
        for pattern in exfiltration_patterns:
            if pattern in payload_lower:
                impact_bonus += 0.15
        
        # UI manipulation patterns
        ui_patterns = [
            'alert(',
            'confirm(',
            'prompt(',
            'document.write',
            'innerhtml',
            'outerhtml',
            'document.body'
        ]
        
        for pattern in ui_patterns:
            if pattern in payload_lower:
                impact_bonus += 0.05
        
        return min(1.0, impact_bonus)  # Cap bonus at 1.0
    
    def _load_impact_factors(self) -> Dict[str, float]:
        """Load impact factors configuration"""
        return {
            'data_theft': 2.0,
            'session_hijacking': 1.8,
            'defacement': 1.2,
            'phishing': 1.5,
            'malware_distribution': 2.0,
            'privilege_escalation': 1.7,
            'dos_attack': 1.0,
            'information_disclosure': 1.3
        }