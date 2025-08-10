#!/usr/bin/env python3

"""
BRS-XSS Context Calculator

Calculates context-based vulnerability scores.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, Any
from ..utils.logger import Logger

logger = Logger("core.context_calculator")


class ContextCalculator:
    """Calculates context-based vulnerability scores"""
    
    def __init__(self):
        """Initialize context calculator"""
        self.context_scores = self._load_context_scores()
    
    def calculate_context_score(self, context_info: Dict[str, Any]) -> float:
        """
        Calculate context-based score (0-10).
        
        Args:
            context_info: Context information
            
        Returns:
            Context score
        """
        context_type = context_info.get('context_type', 'unknown')
        
        # Base context scores
        context_scores = {
            'javascript': 9.0,      # Direct JS execution
            'html_content': 8.0,    # HTML injection
            'js_string': 7.0,       # JS string context
            'html_attribute': 6.0,  # Attribute injection
            'css_style': 4.0,       # CSS injection
            'url_parameter': 5.0,   # URL context
            'html_comment': 2.0,    # Comment context
            'unknown': 3.0          # Unknown context
        }
        
        base_score = context_scores.get(context_type, 3.0)
        
        # Additional context factors
        tag_name = context_info.get('tag_name', '')
        attribute_name = context_info.get('attribute_name', '')
        
        # High-risk tags
        high_risk_tags = ['script', 'iframe', 'object', 'embed', 'form']
        if tag_name.lower() in high_risk_tags:
            base_score += 1.0
        
        # High-risk attributes
        high_risk_attributes = ['src', 'href', 'action', 'onload', 'onerror', 'onclick']
        if attribute_name.lower() in high_risk_attributes:
            base_score += 1.0
        
        # Event handler attributes
        if attribute_name.lower().startswith('on'):
            base_score += 1.5
        
        # Special context considerations
        base_score += self._analyze_special_contexts(context_info)
        
        final_score = min(10.0, base_score)
        logger.debug(f"Context score: {final_score:.2f} for type: {context_type}")
        
        return final_score
    
    def _analyze_special_contexts(self, context_info: Dict[str, Any]) -> float:
        """Analyze special context situations"""
        bonus_score = 0.0
        
        # Position within document
        position = context_info.get('position', '')
        if position == 'head':
            bonus_score += 0.5  # Head section is more critical
        
        # Nested contexts
        if context_info.get('nested_context', False):
            bonus_score += 0.3
        
        # Dynamic content
        if context_info.get('dynamic_content', False):
            bonus_score += 0.4
        
        # Template contexts
        if context_info.get('template_context', False):
            bonus_score += 0.6
        
        # AJAX contexts
        if context_info.get('ajax_context', False):
            bonus_score += 0.5
        
        return bonus_score
    
    def _load_context_scores(self) -> Dict[str, float]:
        """Load context scoring configuration"""
        return {
            'script_tag': 10.0,
            'style_tag': 6.0,
            'img_tag': 5.0,
            'iframe_tag': 9.0,
            'object_tag': 8.0,
            'embed_tag': 8.0,
            'form_tag': 7.0,
            'input_tag': 6.0,
            'textarea_tag': 6.0,
            'div_tag': 4.0,
            'span_tag': 4.0,
            'a_tag': 5.0
        }