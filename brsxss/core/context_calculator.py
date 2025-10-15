#!/usr/bin/env python3

"""
BRS-XSS Context Calculator

Calculates context-based vulnerability scores.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, Any, Optional
from ..utils.logger import Logger
from .config_manager import ConfigManager
from .context_types import ContextType

logger = Logger("core.context_calculator")


class ContextCalculator:
    """Calculates a score based on the injection context"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """Initialize context calculator"""
        self.config = config or ConfigManager()
        self.context_scores = self.config.get('scoring.context_scores', {
            'javascript': 1.0,
            'html_content': 0.9,
            'js_string': 0.8,
            'html_attribute': 0.7,
            'url_parameter': 0.6,
            'css_style': 0.4,
            'html_comment': 0.2,
            'unknown': 0.3
        })
    
    def calculate_context_score(self, context_info: Dict[str, Any]) -> float:
        """
        Calculate context-based score (0-1.0).
        """
        # Use the most specific context available for scoring
        context_type = context_info.get('specific_context', context_info.get('context_type', 'unknown'))
        score = self.context_scores.get(context_type, 0.3)
        
        logger.debug(f"Context score: {score:.2f} for type: {context_type}")
        return score
    
    def _load_context_scores(self) -> Dict[str, float]:
        """Load context scoring configuration"""
        # This logic is now handled by the config loader.
        return {}