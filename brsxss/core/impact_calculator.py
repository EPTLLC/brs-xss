#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 13:11:55 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, Any, Optional
from ..utils.logger import Logger
from .config_manager import ConfigManager

logger = Logger("core.impact_calculator")


class ImpactCalculator:
    """Calculates the potential impact of an XSS vulnerability based on the payload."""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """Initialize impact calculator"""
        self.config = config or ConfigManager()
        self.impact_scores = self.config.get('scoring.impact_functions', {
            '<script': 0.9,
            'document.cookie': 0.9,
            'eval(': 0.8,
            'document.write': 0.7,
            'location.href': 0.6,
            'XMLHttpRequest': 0.8,
            'fetch(': 0.8,
            'alert(': 0.3, # Lower impact, but a good indicator
            'prompt(': 0.4,
            'confirm(': 0.4
        })

    def calculate_impact_score(self, context_info: Dict[str, Any], payload: str) -> float:
        """
        Calculate impact score (0-1.0) based purely on the payload's contents.
        """
        base_score = 0.0
        payload_lower = payload.lower()

        for func, score in self.impact_scores.items():
            if func in payload_lower:
                base_score = max(base_score, score)
        
        # The context bonus is removed to keep this calculator focused *only* on the payload.
        # Context is handled by the ContextCalculator.

        logger.debug(f"Impact score calculated: {base_score:.2f}")
        return base_score