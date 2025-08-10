#!/usr/bin/env python3

"""
BRS-XSS Reflection Calculator

Calculates reflection quality scores.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Any
from ..utils.logger import Logger

logger = Logger("core.reflection_calculator")


class ReflectionCalculator:
    """Calculates reflection quality scores"""
    
    def calculate_reflection_score(self, reflection_result: Any) -> float:
        """
        Calculate reflection quality score (0-10).
        
        Args:
            reflection_result: Reflection analysis result
            
        Returns:
            Reflection score
        """
        if not reflection_result:
            return 0.0
        
        # Base reflection scores
        reflection_type = getattr(reflection_result, 'reflection_type', None)
        
        if not reflection_type:
            return 0.0
        
        # Convert enum to string if necessary
        reflection_value = (
            reflection_type.value 
            if hasattr(reflection_type, 'value') 
            else str(reflection_type)
        )
        
        base_scores = {
            'exact': 10.0,         # Perfect reflection
            'partial': 7.0,        # Partial reflection
            'encoded': 5.0,        # Encoded reflection
            'filtered': 3.0,       # Filtered reflection
            'obfuscated': 4.0,     # Obfuscated reflection
            'modified': 6.0,       # Modified reflection
            'not_reflected': 0.0   # No reflection
        }
        
        base_score = base_scores.get(reflection_value.lower(), 0.0)
        
        # Analyze reflection quality details
        quality_bonus = self._analyze_reflection_quality(reflection_result)
        
        # Position and context of reflection
        position_bonus = self._analyze_reflection_position(reflection_result)
        
        # Multiple reflections
        multiple_bonus = self._analyze_multiple_reflections(reflection_result)
        
        final_score = min(10.0, base_score + quality_bonus + position_bonus + multiple_bonus)
        logger.debug(f"Reflection score: {final_score:.2f} for type: {reflection_value}")
        
        return final_score
    
    def _analyze_reflection_quality(self, reflection_result: Any) -> float:
        """Analyze reflection quality details"""
        quality_bonus = 0.0
        
        # Reflection completeness
        completeness = getattr(reflection_result, 'completeness', 0.0)
        if completeness > 0.8:
            quality_bonus += 1.0
        elif completeness > 0.5:
            quality_bonus += 0.5
        
        # Character preservation
        char_preserved = getattr(reflection_result, 'characters_preserved', 0.0)
        if char_preserved > 0.9:
            quality_bonus += 0.5
        elif char_preserved > 0.7:
            quality_bonus += 0.3
        
        # Special characters preserved
        special_chars = getattr(reflection_result, 'special_chars_preserved', [])
        critical_chars = ['<', '>', '"', "'", '&', '(', ')', ';']
        
        preserved_critical = sum(1 for char in critical_chars if char in special_chars)
        quality_bonus += (preserved_critical / len(critical_chars)) * 1.0
        
        return quality_bonus
    
    def _analyze_reflection_position(self, reflection_result: Any) -> float:
        """Analyze reflection position and context"""
        position_bonus = 0.0
        
        # Reflection positions
        positions = getattr(reflection_result, 'positions', [])
        
        for position in positions:
            context = position.get('context', '')
            
            # High-value positions
            if 'script' in context.lower():
                position_bonus += 1.0
            elif 'attribute' in context.lower():
                position_bonus += 0.7
            elif 'text' in context.lower():
                position_bonus += 0.5
            elif 'comment' in context.lower():
                position_bonus += 0.2
        
        # Multiple positions increase score
        if len(positions) > 1:
            position_bonus += min(1.0, len(positions) * 0.3)
        
        return min(2.0, position_bonus)  # Cap at 2.0
    
    def _analyze_multiple_reflections(self, reflection_result: Any) -> float:
        """Analyze multiple reflections"""
        multiple_bonus = 0.0
        
        # Number of reflections
        reflection_count = getattr(reflection_result, 'reflection_count', 1)
        
        if reflection_count > 1:
            multiple_bonus = min(1.0, (reflection_count - 1) * 0.2)
        
        # Different reflection types
        reflection_types = getattr(reflection_result, 'reflection_types', [])
        if len(set(reflection_types)) > 1:
            multiple_bonus += 0.3
        
        return multiple_bonus