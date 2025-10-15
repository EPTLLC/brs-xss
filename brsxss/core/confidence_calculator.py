#!/usr/bin/env python3

"""
BRS-XSS Confidence Calculator

Calculates confidence scores for vulnerability assessments.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, Any, Optional
from ..utils.logger import Logger
from .config_manager import ConfigManager

logger = Logger("core.confidence_calculator")


class ConfidenceCalculator:
    """Calculates the confidence score of a potential XSS vulnerability"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """Initialize confidence calculator"""
        self.config = config or ConfigManager()
        self.weights = self.config.get('scoring.confidence_weights', {
            'reflection_quality': 0.4,
            'context_certainty': 0.3,
            'response_consistency': 0.2,
            'payload_success': 0.1
        })
    
    def calculate_confidence(
        self,
        reflection_result: Any,
        context_info: Dict[str, Any],
        payload: str
    ) -> float:
        """
        Calculate confidence score (0-1).
        
        Args:
            reflection_result: Reflection analysis result
            context_info: Context information
            payload: XSS payload
            
        Returns:
            Confidence score between 0 and 1
        """
        
        # Reflection quality affects confidence
        reflection_confidence = self._calculate_reflection_confidence(reflection_result)
        
        # Context clarity affects confidence
        context_confidence = self._calculate_context_confidence(context_info)
        
        # Payload analysis affects confidence
        payload_confidence = self._calculate_payload_confidence(payload)
        
        # Detection method confidence
        detection_confidence = self._calculate_detection_confidence(
            reflection_result, context_info
        )
        
        # Weighted combination
        final_confidence = (
            reflection_confidence * self.weights['reflection_quality'] +
            context_confidence * self.weights['context_certainty'] +
            payload_confidence * self.weights['payload_success'] +
            detection_confidence * self.weights['response_consistency']
        )
        
        final_confidence = max(0.0, min(1.0, final_confidence))
        logger.debug(f"Confidence score: {final_confidence:.3f}")
        
        return final_confidence
    
    def _calculate_reflection_confidence(self, reflection_result: Any) -> float:
        """Calculate confidence based on reflection quality"""
        if not reflection_result:
            return 0.1
        
        reflection_type = getattr(reflection_result, 'reflection_type', None)
        
        if not reflection_type:
            return 0.2
        
        reflection_value = (
            reflection_type.value 
            if hasattr(reflection_type, 'value') 
            else str(reflection_type)
        )
        
        # Confidence based on reflection type
        reflection_confidences = {
            'exact': 0.95,
            'partial': 0.80,
            'encoded': 0.70,
            'filtered': 0.60,
            'obfuscated': 0.65,
            'modified': 0.75,
            'not_reflected': 0.10
        }
        
        base_confidence = reflection_confidences.get(reflection_value.lower(), 0.5)
        
        # Adjust based on reflection details
        completeness = getattr(reflection_result, 'completeness', 0.5)
        char_preserved = getattr(reflection_result, 'characters_preserved', 0.5)
        
        detail_bonus = (completeness + char_preserved) / 2 * 0.2
        
        return min(1.0, base_confidence + detail_bonus)
    
    def _calculate_context_confidence(self, context_info: Dict[str, Any]) -> float:
        """Calculate confidence based on context analysis"""
        base_confidence = 0.5
        
        context_type = context_info.get('context_type', 'unknown')
        
        # Known contexts have higher confidence
        if context_type != 'unknown':
            base_confidence += 0.3
        
        # Specific tag and attribute information
        if context_info.get('tag_name'):
            base_confidence += 0.1
        
        if context_info.get('attribute_name'):
            base_confidence += 0.1
        
        # Filter detection increases confidence
        filters_detected = context_info.get('filters_detected', [])
        if filters_detected:
            base_confidence += min(0.2, len(filters_detected) * 0.05)
        
        # Encoding detection
        encoding_detected = context_info.get('encoding_detected', 'none')
        if encoding_detected != 'none':
            base_confidence += 0.1
        
        return min(1.0, base_confidence)
    
    def _calculate_payload_confidence(self, payload: str) -> float:
        """Calculate confidence based on payload analysis"""
        base_confidence = 0.6
        
        # Payload length and complexity
        if len(payload) > 20:  # Non-trivial payload
            base_confidence += 0.1
        
        if len(payload) > 50:  # Complex payload
            base_confidence += 0.1
        
        # Known XSS patterns
        xss_patterns = [
            '<script',
            'javascript:',
            'onerror=',
            'onload=',
            'onclick=',
            'eval(',
            'alert(',
            'document.',
            'window.'
        ]
        
        pattern_matches = sum(1 for pattern in xss_patterns if pattern.lower() in payload.lower())
        pattern_confidence = min(0.3, pattern_matches * 0.05)
        
        return min(1.0, base_confidence + pattern_confidence)
    
    def _calculate_detection_confidence(
        self,
        reflection_result: Any,
        context_info: Dict[str, Any]
    ) -> float:
        """Calculate confidence based on detection methods"""
        base_confidence = 0.7
        
        # Multiple detection methods increase confidence
        detection_methods = []
        
        if reflection_result:
            detection_methods.append('reflection')
        
        if context_info.get('context_type') != 'unknown':
            detection_methods.append('context')
        
        if context_info.get('filters_detected'):
            detection_methods.append('filter_detection')
        
        if context_info.get('encoding_detected', 'none') != 'none':
            detection_methods.append('encoding_detection')
        
        # More methods = higher confidence
        method_bonus = min(0.3, len(detection_methods) * 0.08)
        
        return min(1.0, base_confidence + method_bonus)