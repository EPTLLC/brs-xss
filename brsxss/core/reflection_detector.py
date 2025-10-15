#!/usr/bin/env python3

"""
BRS-XSS Reflection Detector

Main orchestrator for reflection detection system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
import html

from .reflection_types import (
    ReflectionResult, 
    ReflectionPoint, 
    ReflectionConfig, 
    ReflectionType,
    ReflectionContext
)
from .reflection_analyzer import ReflectionAnalyzer
from .similarity_matcher import SimilarityMatcher
from ..utils.logger import Logger

logger = Logger("core.reflection_detector")


class ReflectionDetector:
    """
    Main reflection detector orchestrator.
    
    Coordinates reflection analysis components to provide
    reflection detection and analysis.
    """
    
    def __init__(self, config: Optional[ReflectionConfig] = None):
        """
        Initialize reflection detector.
        
        Args:
            config: Detection configuration
        """
        self.config = config or ReflectionConfig()
        
        # Initialize components
        self.analyzer = ReflectionAnalyzer()
        self.matcher = SimilarityMatcher(self.config.similarity_threshold)
        
        # Detection statistics
        self.detection_count = 0
        self.reflection_stats = {
            'total_detected': 0,
            'by_type': {rt.value: 0 for rt in ReflectionType},
            'avg_quality': 0.0
        }
        
        logger.info("Reflection detector initialized")
    
    def detect_reflections(
        self,
        input_value: str,
        response_text: str
    ) -> ReflectionResult:
        """Detect reflections of an input value in a response"""
        
        self.detection_count += 1
        
        # Performance optimization: if exact match not found, skip further analysis
        if input_value not in response_text and html.escape(input_value) not in response_text:
            return ReflectionResult(input_value=input_value)

        # Decode response for broader matching
        decoded_response_text = html.unescape(response_text)
        
        # Find all occurrences of the original and decoded value
        reflection_points = self._find_all_occurrences(input_value, response_text, decoded_response_text)
        
        # If no reflections found, return empty result
        if not reflection_points:
            return ReflectionResult(input_value=input_value)

        # Create the result object first
        result = ReflectionResult(
            input_value=input_value,
            reflection_points=reflection_points
        )
        
        # Analyze exploitability and add to the result
        if reflection_points:
            result.is_exploitable = self._assess_exploitability(reflection_points)
            result.exploitation_confidence = self._calculate_exploitation_confidence(reflection_points)
            result.recommended_payloads = self._generate_payload_recommendations(reflection_points)
        
        # Update statistics
        self._update_statistics(result)
        
        logger.info(f"Detection complete: {len(reflection_points)} reflections found")
        return result
    
    def _find_all_occurrences(
        self,
        input_value: str,
        original_response: str,
        decoded_response: str
    ) -> List[ReflectionPoint]:
        """Find all occurrences of the input value in its original and decoded forms."""
        
        points = []
        
        # 1. Search for exact, unfiltered reflection in the original response
        for match in re.finditer(re.escape(input_value), original_response, re.IGNORECASE):
            points.append(self._analyze_reflection_point(
                input_value=input_value,
                reflected_value=match.group(0),
                position=match.start(),
                response_text=original_response
            ))

        # 2. Search for encoded/modified reflection in the decoded response
        # We need to find the match in the decoded text, but report its position and content
        # from the *original* response to be accurate.
        encoded_input = html.escape(input_value)
        for match in re.finditer(re.escape(encoded_input), original_response, re.IGNORECASE):
            # Avoid duplicating exact matches found above
            is_duplicate = any(p.position == match.start() for p in points)
            if not is_duplicate:
                points.append(self._analyze_reflection_point(
                    input_value=input_value,
                    reflected_value=match.group(0),
                    position=match.start(),
                    response_text=original_response
                ))

        # Deduplicate based on position
        unique_points = {p.position: p for p in points}.values()
        return list(unique_points)
        
    def _analyze_reflection_point(
        self,
        input_value: str,
        reflected_value: str,
        position: int,
        response_text: str
    ) -> ReflectionPoint:
        """Analyze a single reflection point."""
        
        # Analyze reflection type
        reflection_type = self._determine_reflection_type(input_value, reflected_value)
        
        # Analyze context
        context_type = self._determine_context(response_text, position)
        
        # Analyze quality
        accuracy, completeness = self._analyze_quality(input_value, reflected_value)
        
        # Analyze encoding
        encoding_applied = self._analyze_encoding(input_value, reflected_value)
        
        # Analyze special characters preserved
        special_chars_preserved = self._analyze_special_chars(input_value, reflected_value)
        
        return ReflectionPoint(
            position=position,
            reflected_value=reflected_value,
            original_value=input_value,
            reflection_type=reflection_type,
            context=context_type,
            accuracy=accuracy,
            completeness=completeness,
            encoding_applied=encoding_applied,
            special_chars_preserved=special_chars_preserved
        )
    
    def _determine_reflection_type(self, input_value: str, reflected_value: str) -> ReflectionType:
        """Determine the type of reflection based on input and reflected values."""
        
        if input_value == reflected_value:
            return ReflectionType.EXACT
        
        # Check for specific encoding first, as it's a form of modification
        if reflected_value == html.escape(input_value):
            return ReflectionType.ENCODED
        
        # Check for partial match (e.g., input is a substring of the reflection)
        if input_value in reflected_value:
            return ReflectionType.PARTIAL
        
        # If it's not exact, encoded, or partial, it's generally modified
        return ReflectionType.MODIFIED
    
    def _determine_context(self, response_text: str, position: int) -> ReflectionContext:
        """Determine the context of a reflection based on surrounding content."""
        
        # Get surrounding content
        context_content = self._get_surrounding_content(response_text, position, self.config.context_window)
        
        # Simple heuristic for context
        if '<' in context_content or '>' in context_content:
            return ReflectionContext.HTML_CONTENT
        elif 'javascript:' in context_content or 'window.' in context_content:
            return ReflectionContext.JAVASCRIPT
        elif '"' in context_content or "'" in context_content:
            return ReflectionContext.HTML_ATTRIBUTE
        elif 'style=' in context_content:
            return ReflectionContext.CSS_STYLE
        elif '<!--' in context_content:
            return ReflectionContext.HTML_COMMENT
        elif '?' in context_content:
            return ReflectionContext.URL_PARAMETER
        else:
            return ReflectionContext.UNKNOWN
    
    def _analyze_quality(self, input_value: str, reflected_value: str) -> tuple[float, float]:
        """Analyze the quality of a reflection (accuracy and completeness)."""
        
        # Calculate accuracy (how well the reflected value matches the input)
        accuracy = self.analyzer.calculate_accuracy(input_value, reflected_value)
        
        # Calculate completeness (how much of the input is preserved)
        completeness = self.analyzer.calculate_completeness(input_value, reflected_value)
        
        return accuracy, completeness
    
    def _analyze_encoding(self, input_value: str, reflected_value: str) -> str:
        """Analyze if the reflected value is encoded."""
        
        if reflected_value == html.escape(input_value):
            return 'html_encoding'
        
        # More sophisticated encoding detection would involve a matcher
        # For now, we'll assume any non-exact match is potentially encoded
        return 'unknown'
    
    def _analyze_special_chars(self, input_value: str, reflected_value: str) -> List[str]:
        """Analyze if special characters are preserved."""
        
        preserved_chars = []
        for char in ['<', '>', '"', "'", '&']:
            if char in reflected_value and char in input_value:
                preserved_chars.append(char)
        return preserved_chars
    
    def _get_surrounding_content(self, response_text: str, position: int, length: int) -> str:
        """Get the surrounding content of a reflection point."""
        
        start = max(0, position - length)
        end = min(len(response_text), position + length)
        return response_text[start:end]
    
    def _assess_exploitability(self, reflection_points: List[ReflectionPoint]) -> bool:
        """Assess if reflections are exploitable"""
        for point in reflection_points:
            # High-quality reflections in dangerous contexts are exploitable
            if (point.reflection_type in [ReflectionType.EXACT, ReflectionType.PARTIAL] and
                point.context.value in ['html_content', 'javascript', 'html_attribute'] and
                point.accuracy > 0.7):
                return True
            
            # Special characters preserved in HTML context
            if (point.context.value in ['html_content', 'html_attribute'] and
                any(char in point.special_chars_preserved for char in ['<', '>', '"', "'"])):
                return True
        
        return False
    
    def _calculate_exploitation_confidence(self, reflection_points: List[ReflectionPoint]) -> float:
        """Calculate confidence in exploitation potential"""
        if not reflection_points:
            return 0.0
        
        max_confidence = 0.0
        
        for point in reflection_points:
            confidence = 0.0
            
            # Base confidence from reflection type
            type_confidence = {
                ReflectionType.EXACT: 1.0,
                ReflectionType.PARTIAL: 0.8,
                ReflectionType.MODIFIED: 0.6,
                ReflectionType.ENCODED: 0.4,
                ReflectionType.FILTERED: 0.2,
                ReflectionType.OBFUSCATED: 0.3,
                ReflectionType.NOT_REFLECTED: 0.0
            }
            
            confidence += type_confidence.get(point.reflection_type, 0.0) * 0.4
            
            # Context-based confidence
            context_confidence = {
                'html_content': 1.0,
                'javascript': 1.0,
                'html_attribute': 0.8,
                'css_style': 0.6,
                'html_comment': 0.3,
                'url_parameter': 0.5,
                'unknown': 0.4
            }
            
            confidence += context_confidence.get(point.context.value, 0.4) * 0.3
            
            # Quality-based confidence
            confidence += point.accuracy * 0.2
            confidence += point.completeness * 0.1
            
            max_confidence = max(max_confidence, confidence)
        
        return min(max_confidence, 1.0)
    
    def _generate_payload_recommendations(self, reflection_points: List[ReflectionPoint]) -> List[str]:
        """Generate payload recommendations based on reflections"""
        recommendations = []
        
        for point in reflection_points:
            if point.context.value == 'html_content':
                recommendations.extend([
                    '<script>alert(1)</script>',
                    '<img src=x onerror=alert(1)>',
                    '<svg onload=alert(1)>'
                ])
            
            elif point.context.value == 'html_attribute':
                if '"' in point.special_chars_preserved:
                    recommendations.append('"><script>alert(1)</script>')
                if "'" in point.special_chars_preserved:
                    recommendations.append("'><script>alert(1)</script>")
            
            elif point.context.value == 'javascript':
                recommendations.extend([
                    ';alert(1);//',
                    '";alert(1);//',
                    "';alert(1);//"
                ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _update_statistics(self, result: ReflectionResult):
        """Update detection statistics"""
        self.reflection_stats['total_detected'] += result.total_reflections  # type: ignore[operator]
        
        for point in result.reflection_points:
            reflection_type = point.reflection_type.value
            if reflection_type in self.reflection_stats['by_type']:  # type: ignore[operator]
                self.reflection_stats['by_type'][reflection_type] += 1  # type: ignore[index]
        
        # Update average quality
        if result.reflection_points:
            total_quality = sum(rp.accuracy for rp in result.reflection_points)
            avg_quality = total_quality / len(result.reflection_points)
            
            # Running average
            current_avg = self.reflection_stats['avg_quality']
            self.reflection_stats['avg_quality'] = (
                (current_avg * (self.detection_count - 1) + avg_quality) / self.detection_count  # type: ignore[operator]
            )
    
    def quick_detect(self, input_value: str, response_content: str) -> bool:
        """
        Quick reflection detection (existence only).
        
        Args:
            input_value: Input to search for
            response_content: Content to search in
            
        Returns:
            True if any reflection found
        """
        search_content = response_content[:self.config.max_search_length // 2]
        search_value = input_value if self.config.case_sensitive else input_value.lower()
        search_in = search_content if self.config.case_sensitive else search_content.lower()
        
        return search_value in search_in
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get reflection detection statistics"""
        return {
            'total_detections': self.detection_count,
            'reflection_stats': self.reflection_stats.copy(),
            'config': {
                'similarity_threshold': self.config.similarity_threshold,
                'min_reflection_length': self.config.min_reflection_length,
                'case_sensitive': self.config.case_sensitive
            }
        }
    
    def reset_statistics(self):
        """Reset detection statistics"""
        self.detection_count = 0
        self.reflection_stats = {
            'total_detected': 0,
            'by_type': {rt.value: 0 for rt in ReflectionType},
            'avg_quality': 0.0
        }
        logger.info("Reflection detection statistics reset")
    
    def batch_detect_reflections(
        self,
        input_values: List[str],
        response_content: str
    ) -> Dict[str, ReflectionResult]:
        """
        Detect reflections for multiple input values efficiently.
        
        Args:
            input_values: List of input values to check
            response_content: Response content to search in
            
        Returns:
            Dictionary mapping input values to results
        """
        results = {}
        
        logger.info(f"Batch detecting reflections for {len(input_values)} inputs")
        
        for input_value in input_values:
            try:
                result = self.detect_reflections(input_value, response_content)
                results[input_value] = result
                
            except Exception as e:
                logger.error(f"Error detecting reflections for '{input_value}': {e}")
                # Create empty result
                results[input_value] = ReflectionResult(input_value=input_value)
        
        logger.info(f"Batch detection completed: {len(results)} results")
        return results