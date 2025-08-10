#!/usr/bin/env python3

"""
BRS-XSS Reflection Detector

Main orchestrator for reflection detection system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional, Dict, Any

from .reflection_types import ReflectionResult, ReflectionPoint, ReflectionConfig, ReflectionType
from .reflection_analyzer import ReflectionAnalyzer
from .similarity_matcher import SimilarityMatcher
from ..utils.logger import Logger

logger = Logger("core.reflection_detector")


class ReflectionDetector:
    """
    Main reflection detector orchestrator.
    
    Coordinates reflection analysis components to provide
    comprehensive reflection detection and analysis.
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
        response_content: str
    ) -> ReflectionResult:
        """
        Main reflection detection method.
        
        Args:
            input_value: Original input value to search for
            response_content: Response content to search in
            
        Returns:
            Comprehensive reflection analysis result
        """
        self.detection_count += 1
        
        logger.debug(f"Detecting reflections for input: {input_value[:50]}...")
        
        # Limit search length for performance
        search_content = response_content[:self.config.max_search_length]
        
        # Find all potential reflections
        reflection_points = self._find_all_reflections(input_value, search_content)
        
        # Create result
        result = ReflectionResult(
            input_value=input_value,
            reflection_points=reflection_points
        )
        
        # Analyze exploitability
        if reflection_points:
            result.is_exploitable = self._assess_exploitability(reflection_points)
            result.exploitation_confidence = self._calculate_exploitation_confidence(reflection_points)
            result.recommended_payloads = self._generate_payload_recommendations(reflection_points)
        
        # Update statistics
        self._update_statistics(result)
        
        logger.info(f"Detection complete: {len(reflection_points)} reflections found")
        return result
    
    def _find_all_reflections(
        self,
        input_value: str,
        content: str
    ) -> List[ReflectionPoint]:
        """Find all reflections of input value in content"""
        reflection_points = []
        
        # 1. Find exact matches
        exact_matches = self._find_exact_reflections(input_value, content)
        reflection_points.extend(exact_matches)
        
        # 2. Find encoded reflections
        if self.config.analyze_encoding:
            encoded_matches = self._find_encoded_reflections(input_value, content)
            reflection_points.extend(encoded_matches)
        
        # 3. Find similar reflections
        similar_matches = self._find_similar_reflections(input_value, content)
        reflection_points.extend(similar_matches)
        
        # Remove duplicates and limit count
        unique_points = self._remove_duplicate_reflections(reflection_points)
        limited_points = unique_points[:self.config.max_reflections_per_input]
        
        logger.debug(f"Found {len(limited_points)} unique reflection points")
        return limited_points
    
    def _find_exact_reflections(
        self,
        input_value: str,
        content: str
    ) -> List[ReflectionPoint]:
        """Find exact reflections"""
        reflection_points = []
        search_value = input_value if self.config.case_sensitive else input_value.lower()
        search_content = content if self.config.case_sensitive else content.lower()
        
        start = 0
        while True:
            pos = search_content.find(search_value, start)
            if pos == -1:
                break
            
            # Extract actual reflected value from original content
            reflected_value = content[pos:pos + len(input_value)]
            
            # Analyze this reflection point
            reflection_point = self.analyzer.analyze_reflection_point(
                input_value, reflected_value, pos, content
            )
            
            reflection_points.append(reflection_point)
            start = pos + 1
        
        return reflection_points
    
    def _find_encoded_reflections(
        self,
        input_value: str,
        content: str
    ) -> List[ReflectionPoint]:
        """Find encoded reflections"""
        reflection_points = []
        
        # Find encoded matches using similarity matcher
        encoded_matches = self.matcher.find_encoded_reflections(input_value, content)
        
        for pos, encoded_value, encoding_type in encoded_matches:
            reflection_point = self.analyzer.analyze_reflection_point(
                input_value, encoded_value, pos, content
            )
            
            # Update encoding information
            reflection_point.encoding_applied = encoding_type
            reflection_point.reflection_type = ReflectionType.ENCODED
            
            reflection_points.append(reflection_point)
        
        return reflection_points
    
    def _find_similar_reflections(
        self,
        input_value: str,
        content: str
    ) -> List[ReflectionPoint]:
        """Find similar/partial reflections"""
        reflection_points = []
        
        # Use similarity matcher to find similar strings
        similar_matches = self.matcher.find_similar_reflections(
            input_value, content, self.config.min_reflection_length
        )
        
        for pos, similar_value, similarity_score in similar_matches:
            reflection_point = self.analyzer.analyze_reflection_point(
                input_value, similar_value, pos, content
            )
            
            # Adjust accuracy based on similarity score
            reflection_point.accuracy = similarity_score
            
            reflection_points.append(reflection_point)
        
        return reflection_points
    
    def _remove_duplicate_reflections(
        self,
        reflection_points: List[ReflectionPoint]
    ) -> List[ReflectionPoint]:
        """Remove duplicate reflection points"""
        unique_points = []
        seen_positions = set()
        
        # Sort by quality (best first)
        sorted_points = sorted(
            reflection_points,
            key=lambda rp: (rp.accuracy, rp.completeness, rp.characters_preserved),
            reverse=True
        )
        
        for point in sorted_points:
            # Check if this position is too close to an existing one
            is_duplicate = False
            for seen_pos in seen_positions:
                if abs(point.position - seen_pos) < 10:  # Within 10 characters
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                unique_points.append(point)
                seen_positions.add(point.position)
        
        return unique_points
    
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
        self.reflection_stats['total_detected'] += result.total_reflections
        
        for point in result.reflection_points:
            reflection_type = point.reflection_type.value
            if reflection_type in self.reflection_stats['by_type']:
                self.reflection_stats['by_type'][reflection_type] += 1
        
        # Update average quality
        if result.reflection_points:
            total_quality = sum(rp.accuracy for rp in result.reflection_points)
            avg_quality = total_quality / len(result.reflection_points)
            
            # Running average
            current_avg = self.reflection_stats['avg_quality']
            self.reflection_stats['avg_quality'] = (
                (current_avg * (self.detection_count - 1) + avg_quality) / self.detection_count
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