#!/usr/bin/env python3

"""
BRS-XSS Filter Detector

Detects filtering and encoding applied to user input.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from typing import List, Dict, Any, Optional
from .context_types import FilterType, EncodingType
from ..utils.logger import Logger

logger = Logger("core.filter_detector")


class FilterDetector:
    """Detects XSS filters and encoding mechanisms"""
    
    def __init__(self):
        """Initialize filter detector"""
        self.filter_indicators = {
            # HTML entity encoding
            '&lt;': FilterType.HTML_ENTITY_ENCODING,
            '&gt;': FilterType.HTML_ENTITY_ENCODING,
            '&quot;': FilterType.HTML_ENTITY_ENCODING,
            '&amp;': FilterType.HTML_ENTITY_ENCODING,
            '&#x3c;': FilterType.HTML_ENTITY_ENCODING,
            '&#x3e;': FilterType.HTML_ENTITY_ENCODING,
            '&#60;': FilterType.HTML_ENTITY_ENCODING,
            '&#62;': FilterType.HTML_ENTITY_ENCODING,
            
            # URL encoding
            '%3C': FilterType.URL_ENCODING,
            '%3E': FilterType.URL_ENCODING,
            '%22': FilterType.URL_ENCODING,
            '%27': FilterType.URL_ENCODING,
            '%3c': FilterType.URL_ENCODING,
            '%3e': FilterType.URL_ENCODING,
            
            # Backslash escaping
            '\\"': FilterType.BACKSLASH_ESCAPING,
            "\\'": FilterType.BACKSLASH_ESCAPING,
            '\\<': FilterType.BACKSLASH_ESCAPING,
            '\\>': FilterType.BACKSLASH_ESCAPING,
        }
        
        self.encoding_patterns = {
            EncodingType.HTML_ENTITIES: [r'&\w+;', r'&#\d+;', r'&#x[0-9a-fA-F]+;'],
            EncodingType.URL_ENCODING: [r'%[0-9a-fA-F]{2}'],
            EncodingType.UNICODE_ESCAPING: [r'\\u[0-9a-fA-F]{4}', r'\\x[0-9a-fA-F]{2}'],
            EncodingType.BACKSLASH_ESCAPING: [r'\\[\'\"<>(){}[\]]']
        }
    
    def detect_filters(self, original_input: str, rendered_output: str) -> List[str]:
        """
        Detect filters applied to input.
        
        Args:
            original_input: Original user input
            rendered_output: Rendered output content
            
        Returns:
            List of detected filter types
        """
        detected_filters = []
        
        # Check if input was completely removed
        if original_input and original_input not in rendered_output:
            detected_filters.append(FilterType.CONTENT_FILTERING.value)
        
        # Check for specific filter indicators
        for indicator, filter_type in self.filter_indicators.items():
            if indicator in rendered_output:
                if filter_type.value not in detected_filters:
                    detected_filters.append(filter_type.value)
        
        # Check for character substitutions
        substitution_filters = self._detect_character_substitutions(
            original_input, rendered_output
        )
        detected_filters.extend(substitution_filters)
        
        # Check for length-based filtering
        if self._is_length_filtered(original_input, rendered_output):
            detected_filters.append("length_filtering")
        
        # Check for keyword filtering
        keyword_filters = self._detect_keyword_filtering(original_input, rendered_output)
        detected_filters.extend(keyword_filters)
        
        logger.debug(f"Detected filters: {detected_filters}")
        return detected_filters
    
    def detect_encoding(self, content: str) -> str:
        """
        Detect encoding type applied to content.
        
        Args:
            content: Content to analyze
            
        Returns:
            Detected encoding type
        """
        for encoding_type, patterns in self.encoding_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    logger.debug(f"Detected encoding: {encoding_type.value}")
                    return encoding_type.value
        
        return EncodingType.NONE.value
    
    def analyze_filter_strength(self, filters: List[str]) -> Dict[str, Any]:
        """
        Analyze the strength and bypassability of detected filters.
        
        Args:
            filters: List of detected filters
            
        Returns:
            Filter strength analysis
        """
        analysis = {
            'strength_level': 'none',
            'bypassable': True,
            'bypass_techniques': [],
            'risk_assessment': 'high'
        }
        
        if not filters:
            return analysis
        
        # Determine strength level
        filter_strength_map = {
            FilterType.CONTENT_FILTERING.value: 3,
            FilterType.HTML_ENTITY_ENCODING.value: 2,
            FilterType.URL_ENCODING.value: 2,
            FilterType.BACKSLASH_ESCAPING.value: 1,
            FilterType.UNICODE_ESCAPING.value: 2,
            FilterType.WAF_FILTERING.value: 4
        }
        
        max_strength = max([filter_strength_map.get(f, 0) for f in filters])
        
        if max_strength >= 4:
            analysis['strength_level'] = 'very_high'
            analysis['bypassable'] = False
            analysis['risk_assessment'] = 'low'
        elif max_strength >= 3:
            analysis['strength_level'] = 'high'
            analysis['bypassable'] = True
            analysis['risk_assessment'] = 'medium'
        elif max_strength >= 2:
            analysis['strength_level'] = 'medium'
            analysis['bypassable'] = True
            analysis['risk_assessment'] = 'high'
        else:
            analysis['strength_level'] = 'low'
            analysis['bypassable'] = True
            analysis['risk_assessment'] = 'very_high'
        
        # Generate bypass techniques
        analysis['bypass_techniques'] = self._generate_bypass_techniques(filters)
        
        return analysis
    
    def _detect_character_substitutions(self, original: str, rendered: str) -> List[str]:
        """Detect character substitution filters"""
        substitutions = []
        
        # Common substitution patterns
        substitution_maps = {
            '<': ['&lt;', '&#60;', '&#x3c;', '%3c', '%3C'],
            '>': ['&gt;', '&#62;', '&#x3e;', '%3e', '%3E'],
            '"': ['&quot;', '&#34;', '&#x22;', '%22'],
            "'": ['&#39;', '&#x27;', '%27'],
            '&': ['&amp;', '&#38;', '&#x26;', '%26'],
            '(': ['&#40;', '&#x28;', '%28'],
            ')': ['&#41;', '&#x29;', '%29']
        }
        
        for char, replacements in substitution_maps.items():
            if char in original:
                for replacement in replacements:
                    if replacement in rendered and char not in rendered:
                        if replacement.startswith('&'):
                            substitutions.append(FilterType.HTML_ENTITY_ENCODING.value)
                        elif replacement.startswith('%'):
                            substitutions.append(FilterType.URL_ENCODING.value)
                        break
        
        return list(set(substitutions))  # Remove duplicates
    
    def _is_length_filtered(self, original: str, rendered: str) -> bool:
        """Check if content was filtered based on length"""
        if len(original) > 100 and len(rendered) < len(original) * 0.5:
            return True
        
        # Check for truncation patterns
        if rendered.endswith('...') or rendered.endswith('[truncated]'):
            return True
        
        return False
    
    def _detect_keyword_filtering(self, original: str, rendered: str) -> List[str]:
        """Detect keyword-based filtering"""
        keyword_filters = []
        
        # Common XSS keywords that might be filtered
        xss_keywords = [
            'script', 'alert', 'eval', 'javascript', 'onerror',
            'onload', 'onclick', 'document', 'window', 'location'
        ]
        
        for keyword in xss_keywords:
            if keyword.lower() in original.lower() and keyword.lower() not in rendered.lower():
                keyword_filters.append("keyword_filtering")
                break
        
        return keyword_filters
    
    def _generate_bypass_techniques(self, filters: List[str]) -> List[str]:
        """Generate bypass techniques based on detected filters"""
        bypass_techniques = []
        
        for filter_type in filters:
            if filter_type == FilterType.HTML_ENTITY_ENCODING.value:
                bypass_techniques.extend([
                    "Use alternative HTML entities",
                    "Try numeric character references",
                    "Use hexadecimal entities",
                    "Mix different encoding types"
                ])
            
            elif filter_type == FilterType.URL_ENCODING.value:
                bypass_techniques.extend([
                    "Use double URL encoding",
                    "Try alternative percent encodings",
                    "Mix encoded and unencoded characters"
                ])
            
            elif filter_type == FilterType.BACKSLASH_ESCAPING.value:
                bypass_techniques.extend([
                    "Use alternative quote characters",
                    "Try Unicode escaping",
                    "Use template literals"
                ])
            
            elif filter_type == FilterType.CONTENT_FILTERING.value:
                bypass_techniques.extend([
                    "Use obfuscation techniques",
                    "Try alternative payloads",
                    "Use encoding variations",
                    "Fragment the payload"
                ])
        
        # Remove duplicates and return
        return list(set(bypass_techniques))
    
    def get_filter_recommendations(self, filters: List[str]) -> List[str]:
        """Get recommendations for bypassing detected filters"""
        if not filters:
            return ["No filters detected - standard payloads should work"]
        
        recommendations = []
        
        # General recommendations
        recommendations.extend([
            "Try alternative payload vectors",
            "Use encoding variations",
            "Fragment payloads across parameters",
            "Test different contexts"
        ])
        
        # Filter-specific recommendations
        analysis = self.analyze_filter_strength(filters)
        recommendations.extend(analysis['bypass_techniques'])
        
        return recommendations