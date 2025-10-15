#!/usr/bin/env python3

"""
BRS-XSS Reflection Analyzer

Core reflection analysis logic.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from typing import List, Optional
from .reflection_types import ReflectionPoint, ReflectionType, ReflectionContext
from ..utils.logger import Logger

logger = Logger("core.reflection_analyzer")


class ReflectionAnalyzer:
    """Analyzes reflection characteristics and quality"""
    
    def __init__(self):
        """Initialize reflection analyzer"""
        self.filter_patterns = {
            # HTML entities
            '&lt;': '<',
            '&gt;': '>',
            '&quot;': '"',
            '&amp;': '&',
            '&#x27;': "'",
            '&#39;': "'",
            
            # URL encoding
            '%3C': '<',
            '%3E': '>',
            '%22': '"',
            '%27': "'",
            '%26': '&',
            
            # Other common filters
            '&apos;': "'",
            '&#34;': '"',
            '&#60;': '<',
            '&#62;': '>'
        }
    
    def analyze_reflection_point(
        self,
        original_value: str,
        reflected_value: str,
        position: int,
        response_content: str
    ) -> ReflectionPoint:
        """
        Analyze a single reflection point.
        
        Args:
            original_value: Original input value
            reflected_value: What was actually reflected
            position: Position in response
            response_content: Full response content
            
        Returns:
            Analyzed reflection point
        """
        # Determine reflection type
        reflection_type = self._determine_reflection_type(original_value, reflected_value)
        
        # Analyze context
        context = self._analyze_context(position, response_content)
        
        # Calculate quality metrics
        completeness = self.calculate_completeness(original_value, reflected_value)
        accuracy = self.calculate_accuracy(original_value, reflected_value)
        chars_preserved = self.calculate_character_preservation(original_value, reflected_value)
        
        # Extract surrounding content
        surrounding = self.extract_surrounding_content(position, response_content, len(reflected_value))
        
        # Detect applied encoding/filtering
        encoding = self._detect_encoding(original_value, reflected_value)
        filters = self._detect_filters(original_value, reflected_value)
        
        # Analyze special characters
        special_chars: List[str] = []  # self._analyze_special_characters(original_value, reflected_value)
        
        return ReflectionPoint(
            position=position,
            reflected_value=reflected_value,
            original_value=original_value,
            reflection_type=reflection_type,
            context=context,
            completeness=completeness,
            accuracy=accuracy,
            characters_preserved=chars_preserved,
            surrounding_content=surrounding,
            special_chars_preserved=special_chars,
            encoding_applied=encoding,
            filters_detected=filters
        )
    
    def _determine_reflection_type(self, original: str, reflected: str) -> ReflectionType:
        """Determine the type of reflection"""
        if original == reflected:
            return ReflectionType.EXACT
        
        if not reflected or reflected.isspace():
            return ReflectionType.NOT_REFLECTED
        
        # Check for encoding
        # if self._is_encoded_reflection(original, reflected):
        #     return ReflectionType.ENCODED
        
        # Check for filtering
        # if self._is_filtered_reflection(original, reflected):
        #     return ReflectionType.FILTERED
        
        # Check for obfuscation
        if self._is_obfuscated_reflection(original, reflected):
            return ReflectionType.OBFUSCATED
        
        # Check if it's a partial reflection
        if original in reflected or reflected in original:
            return ReflectionType.PARTIAL
        
        # Check for modifications
        if self._calculate_similarity(original, reflected) > 0.6:
            return ReflectionType.MODIFIED
        
        return ReflectionType.NOT_REFLECTED
    
    def _analyze_context(self, position: int, content: str) -> ReflectionContext:
        """Analyze the context where reflection occurs"""
        # Get context around position
        start = max(0, position - 100)
        end = min(len(content), position + 100)
        context_content = content[start:end].lower()
        
        # Check for JavaScript context
        if any(pattern in context_content for pattern in ['<script', 'javascript:', 'eval(']):
            return ReflectionContext.JAVASCRIPT
        
        # Check for CSS context
        if any(pattern in context_content for pattern in ['<style', 'style=', 'css']):
            return ReflectionContext.CSS_STYLE
        
        # Check for HTML comment
        if '<!--' in context_content and '-->' in context_content:
            return ReflectionContext.HTML_COMMENT
        
        # Check for HTML attribute
        if re.search(r'\w+\s*=\s*["\']?[^"\']*$', context_content[:position-start]):
            return ReflectionContext.HTML_ATTRIBUTE
        
        # Check for URL parameter
        if any(char in context_content for char in ['?', '&', '=']):
            return ReflectionContext.URL_PARAMETER
        
        # Default to HTML content
        return ReflectionContext.HTML_CONTENT
    
    def calculate_completeness(self, original: str, reflected: str) -> float:
        """Calculate how complete the reflection is"""
        if not original:
            return 1.0
        
        if not reflected:
            return 0.0
        
        # Find longest common subsequence
        original_chars = set(original.lower())
        reflected_chars = set(reflected.lower())
        
        common_chars = original_chars.intersection(reflected_chars)
        return len(common_chars) / len(original_chars) if original_chars else 0.0
    
    def calculate_accuracy(self, original: str, reflected: str) -> float:
        """Calculate accuracy of reflection"""
        if not original or not reflected:
            return 0.0
        
        # Use character-level similarity
        return self._calculate_similarity(original, reflected)
    
    def calculate_character_preservation(self, original: str, reflected: str) -> float:
        """Calculate percentage of characters preserved"""
        if not original:
            return 1.0
        
        preserved_count = 0
        for char in original:
            if char in reflected:
                preserved_count += 1
        
        return preserved_count / len(original)
    
    def extract_surrounding_content(self, position: int, content: str, length: int) -> str:
        """Extract content around the reflection point"""
        start = max(0, position - 50)
        end = min(len(content), position + length + 50)
        return content[start:end]
    
    def _detect_encoding(self, original: str, reflected: str) -> str:
        """Detect encoding applied to reflection"""
        if original == reflected:
            return "none"
        
        # Check for HTML entity encoding
        if any(entity in reflected for entity in ['&lt;', '&gt;', '&quot;', '&amp;']):
            return "html_entities"
        
        # Check for URL encoding
        if any(encoded in reflected for encoded in ['%3C', '%3E', '%22', '%27']):
            return "url_encoding"
        
        # Check for Unicode escaping
        if '\\u' in reflected or '\\x' in reflected:
            return "unicode_escaping"
        
        # Check for base64 encoding
        if len(reflected) > len(original) * 1.3 and reflected.isalnum():
            return "base64"
        
        return "unknown"
    
    def _detect_filters(self, original: str, reflected: str) -> List[str]:
        """Detect filters applied to reflection"""
        filters: List[str] = []
        
        # Check for character removal
        if len(reflected) < len(original) * 0.5:
            filters.append("character_removal")
            return filters
        
        # Check for character removal
        dangerous_chars = ['<', '>', '"', "'", '&']
        removed_chars = sum(1 for char in dangerous_chars if char in original and char not in reflected)
        
        return filters
    
    def _is_obfuscated_reflection(self, original: str, reflected: str) -> bool:
        """Check if reflection is obfuscated"""
        # Look for obfuscation patterns
        obfuscation_patterns = [
            r'\\x[0-9a-fA-F]{2}',  # Hex escaping
            r'\\u[0-9a-fA-F]{4}',  # Unicode escaping
            r'\\[0-9]{3}',         # Octal escaping
            r'&\w+;',              # HTML entities
            r'%[0-9a-fA-F]{2}'     # URL encoding
        ]
        
        for pattern in obfuscation_patterns:
            if re.search(pattern, reflected):
                return True
        
        return False
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings"""
        if not str1 or not str2:
            return 0.0
        
        if str1 == str2:
            return 1.0
        
        # Simple character-based similarity
        longer = str1 if len(str1) > len(str2) else str2
        shorter = str2 if len(str1) > len(str2) else str1
        
        if len(longer) == 0:
            return 1.0
        
        # Count matching characters
        matches = sum(1 for i, char in enumerate(shorter) if i < len(longer) and char == longer[i])
        
        return matches / len(longer)