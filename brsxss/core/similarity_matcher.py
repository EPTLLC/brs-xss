#!/usr/bin/env python3

"""
BRS-XSS Similarity Matcher

String similarity matching for reflection detection.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Tuple, Optional
from ..utils.logger import Logger

logger = Logger("core.similarity_matcher")


class SimilarityMatcher:
    """Matches similar strings for reflection detection"""
    
    def __init__(self, threshold: float = 0.8):
        """
        Initialize similarity matcher.
        
        Args:
            threshold: Similarity threshold (0.0-1.0)
        """
        self.threshold = threshold
        
    def find_similar_reflections(
        self,
        needle: str,
        haystack: str,
        min_length: int = 3
    ) -> List[Tuple[int, str, float]]:
        """
        Find similar reflections in content.
        
        Args:
            needle: String to search for
            haystack: Content to search in
            min_length: Minimum match length
            
        Returns:
            List of (position, matched_string, similarity_score)
        """
        if len(needle) < min_length:
            return []
        
        matches = []
        haystack_lower = haystack.lower()
        needle_lower = needle.lower()
        
        # Find exact matches first
        exact_matches = self._find_exact_matches(needle, haystack)
        for pos, match in exact_matches:
            matches.append((pos, match, 1.0))
        
        # Find partial matches
        if not exact_matches:
            partial_matches = self._find_partial_matches(needle_lower, haystack_lower, min_length)
            matches.extend(partial_matches)
        
        # Find fuzzy matches
        if not matches:
            fuzzy_matches = self._find_fuzzy_matches(needle_lower, haystack_lower, min_length)
            matches.extend(fuzzy_matches)
        
        # Filter by threshold and sort by similarity
        filtered_matches = [
            (pos, match, score) for pos, match, score in matches
            if score >= self.threshold
        ]
        
        filtered_matches.sort(key=lambda x: x[2], reverse=True)
        
        return filtered_matches
    
    def _find_exact_matches(self, needle: str, haystack: str) -> List[Tuple[int, str]]:
        """Find exact string matches"""
        matches = []
        start = 0
        
        while True:
            pos = haystack.find(needle, start)
            if pos == -1:
                break
            
            matches.append((pos, needle))
            start = pos + 1
        
        return matches
    
    def _find_partial_matches(
        self,
        needle: str,
        haystack: str,
        min_length: int
    ) -> List[Tuple[int, str, float]]:
        """Find partial string matches"""
        matches = []
        
        # Try different substring lengths
        for length in range(len(needle), min_length - 1, -1):
            for start_pos in range(len(needle) - length + 1):
                substring = needle[start_pos:start_pos + length]
                
                # Find this substring in haystack
                pos = 0
                while True:
                    found_pos = haystack.find(substring, pos)
                    if found_pos == -1:
                        break
                    
                    # Calculate similarity score
                    similarity = length / len(needle)
                    matches.append((found_pos, substring, similarity))
                    
                    pos = found_pos + 1
        
        return matches
    
    def _find_fuzzy_matches(
        self,
        needle: str,
        haystack: str,
        min_length: int
    ) -> List[Tuple[int, str, float]]:
        """Find fuzzy string matches using sliding window"""
        matches = []
        needle_len = len(needle)
        
        # Try different window sizes
        for window_size in range(min(needle_len + 10, len(haystack)), min_length - 1, -1):
            for i in range(len(haystack) - window_size + 1):
                window = haystack[i:i + window_size]
                similarity = self._calculate_similarity(needle, window)
                
                if similarity >= self.threshold:
                    matches.append((i, window, similarity))
        
        return matches
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings"""
        if not str1 or not str2:
            return 0.0
        
        if str1 == str2:
            return 1.0
        
        # Use Levenshtein distance for similarity
        distance = self._levenshtein_distance(str1, str2)
        max_len = max(len(str1), len(str2))
        
        return 1.0 - (distance / max_len) if max_len > 0 else 0.0
    
    def _levenshtein_distance(self, str1: str, str2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(str1) < len(str2):
            return self._levenshtein_distance(str2, str1)
        
        if len(str2) == 0:
            return len(str1)
        
        previous_row = list(range(len(str2) + 1))
        
        for i, char1 in enumerate(str1):
            current_row = [i + 1]
            
            for j, char2 in enumerate(str2):
                # Cost of insertions, deletions, or substitutions
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (char1 != char2)
                
                current_row.append(min(insertions, deletions, substitutions))
            
            previous_row = current_row
        
        return previous_row[-1]
    
    def find_encoded_reflections(
        self,
        needle: str,
        haystack: str
    ) -> List[Tuple[int, str, str]]:
        """
        Find encoded reflections of the needle in haystack.
        
        Returns:
            List of (position, encoded_string, encoding_type)
        """
        encoded_matches = []
        
        # Common encoding patterns
        encodings = {
            'html_entities': self._html_entity_encode,
            'url_encoding': self._url_encode,
            'unicode_escape': self._unicode_escape,
            'hex_escape': self._hex_escape
        }
        
        for encoding_name, encoding_func in encodings.items():
            try:
                encoded_needle = encoding_func(needle)
                exact_matches = self._find_exact_matches(encoded_needle, haystack)
                
                for pos, match in exact_matches:
                    encoded_matches.append((pos, match, encoding_name))
                    
            except Exception as e:
                logger.debug(f"Encoding {encoding_name} failed: {e}")
                continue
        
        return encoded_matches
    
    def _html_entity_encode(self, text: str) -> str:
        """HTML entity encode text"""
        entities = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;'
        }
        
        encoded = text
        for char, entity in entities.items():
            encoded = encoded.replace(char, entity)
        
        return encoded
    
    def _url_encode(self, text: str) -> str:
        """URL encode text"""
        import urllib.parse
        return urllib.parse.quote(text)
    
    def _unicode_escape(self, text: str) -> str:
        """Unicode escape text"""
        return text.encode('unicode_escape').decode('ascii')
    
    def _hex_escape(self, text: str) -> str:
        """Hex escape text"""
        return ''.join(f'\\x{ord(c):02x}' for c in text)
    
    def calculate_reflection_quality(
        self,
        original: str,
        reflected: str
    ) -> dict:
        """
        Calculate reflection quality metrics.
        
        Returns:
            Dictionary with quality metrics
        """
        if not original or not reflected:
            return {
                'similarity': 0.0,
                'completeness': 0.0,
                'accuracy': 0.0,
                'char_preservation': 0.0
            }
        
        # Overall similarity
        similarity = self._calculate_similarity(original, reflected)
        
        # Completeness (how much of original is in reflected)
        completeness = len(reflected) / len(original) if len(original) > 0 else 0.0
        completeness = min(completeness, 1.0)  # Cap at 1.0
        
        # Accuracy (how accurate the reflection is)
        accuracy = similarity
        
        # Character preservation
        original_chars = set(original.lower())
        reflected_chars = set(reflected.lower())
        common_chars = original_chars.intersection(reflected_chars)
        char_preservation = len(common_chars) / len(original_chars) if original_chars else 0.0
        
        return {
            'similarity': similarity,
            'completeness': completeness,
            'accuracy': accuracy,
            'char_preservation': char_preservation
        }