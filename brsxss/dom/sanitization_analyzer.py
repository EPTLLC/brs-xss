#!/usr/bin/env python3

"""
BRS-XSS Sanitization Analyzer

Analysis of sanitization functions and bypass detection.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from typing import List, Tuple, Optional


class SanitizationAnalyzer:
    """Sanitization function analyzer"""
    
    # Known sanitization functions
    SANITIZATION_FUNCTIONS = [
        # Encoding functions
        'encodeURI', 'encodeURIComponent', 'decodeURI', 'decodeURIComponent',
        'escape', 'unescape', 'btoa', 'atob',
        
        # HTML encoding
        'htmlspecialchars', 'htmlentities', 'html_entity_decode',
        
        # Custom sanitization
        'sanitize', 'clean', 'escape', 'filter', 'validate',
        'stripTags', 'removeTags', 'purify',
        
        # Framework sanitization
        'DOMPurify.sanitize', '$.text', 'textContent',
        
        # Regex-based
        'replace', 'replaceAll', 'match', 'search',
    ]
    
    # Unsafe sanitization patterns
    UNSAFE_SANITIZATION_PATTERNS = [
        r'\.replace\([\'\"]/g[\'\"], [\'\"]{2}\)',  # .replace(/</g, "")
        r'\.replace\([\'\"]\<[\'\"], [\'\"]{2}\)',  # .replace("<", "")
        r'\.replace\([\'\"]\>[\'\"], [\'\"]{2}\)',  # .replace(">", "")
        r'\.replace\([\'\"]/script/gi[\'\"], [\'\"]{2}\)',  # .replace(/script/gi, "")
    ]
    
    @staticmethod
    def analyze_sanitization(code: str) -> Tuple[bool, bool, List[str]]:
        """
        Analyze sanitization in code.
        
        Args:
            code: Code to analyze
            
        Returns:
            Tuple[has_sanitization, bypasses_sanitization, sanitization_functions]
        """
        has_sanitization = False
        bypasses_sanitization = False
        sanitization_functions = []
        
        code_lower = code.lower()
        
        # Check for sanitization functions
        for func in SanitizationAnalyzer.SANITIZATION_FUNCTIONS:
            if func.lower() in code_lower:
                has_sanitization = True
                sanitization_functions.append(func)
        
        # Check for unsafe patterns
        for pattern in SanitizationAnalyzer.UNSAFE_SANITIZATION_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                bypasses_sanitization = True
                break
        
        # Additional check for incomplete sanitization
        if has_sanitization:
            # Check for incomplete sanitization
            if any(keyword in code_lower for keyword in ['replace', 'remove']) and \
               not any(keyword in code_lower for keyword in ['all', 'global', '/g']):
                bypasses_sanitization = True
        
        return has_sanitization, bypasses_sanitization, sanitization_functions