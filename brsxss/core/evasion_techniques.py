#!/usr/bin/env python3

"""
BRS-XSS Evasion Techniques

WAF and filter evasion techniques for payload generation.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

import re
import random
from typing import List, Optional
from urllib.parse import quote
from ..utils.logger import Logger

logger = Logger("core.evasion_techniques")


class EvasionTechniques:
    """Implements various WAF and filter evasion techniques"""
    
    def apply_case_variations(self, payload: str) -> List[str]:
        """Apply case variation evasions"""
        variations = []
        
        # Upper case
        variations.append(payload.upper())
        
        # Lower case
        variations.append(payload.lower())
        
        # Mixed case (alternating)
        mixed = ''.join([
            c.upper() if i % 2 == 0 else c.lower() 
            for i, c in enumerate(payload)
        ])
        variations.append(mixed)
        
        # Random case
        random_case = ''.join([
            c.upper() if random.choice([True, False]) else c.lower()
            for c in payload
        ])
        variations.append(random_case)
        
        # Tag-specific case variations
        script_variations = [
            payload.replace('script', 'SCRIPT'),
            payload.replace('script', 'Script'),
            payload.replace('script', 'ScRiPt'),
            payload.replace('alert', 'ALERT'),
            payload.replace('alert', 'Alert'),
            payload.replace('onerror', 'ONERROR'),
            payload.replace('onerror', 'OnError')
        ]
        
        variations.extend([v for v in script_variations if v != payload])
        
        logger.debug(f"Generated {len(variations)} case variations")
        return variations
    
    def apply_url_encoding(self, payload: str) -> List[str]:
        """Apply URL encoding evasions"""
        variations = []
        
        # Full URL encoding
        variations.append(quote(payload))
        
        # Double URL encoding
        variations.append(quote(quote(payload)))
        
        # Partial URL encoding (special characters only)
        special_chars = ['<', '>', '"', "'", '&', '=', '(', ')', ';', '/']
        partial = payload
        for char in special_chars:
            if char in partial:
                partial = partial.replace(char, quote(char))
        variations.append(partial)
        
        # Mixed encoding
        mixed = payload
        for char in ['<', '>', '"']:
            if char in mixed:
                if random.choice([True, False]):
                    mixed = mixed.replace(char, quote(char))
        variations.append(mixed)
        
        logger.debug(f"Generated {len(variations)} URL encoding variations")
        return variations
    
    def apply_html_entity_encoding(self, payload: str) -> List[str]:
        """Apply HTML entity encoding evasions"""
        variations = []
        
        # Common HTML entities
        entities = {
            '<': ['&lt;', '&#60;', '&#x3c;'],
            '>': ['&gt;', '&#62;', '&#x3e;'],
            '"': ['&quot;', '&#34;', '&#x22;'],
            "'": ['&#39;', '&#x27;'],
            '&': ['&amp;', '&#38;', '&#x26;'],
            '=': ['&#61;', '&#x3d;'],
            '(': ['&#40;', '&#x28;'],
            ')': ['&#41;', '&#x29;'],
            '/': ['&#47;', '&#x2f;']
        }
        
        # Full entity encoding
        full_entity = payload
        for char, entity_list in entities.items():
            if char in full_entity:
                full_entity = full_entity.replace(char, entity_list[0])
        variations.append(full_entity)
        
        # Decimal entity encoding
        decimal_entity = payload
        for char, entity_list in entities.items():
            if char in decimal_entity and len(entity_list) > 1:
                decimal_entity = decimal_entity.replace(char, entity_list[1])
        variations.append(decimal_entity)
        
        # Hex entity encoding
        hex_entity = payload
        for char, entity_list in entities.items():
            if char in hex_entity and len(entity_list) > 2:
                hex_entity = hex_entity.replace(char, entity_list[2])
        variations.append(hex_entity)
        
        # Mixed entity encoding
        mixed_entity = payload
        for char, entity_list in entities.items():
            if char in mixed_entity:
                chosen_entity = random.choice(entity_list)
                mixed_entity = mixed_entity.replace(char, chosen_entity)
        variations.append(mixed_entity)
        
        logger.debug(f"Generated {len(variations)} HTML entity variations")
        return variations
    
    def apply_unicode_escaping(self, payload: str) -> List[str]:
        """Apply Unicode escaping evasions"""
        variations = []
        
        # JavaScript Unicode escaping
        js_unicode = payload
        unicode_map = {
            '<': '\\u003c',
            '>': '\\u003e',
            '"': '\\u0022',
            "'": '\\u0027',
            '&': '\\u0026',
            '=': '\\u003d',
            '(': '\\u0028',
            ')': '\\u0029',
            ';': '\\u003b',
            '/': '\\u002f'
        }
        
        for char, unicode_escape in unicode_map.items():
            if char in js_unicode:
                js_unicode = js_unicode.replace(char, unicode_escape)
        variations.append(js_unicode)
        
        # CSS Unicode escaping
        css_unicode = payload
        css_map = {
            '<': '\\3c ',
            '>': '\\3e ',
            '"': '\\22 ',
            "'": '\\27 ',
            '&': '\\26 ',
            '=': '\\3d ',
            '(': '\\28 ',
            ')': '\\29 ',
            ';': '\\3b ',
            '/': '\\2f '
        }
        
        for char, css_escape in css_map.items():
            if char in css_unicode:
                css_unicode = css_unicode.replace(char, css_escape)
        variations.append(css_unicode)
        
        # Hex escaping
        hex_escape = payload
        for char in ['<', '>', '"', "'", '&']:
            if char in hex_escape:
                hex_value = f'\\x{ord(char):02x}'
                hex_escape = hex_escape.replace(char, hex_value)
        variations.append(hex_escape)
        
        logger.debug(f"Generated {len(variations)} Unicode escape variations")
        return variations
    
    def apply_comment_insertions(self, payload: str) -> List[str]:
        """Apply comment insertion evasions"""
        variations = []
        
        # HTML comments
        html_variations = [
            payload.replace('<script', '<!--<script'),
            payload.replace('script>', 'script>-->'),
            payload.replace('<script>', '<!--<script>-->'),
            payload.replace('alert', 'ale<!---->rt'),
            payload.replace('=', '<!---->='),
            payload.replace('(', '<!---->(')
        ]
        variations.extend([v for v in html_variations if v != payload])
        
        # JavaScript comments
        js_variations = [
            payload.replace('alert', 'ale/**/rt'),
            payload.replace('=', '/**/=/**/'),
            payload.replace('(', '/**/('),
            payload.replace(')', ')/**/'),
            payload.replace(';', ';/**/'),
            payload.replace('script', 'scr/**/ipt')
        ]
        variations.extend([v for v in js_variations if v != payload])
        
        # CSS comments
        css_variations = [
            payload.replace('expression', 'expr/**/ession'),
            payload.replace('url', 'u/**/rl'),
            payload.replace('(', '/**/('),
            payload.replace(')', ')/**/')
        ]
        variations.extend([v for v in css_variations if v != payload])
        
        logger.debug(f"Generated {len(variations)} comment insertion variations")
        return variations
    
    def apply_whitespace_variations(self, payload: str) -> List[str]:
        """Apply whitespace variation evasions"""
        variations = []
        
        # Different whitespace characters
        whitespace_chars = ['\t', '\n', '\r', '\v', '\f', '\x0b', '\x0c']
        
        for ws_char in whitespace_chars:
            # Replace spaces with alternative whitespace
            if ' ' in payload:
                variations.append(payload.replace(' ', ws_char))
            
            # Insert whitespace around operators
            ws_variation = payload
            for operator in ['=', '<', '>', '(', ')']:
                if operator in ws_variation:
                    ws_variation = ws_variation.replace(operator, f'{ws_char}{operator}{ws_char}')
            variations.append(ws_variation)
        
        # Remove all whitespace
        no_space = re.sub(r'\s+', '', payload)
        variations.append(no_space)
        
        # Multiple spaces
        multi_space = payload.replace(' ', '   ')
        variations.append(multi_space)
        
        logger.debug(f"Generated {len(variations)} whitespace variations")
        return variations
    
    def apply_mixed_encoding(self, payload: str) -> List[str]:
        """Apply mixed encoding techniques"""
        variations = []
        
        # Combine URL and HTML entity encoding
        mixed1 = payload
        if '<' in mixed1:
            mixed1 = mixed1.replace('<', '%3c')
        if '>' in mixed1:
            mixed1 = mixed1.replace('>', '&gt;')
        if '"' in mixed1:
            mixed1 = mixed1.replace('"', '&#34;')
        variations.append(mixed1)
        
        # Combine case variation with encoding
        mixed2 = payload.upper()
        if '=' in mixed2:
            mixed2 = mixed2.replace('=', '%3d')
        variations.append(mixed2)
        
        # Combine Unicode with HTML entities
        mixed3 = payload
        if 'script' in mixed3:
            mixed3 = mixed3.replace('script', 'scr\\u0069pt')
        if '<' in mixed3:
            mixed3 = mixed3.replace('<', '&lt;')
        variations.append(mixed3)
        
        logger.debug(f"Generated {len(variations)} mixed encoding variations")
        return variations