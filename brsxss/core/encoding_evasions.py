#!/usr/bin/env python3

"""
BRS-XSS Encoding Evasions

Encoding-based WAF evasion techniques.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

import random
from typing import List, Optional
from urllib.parse import quote, quote_plus
from .evasion_types import UNICODE_ALTERNATIVES, HTML_ENTITY_MAP, WHITESPACE_CHARS

from ..utils.logger import Logger

logger = Logger("core.encoding_evasions")


class EncodingEvasions:
    """
    Encoding-based evasion techniques.
    
    Techniques:
    - Unicode encoding
    - HTML entity encoding  
    - URL encoding
    - Mixed encoding
    """
    
    def __init__(self):
        """Initialize encoding evasions"""
        logger.debug("Encoding evasions initialized")
    
    def apply_unicode_encoding(self, payload: str) -> str:
        """Apply Unicode encoding to bypass filters"""
        
        result = payload
        
        # Replace some characters with Unicode alternatives
        for char, alternatives in UNICODE_ALTERNATIVES.items():
            if char in result and random.random() < 0.3:
                alternative = random.choice(alternatives)
                # Replace first occurrence only
                result = result.replace(char, alternative, 1)
        
        return result
    
    def apply_html_entity_encoding(self, payload: str) -> str:
        """Apply HTML entity encoding variations"""
        
        result = payload
        for char, entities in HTML_ENTITY_MAP.items():
            if char in result and random.random() < 0.2:
                entity = random.choice(entities)
                result = result.replace(char, entity, 1)
        
        return result
    
    def apply_url_encoding(self, payload: str) -> str:
        """Apply URL encoding variations"""
        
        if random.random() < 0.3:
            # Double URL encoding
            return quote(quote(payload, safe=''), safe='')
        elif random.random() < 0.5:
            # Partial URL encoding
            chars_to_encode = ['<', '>', '"', "'", '(', ')', '=', ' ']
            result = payload
            for char in chars_to_encode:
                if char in result and random.random() < 0.4:
                    result = result.replace(char, quote(char), 1)
            return result
        else:
            return quote_plus(payload)
    
    def apply_mixed_encoding(self, payload: str) -> str:
        """Apply mixed encoding techniques"""
        
        result = ''
        for i, char in enumerate(payload):
            if i % 3 == 0 and char in UNICODE_ALTERNATIVES:
                # Unicode encoding
                alternatives = UNICODE_ALTERNATIVES[char]
                result += random.choice(alternatives)
            elif i % 3 == 1 and char in HTML_ENTITY_MAP:
                # HTML entity encoding
                entities = HTML_ENTITY_MAP[char]
                result += random.choice(entities)
            elif i % 3 == 2 and char in ['<', '>', ' ', '=']:
                # URL encoding
                result += quote(char)
            else:
                result += char
        
        return result
    
    def generate_encoded_payloads(self, payload: str) -> List[str]:
        """Generate various encoded versions of payload"""
        
        encoded_versions = []
        
        # Base64 encoding (for certain contexts)
        import base64
        try:
            b64_payload = base64.b64encode(payload.encode()).decode()
            encoded_versions.append(f'eval(atob("{b64_payload}"))')
        except Exception:
            pass
        
        # Hex encoding
        hex_payload = ''.join(f'\\x{ord(c):02x}' for c in payload)
        encoded_versions.append(hex_payload)
        
        # Unicode escape sequences
        unicode_payload = ''.join(f'\\u{ord(c):04x}' for c in payload)
        encoded_versions.append(unicode_payload)
        
        # Octal encoding
        octal_payload = ''.join(f'\\{ord(c):03o}' for c in payload)
        encoded_versions.append(octal_payload)
        
        return encoded_versions
    
    def apply_whitespace_manipulation(self, payload: str) -> str:
        """Apply whitespace manipulation techniques"""
        
        result = payload
        
        # Replace some spaces with alternative whitespace
        if ' ' in result and random.random() < 0.4:
            alternative = random.choice(WHITESPACE_CHARS[1:])
            result = result.replace(' ', alternative, 1)
        
        # Add extra whitespace in strategic locations
        if random.random() < 0.3:
            positions = ['=', '(', ')', '<', '>']
            for pos in positions:
                if pos in result and random.random() < 0.5:
                    ws = random.choice(WHITESPACE_CHARS)
                    result = result.replace(pos, f'{pos}{ws}', 1)
                    break
        
        return result