#!/usr/bin/env python3

"""
BRS-XSS Encoding Engine

Payload encoding engine for WAF evasion.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import base64
import urllib.parse


class EncodingEngine:
    """Payload encoding engine"""
    
    @staticmethod
    def url_encode(payload: str, double: bool = False) -> str:
        """URL encoding"""
        encoded = urllib.parse.quote(payload, safe='')
        if double:
            encoded = urllib.parse.quote(encoded, safe='')
        return encoded
    
    @staticmethod
    def html_encode(payload: str, use_hex: bool = False) -> str:
        """HTML entity encoding"""
        if use_hex:
            return ''.join([f'&#x{ord(c):x};' for c in payload])
        else:
            return ''.join([f'&#{ord(c)};' for c in payload])
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode escape encoding"""
        return ''.join([f'\\u{ord(c):04x}' for c in payload])
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encoding"""
        return ''.join([f'\\x{ord(c):02x}' for c in payload])
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encoding"""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def mixed_encoding(payload: str) -> str:
        """Mixed encoding (different characters - different methods)"""
        result = ""
        for i, char in enumerate(payload):
            if i % 4 == 0:
                result += f'%{ord(char):02x}'
            elif i % 4 == 1:
                result += f'&#{ord(char)};'
            elif i % 4 == 2:
                result += f'\\u{ord(char):04x}'
            else:
                result += char
        return result