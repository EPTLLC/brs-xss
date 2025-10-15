#!/usr/bin/env python3

"""
BRS-XSS WAF Content Detector

WAF detection based on response content.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from typing import Optional, Dict, Any
from .waf_types import WAFType, WAFInfo
from ..utils.logger import Logger

logger = Logger("waf.content_detector")


class ContentDetector:
    """Detects WAF based on response content"""
    
    def __init__(self):
        """Initialize content detector"""
        self.content_signatures = {
            # Cloudflare
            'cloudflare': {
                'patterns': ['cloudflare', 'cf-ray', 'attention required', 'checking your browser'],
                'waf_type': WAFType.CLOUDFLARE,
                'confidence': 0.9
            },
            
            # AWS WAF
            'aws_waf': {
                'patterns': ['aws', 'amazon', 'cloudfront', 'aws waf'],
                'waf_type': WAFType.AWS_WAF,
                'confidence': 0.8
            },
            
            # Incapsula
            'incapsula': {
                'patterns': ['incapsula', 'incident id', 'imperva', 'visid_incap'],
                'waf_type': WAFType.INCAPSULA,
                'confidence': 0.9
            },
            
            # ModSecurity
            'modsecurity': {
                'patterns': ['mod_security', 'modsecurity', 'mod security'],
                'waf_type': WAFType.MODSECURITY,
                'confidence': 0.85
            },
            
            # Akamai
            'akamai': {
                'patterns': ['akamai', 'reference #', 'ghost'],
                'waf_type': WAFType.AKAMAI,
                'confidence': 0.8
            },
            
            # Barracuda
            'barracuda': {
                'patterns': ['barracuda', 'barra', 'you have been blocked'],
                'waf_type': WAFType.BARRACUDA,
                'confidence': 0.85
            },
            
            # F5 BIG-IP
            'f5_bigip': {
                'patterns': ['f5', 'bigip', 'big-ip', 'tmui'],
                'waf_type': WAFType.F5_BIG_IP,
                'confidence': 0.8
            },
            
            # Fortinet
            'fortinet': {
                'patterns': ['fortinet', 'fortigate', 'fortiweb'],
                'waf_type': WAFType.FORTINET,
                'confidence': 0.8
            }
        }
        
        self.blocking_indicators = [
            'blocked', 'denied', 'forbidden', 'unauthorized', 'suspicious',
            'malicious', 'attack', 'violation', 'security', 'firewall',
            'protection', 'incident', 'reference', 'ray id', 'access denied',
            'request rejected', 'not allowed', 'invalid request'
        ]
    
    def detect_from_content(self, content: str, method: str = "content_analysis") -> Optional[WAFInfo]:
        """
        Detect WAF from response content.
        
        Args:
            content: Response content
            method: Detection method name
            
        Returns:
            WAF information if detected
        """
        content_lower = content.lower()
        
        # Check for specific WAF signatures
        for signature_name, signature_data in self.content_signatures.items():
            for pattern in signature_data['patterns']:
                if pattern in content_lower:
                    return WAFInfo(
                        waf_type=signature_data['waf_type'],
                        name=self._get_waf_name(signature_data['waf_type']),
                        confidence=signature_data['confidence'],
                        detection_method=method,
                        detected_features=[f"content_pattern:{pattern}"],
                        # additional_info removed - not supported by WAFInfo
                    )
        
        # Check for generic blocking indicators
        blocking_detected = self._detect_blocking_behavior(content_lower)
        if blocking_detected:
            return blocking_detected
        
        return None
    
    def _get_waf_name(self, waf_type: WAFType) -> str:
        """Get WAF name from type"""
        waf_names = {
            WAFType.CLOUDFLARE: "Cloudflare",
            WAFType.AWS_WAF: "AWS WAF",
            WAFType.INCAPSULA: "Incapsula",
            WAFType.MODSECURITY: "ModSecurity",
            WAFType.AKAMAI: "Akamai",
            WAFType.BARRACUDA: "Barracuda",
            WAFType.F5_BIG_IP: "F5 BIG-IP",
            WAFType.FORTINET: "Fortinet FortiGate"
        }
        return waf_names.get(waf_type, "Unknown WAF")
    
    def _detect_blocking_behavior(self, content: str) -> Optional[WAFInfo]:
        """Detect generic blocking behavior"""
        blocking_count = sum(1 for indicator in self.blocking_indicators if indicator in content)
        
        if blocking_count >= 2:
            return WAFInfo(
                waf_type=WAFType.UNKNOWN,
                name="Unknown WAF",
                confidence=0.6,
                detection_method="blocking_behavior",
                detected_features=[f"blocking_indicators:{blocking_count}"],
                blocking_level="medium"
            )
        
        return None
    
    def _extract_additional_info(self, content: str, pattern: str) -> Dict[str, str]:
        """Extract additional information from content"""
        additional_info = {}
        
        # Extract incident/reference IDs
        id_patterns = [
            r'incident[:\s]+([a-zA-Z0-9\-]+)',
            r'reference[:\s]+#?([a-zA-Z0-9\-]+)',
            r'ray[:\s]+id[:\s]+([a-zA-Z0-9\-]+)',
            r'request[:\s]+id[:\s]+([a-zA-Z0-9\-]+)'
        ]
        
        for id_pattern in id_patterns:
            match = re.search(id_pattern, content, re.IGNORECASE)
            if match:
                additional_info['incident_id'] = match.group(1)
                break
        
        # Extract timestamp if present
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{10,13})'  # Unix timestamp
        ]
        
        for ts_pattern in timestamp_patterns:
            match = re.search(ts_pattern, content)
            if match:
                additional_info['timestamp'] = match.group(1)
                break
        
        return additional_info
    
    def analyze_error_pages(self, content: str) -> Dict[str, Any]:
        """Analyze error pages for WAF characteristics"""
        analysis: Dict[str, Any] = {
            'is_error_page': False,
            'error_type': None,
            'waf_indicators': [],
            'custom_error_page': False,
            'security_focused': False
        }
        
        content_lower = content.lower()
        
        # Check if it's an error page
        error_indicators = [
            '403', '404', '500', '502', '503',
            'forbidden', 'not found', 'error', 'denied'
        ]
        
        if any(indicator in content_lower for indicator in error_indicators):
            analysis['is_error_page'] = True
        
        # Determine error type
        if '403' in content_lower or 'forbidden' in content_lower:
            analysis['error_type'] = '403_forbidden'
        elif '404' in content_lower or 'not found' in content_lower:
            analysis['error_type'] = '404_not_found'
        elif any(code in content_lower for code in ['500', '502', '503']):
            analysis['error_type'] = 'server_error'
        
        # Check for WAF-specific indicators
        waf_error_indicators = [
            'web application firewall',
            'security violation',
            'malicious request',
            'suspicious activity',
            'blocked by security policy',
            'request rejected by policy'
        ]
        
        for indicator in waf_error_indicators:
            if indicator in content_lower:
                analysis['waf_indicators'].append(indicator)
                analysis['security_focused'] = True
        
        # Check for custom error page
        if len(content) > 1000 and any(tag in content_lower for tag in ['<html>', '<body>', '<div>']):
            analysis['custom_error_page'] = True
        
        return analysis
    
    def detect_javascript_challenges(self, content: str) -> Dict[str, Any]:
        """Detect JavaScript challenges (like Cloudflare's)"""
        js_analysis: Dict[str, Any] = {
            'has_js_challenge': False,
            'challenge_type': None,
            'challenge_indicators': []
        }
        
        content_lower = content.lower()
        
        # Cloudflare challenge indicators
        cf_indicators = [
            'checking your browser',
            'please wait while we check',
            'cloudflare',
            'cf-ray',
            'just a moment'
        ]
        
        if any(indicator in content_lower for indicator in cf_indicators):
            js_analysis['has_js_challenge'] = True
            js_analysis['challenge_type'] = 'cloudflare'
            js_analysis['challenge_indicators'].extend([
                ind for ind in cf_indicators if ind in content_lower
            ])
        
        # Generic JS challenge patterns
        js_patterns = [
            r'document\.cookie\s*=',
            r'window\.location\s*=',
            r'settimeout\s*\(',
            r'eval\s*\(',
            r'challenge'
        ]
        
        for pattern in js_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                js_analysis['has_js_challenge'] = True
                js_analysis['challenge_indicators'].append(f"js_pattern:{pattern}")
        
        return js_analysis