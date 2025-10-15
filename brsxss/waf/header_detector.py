#!/usr/bin/env python3

"""
BRS-XSS WAF Header Detector

WAF detection based on HTTP headers.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Optional, Dict, Any
from .waf_types import WAFType, WAFInfo
from ..utils.logger import Logger

logger = Logger("waf.header_detector")


class HeaderDetector:
    """Detects WAF based on HTTP headers"""
    
    def __init__(self):
        """Initialize header detector"""
        self.header_signatures = {
            # Cloudflare
            'cf-ray': WAFType.CLOUDFLARE,
            'cf-cache-status': WAFType.CLOUDFLARE,
            'cf-request-id': WAFType.CLOUDFLARE,
            '__cfruid': WAFType.CLOUDFLARE,
            
            # AWS WAF
            'x-amzn-requestid': WAFType.AWS_WAF,
            'x-amz-cf-id': WAFType.AWS_WAF,
            'x-amzn-trace-id': WAFType.AWS_WAF,
            
            # Incapsula
            'x-iinfo': WAFType.INCAPSULA,
            'incap-ses': WAFType.INCAPSULA,
            'visid_incap': WAFType.INCAPSULA,
            
            # ModSecurity
            'mod_security': WAFType.MODSECURITY,
            'x-mod-security-message': WAFType.MODSECURITY,
            
            # Akamai
            'akamai-ghost-ip': WAFType.AKAMAI,
            'x-akamai-transformed': WAFType.AKAMAI,
            
            # Barracuda
            'barra': WAFType.BARRACUDA,
            'x-barracuda': WAFType.BARRACUDA,
            
            # F5 BIG-IP
                    'bigipserver': WAFType.F5_BIG_IP,
        'x-waf-event-info': WAFType.F5_BIG_IP,
            
            # Fortinet
            'fortigate': WAFType.FORTINET,
            'x-protected-by': WAFType.FORTINET
        }
    
    def detect_from_headers(self, headers: Dict[str, str]) -> Optional[WAFInfo]:
        """
        Detect WAF from HTTP headers.
        
        Args:
            headers: HTTP response headers
            
        Returns:
            WAF information if detected
        """
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Check for specific header signatures
        for header, waf_type in self.header_signatures.items():
            if header.lower() in headers_lower:
                return self._create_waf_info(waf_type, header, headers_lower[header.lower()])
        
        # Check header values for WAF indicators
        return self._check_header_values(headers_lower)
    
    def _create_waf_info(self, waf_type: WAFType, header: str, value: str) -> WAFInfo:
        """Create WAF info from detected header"""
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
        
        return WAFInfo(
            waf_type=waf_type,
            name=waf_names.get(waf_type, "Unknown WAF"),
            confidence=0.95,
            detection_method="header_analysis",
            detected_features=[f"header:{header}"],
            version=self._extract_version(value) if value else None
        )
    
    def _check_header_values(self, headers: Dict[str, str]) -> Optional[WAFInfo]:
        """Check header values for WAF indicators"""
        
        # Server header analysis
        server = headers.get('server', '')
        if server:
            if 'cloudflare' in server:
                return WAFInfo(
                    waf_type=WAFType.CLOUDFLARE,
                    name="Cloudflare",
                    confidence=0.9,
                    detection_method="server_header",
                    detected_features=["server_header"]
                )
            
            elif any(indicator in server for indicator in ['nginx', 'apache']) and 'modsecurity' in server:
                return WAFInfo(
                    waf_type=WAFType.MODSECURITY,
                    name="ModSecurity",
                    confidence=0.85,
                    detection_method="server_header",
                    detected_features=["server_header"]
                )
        
        # X-Protected-By header
        protected_by = headers.get('x-protected-by', '')
        if protected_by:
            if 'incapsula' in protected_by:
                return WAFInfo(
                    waf_type=WAFType.INCAPSULA,
                    name="Incapsula",
                    confidence=0.9,
                    detection_method="protection_header",
                    detected_features=["x-protected-by"]
                )
        
        # Generic security headers
        security_headers = [
            'x-content-security-policy',
            'x-frame-options',
            'x-xss-protection',
            'strict-transport-security'
        ]
        
        security_count = sum(1 for header in security_headers if header in headers)
        
        if security_count >= 3:
            return WAFInfo(
                waf_type=WAFType.UNKNOWN,
                name="Generic WAF/Security System",
                confidence=0.6,
                detection_method="security_headers",
                detected_features=[f"security_headers:{security_count}"]
            )
        
        return None
    
    def _extract_version(self, header_value: str) -> Optional[str]:
        """Extract version information from header value"""
        import re
        
        # Look for version patterns
        version_patterns = [
            r'v?(\d+\.\d+\.\d+)',
            r'v?(\d+\.\d+)',
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, header_value)
            if match:
                return match.group(1)
        
        return None
    
    def analyze_header_anomalies(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze headers for WAF-related anomalies"""
        anomalies = {
            'missing_standard_headers': [],
            'suspicious_headers': [],
            'header_modifications': [],
            'security_headers_count': 0
        }
        
        # Standard headers that might be missing due to WAF
        standard_headers = ['server', 'date', 'content-type', 'content-length']
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header in standard_headers:
            if header not in headers_lower:
                anomalies['missing_standard_headers'].append(header)  # type: ignore[attr-defined]
        
        # Suspicious header patterns
        suspicious_patterns = [
            'x-cache',
            'x-proxy',
            'x-forwarded',
            'x-real-ip',
            'x-powered-by'
        ]
        
        for header_name, header_value in headers_lower.items():
            for pattern in suspicious_patterns:
                if pattern in header_name or pattern in header_value:
                    anomalies['suspicious_headers'].append(header_name)  # type: ignore[attr-defined]
        
        # Count security headers
        security_headers = [
            'x-content-security-policy',
            'content-security-policy',
            'x-frame-options',
            'x-xss-protection',
            'x-content-type-options',
            'strict-transport-security'
        ]
        
        anomalies['security_headers_count'] = sum(
            1 for header in security_headers if header in headers_lower
        )
        
        return anomalies