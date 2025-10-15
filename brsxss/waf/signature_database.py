#!/usr/bin/env python3

"""
BRS-XSS Signature Database

Database of WAF signatures with default and custom signature management.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import json
from typing import Dict, List, Optional
from dataclasses import asdict
from pathlib import Path

from .waf_types import WAFType
from .waf_signature import WAFSignature
from ..utils.logger import Logger

logger = Logger("waf.signature_database")


class SignatureDatabase:
    """WAF signature database"""
    
    def __init__(self, signatures_path: Optional[str] = None):
        """
        Initialize signature database.
        
        Args:
            signatures_path: Path to signature file
        """
        self.signatures_path = signatures_path or "config/signatures/waf_signatures.json"
        self.signatures: Dict[WAFType, List[WAFSignature]] = {}
        self._load_default_signatures()
        
        # Try to load custom signatures
        if Path(self.signatures_path).exists():
            self._load_custom_signatures()
    
    def _load_default_signatures(self):
        """Load built-in signatures"""
        
        # Cloudflare
        self.signatures[WAFType.CLOUDFLARE] = [
            WAFSignature(
                waf_type=WAFType.CLOUDFLARE,
                name="Cloudflare",
                header_patterns=[
                    r"cf-ray:\s*\w+",
                    r"server:\s*cloudflare",
                    r"cf-cache-status:",
                    r"cf-request-id:"
                ],
                required_headers=["cf-ray"],
                content_patterns=[
                    r"attention required.*cloudflare",
                    r"cloudflare.*security",
                    r"ray id:\s*\w+",
                    r"cloudflare\.com\/5xx-error"
                ],
                error_page_patterns=[
                    r"<title>.*attention required.*cloudflare.*</title>",
                    r"checking.*browser.*cloudflare"
                ],
                status_codes=[403, 503],
                confidence_weight=0.9
            )
        ]
        
        # AWS WAF
        self.signatures[WAFType.AWS_WAF] = [
            WAFSignature(
                waf_type=WAFType.AWS_WAF,
                name="AWS WAF",
                header_patterns=[
                    r"x-amzn-requestid:",
                    r"x-amz-cf-id:",
                    r"server:\s*cloudfront",
                    r"x-amz-cf-pop:"
                ],
                required_headers=["x-amzn-requestid"],
                content_patterns=[
                    r"aws.*waf",
                    r"access.*denied.*aws",
                    r"forbidden.*amazon",
                    r"cloudfront.*distribution"
                ],
                error_page_patterns=[
                    r"<title>.*403.*forbidden.*</title>"
                ],
                status_codes=[403],
                confidence_weight=0.85
            )
        ]
        
        # Incapsula
        self.signatures[WAFType.INCAPSULA] = [
            WAFSignature(
                waf_type=WAFType.INCAPSULA,
                name="Incapsula",
                header_patterns=[
                    r"x-iinfo:",
                    r"incap_ses:",
                    r"x-cdn:\s*incapsula",
                    r"incapsula-incident-id:"
                ],
                required_headers=["x-iinfo"],
                content_patterns=[
                    r"incapsula.*incident",
                    r"request.*unsuccessful.*incapsula",
                    r"incident.*id:\s*\d+",
                    r"imperva.*incapsula"
                ],
                error_page_patterns=[
                    r"<title>.*incapsula.*incident.*</title>",
                    r"incapsula.*security.*breach"
                ],
                status_codes=[403, 406],
                confidence_weight=0.9
            )
        ]
        
        # Sucuri
        self.signatures[WAFType.SUCURI] = [
            WAFSignature(
                waf_type=WAFType.SUCURI,
                name="Sucuri",
                header_patterns=[
                    r"x-sucuri-id:",
                    r"x-sucuri-cache:",
                    r"server:\s*sucuri\/cloudproxy",
                    r"x-sucuri-block:"
                ],
                required_headers=["x-sucuri-id"],
                content_patterns=[
                    r"access.*denied.*sucuri",
                    r"sucuri.*security",
                    r"blocked.*sucuri",
                    r"cloudproxy.*sucuri"
                ],
                error_page_patterns=[
                    r"<title>.*sucuri.*blocked.*</title>"
                ],
                status_codes=[403],
                confidence_weight=0.85
            )
        ]
        
        # Akamai
        self.signatures[WAFType.AKAMAI] = [
            WAFSignature(
                waf_type=WAFType.AKAMAI,
                name="Akamai",
                header_patterns=[
                    r"akamai-ghost-ip:",
                    r"x-akamai-request-id:",
                    r"server:\s*akamaighost",
                    r"x-cache-key:\s*akamai"
                ],
                required_headers=["x-akamai-request-id"],
                content_patterns=[
                    r"access.*denied.*akamai",
                    r"unauthorized.*akamai",
                    r"reference.*#\d+\.\w+",
                    r"akamai.*technologies"
                ],
                error_page_patterns=[
                    r"<title>.*access.*denied.*</title>"
                ],
                status_codes=[403],
                confidence_weight=0.8
            )
        ]
        
        # ModSecurity
        self.signatures[WAFType.MODSECURITY] = [
            WAFSignature(
                waf_type=WAFType.MODSECURITY,
                name="ModSecurity",
                header_patterns=[
                    r"x-mod-security-message:",
                    r"server:.*mod_security"
                ],
                required_headers=[],
                content_patterns=[
                    r"mod_security.*action",
                    r"not.*acceptable.*mod_security",
                    r"modsecurity.*rule",
                    r"apache.*mod_security"
                ],
                error_page_patterns=[
                    r"<title>.*406.*not acceptable.*</title>",
                    r"mod_security.*violation"
                ],
                status_codes=[406],
                confidence_weight=0.7
            )
        ]
        
        # F5 BIG-IP
        self.signatures[WAFType.F5_BIG_IP] = [
            WAFSignature(
                waf_type=WAFType.F5_BIG_IP,
                name="F5 BIG-IP",
                header_patterns=[
                    r"bigipserver:",
                    r"x-wa-info:",
                    r"f5-ltm-pool:",
                    r"server:.*bigip"
                ],
                required_headers=["bigipserver"],
                content_patterns=[
                    r"f5.*big-?ip",
                    r"bigip.*ltm",
                    r"application.*security.*manager"
                ],
                error_page_patterns=[
                    r"<title>.*request.*rejected.*</title>"
                ],
                status_codes=[403],
                confidence_weight=0.8
            )
        ]
        
        # Barracuda
        self.signatures[WAFType.BARRACUDA] = [
            WAFSignature(
                waf_type=WAFType.BARRACUDA,
                name="Barracuda",
                header_patterns=[
                    r"barra_counter_session:",
                    r"bncounter:",
                    r"x-barra-counter:"
                ],
                required_headers=["barra_counter_session"],
                content_patterns=[
                    r"barracuda.*networks",
                    r"barra.*waf",
                    r"web.*application.*firewall.*barracuda"
                ],
                error_page_patterns=[
                    r"<title>.*barracuda.*</title>"
                ],
                status_codes=[403],
                confidence_weight=0.8
            )
        ]
    
    def _load_custom_signatures(self):
        """Load custom signatures from file"""
        try:
            with open(self.signatures_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for waf_type_str, signatures_data in data.items():
                try:
                    waf_type = WAFType(waf_type_str)
                    
                    signatures = []
                    for sig_data in signatures_data:
                        # Ensure proper enum type inside signatures
                        sig_data = dict(sig_data)
                        sig_data['waf_type'] = waf_type
                        signature = WAFSignature(**sig_data)
                        signatures.append(signature)
                    
                    # Merge with built-in signatures
                    if waf_type in self.signatures:
                        self.signatures[waf_type].extend(signatures)
                    else:
                        self.signatures[waf_type] = signatures
                    
                except (ValueError, TypeError) as e:
                    logger.warning(f"Error loading signature for {waf_type_str}: {e}")
            
            logger.info(f"Custom signatures loaded from {self.signatures_path}")
            
        except Exception as e:
            logger.warning(f"Failed to load custom signatures: {e}")
    
    def save_signatures(self):
        """Save signatures to file"""
        try:
            # Create directory if not exists
            Path(self.signatures_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Convert to JSON-compatible format
            data = {}
            for waf_type, signatures in self.signatures.items():
                serializable = []
                for sig in signatures:
                    sig_dict = asdict(sig)
                    # Convert enum field to value for JSON
                    sig_dict['waf_type'] = waf_type.value
                    serializable.append(sig_dict)
                data[waf_type.value] = serializable
            
            with open(self.signatures_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Signatures saved to {self.signatures_path}")
            
        except Exception as e:
            logger.error(f"Error saving signatures: {e}")
    
    def add_signature(self, signature: WAFSignature):
        """Add new signature"""
        if signature.waf_type not in self.signatures:
            self.signatures[signature.waf_type] = []
        
        self.signatures[signature.waf_type].append(signature)
        logger.info(f"Added signature for {signature.name}")
    
    def get_signatures_for_waf(self, waf_type: WAFType) -> List[WAFSignature]:
        """Get signatures for specific WAF"""
        return self.signatures.get(waf_type, [])
    
    def get_all_signatures(self) -> List[WAFSignature]:
        """Get all signatures"""
        all_signatures = []
        for signatures in self.signatures.values():
            all_signatures.extend(signatures)
        return all_signatures