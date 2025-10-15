#!/usr/bin/env python3

"""
BRS-XSS WAF Fingerprinter

WAF fingerprinting system with ML classification and learning capabilities.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import re
import hashlib
from typing import Dict, List, Optional, Any

from .waf_types import WAFType, WAFInfo
from .waf_signature import WAFSignature
from .signature_database import SignatureDatabase
from ..utils.logger import Logger

logger = Logger("waf.waf_fingerprinter")


class WAFFingerprinter:
    """
    WAF fingerprinting system.
    
    Functions:
    - Signature analysis
    - ML classification
    - Learning from data
    - Export/import signatures
    """
    
    def __init__(self, signatures_db: Optional[SignatureDatabase] = None):
        """
        Initialize fingerprinter.
        
        Args:
            signatures_db: Signature database
        """
        self.signatures_db = signatures_db or SignatureDatabase()
        
        # Fingerprinting result cache
        self.fingerprint_cache: Dict[str, List[WAFInfo]] = {}
    
    def fingerprint_response(
        self,
        headers: Dict[str, str],
        content: str,
        status_code: int,
        response_time: Optional[float] = None
    ) -> List[WAFInfo]:
        """
        Main response fingerprinting method.
        
        Args:
            headers: HTTP headers
            content: Response content
            status_code: Status code
            response_time: Response time
            
        Returns:
            List of detected WAFs with confidence assessment
        """
        
        # Create hash for caching
        cache_key = self._create_cache_key(headers, content, status_code)
        
        if cache_key in self.fingerprint_cache:
            return self.fingerprint_cache[cache_key]
        
        detected_wafs = []
        
        # Normalize headers
        normalized_headers = {k.lower(): v.lower() for k, v in headers.items()}
        normalized_content = content.lower()
        
        # Check each signature
        for signatures_list in self.signatures_db.signatures.values():
            for signature in signatures_list:
                confidence = self._calculate_signature_confidence(
                    signature, normalized_headers, normalized_content, status_code, response_time
                )
                
                if confidence > 0.3:  # Minimum threshold
                    waf_info = WAFInfo(
                        waf_type=signature.waf_type,
                        name=signature.name,
                        confidence=confidence,
                        detection_method="fingerprinting",
                        response_headers=headers,
                        detected_features=self._get_matched_features(
                            signature, normalized_headers, normalized_content
                        )
                    )
                    detected_wafs.append(waf_info)
        
        # Deduplicate and sort
        final_results = self._deduplicate_and_sort(detected_wafs)
        
        # Cache result
        self.fingerprint_cache[cache_key] = final_results
        
        return final_results
    
    def _calculate_signature_confidence(
        self,
        signature: WAFSignature,
        headers: Dict[str, str],
        content: str,
        status_code: int,
        response_time: Optional[float]
    ) -> float:
        """Calculate confidence for signature"""
        
        confidence = 0.0
        max_confidence = 0.0
        
        # Check required headers (high weight)
        required_weight = 0.4
        if signature.required_headers:
            required_matches = sum(
                1 for req_header in signature.required_headers
                if req_header.lower() in headers
            )
            required_score = required_matches / len(signature.required_headers)
            confidence += required_score * required_weight
            max_confidence += required_weight
        
        # Check header patterns
        header_weight = 0.3
        if signature.header_patterns:
            header_matches = 0
            for pattern in signature.header_patterns:
                for header_value in headers.values():
                    if re.search(pattern, header_value, re.IGNORECASE):
                        header_matches += 1
                        break
            
            header_score = min(1.0, header_matches / len(signature.header_patterns))
            confidence += header_score * header_weight
            max_confidence += header_weight
        
        # Check content patterns
        content_weight = 0.2
        if signature.content_patterns:
            content_matches = sum(
                1 for pattern in signature.content_patterns
                if re.search(pattern, content, re.IGNORECASE)
            )
            content_score = min(1.0, content_matches / len(signature.content_patterns))
            confidence += content_score * content_weight
            max_confidence += content_weight
        
        # Check status codes
        status_weight = 0.1
        if signature.status_codes:
            if status_code in signature.status_codes:
                confidence += status_weight
            max_confidence += status_weight
        
        # Normalize confidence
        if max_confidence > 0:
            normalized_confidence = confidence / max_confidence
        else:
            normalized_confidence = 0.0
        
        # Apply signature weight
        final_confidence = normalized_confidence * signature.confidence_weight
        
        return min(1.0, final_confidence)
    
    def _get_matched_features(
        self,
        signature: WAFSignature,
        headers: Dict[str, str],
        content: str
    ) -> List[str]:
        """Get list of matched features"""
        
        matched_features = []
        
        # Check headers
        for req_header in signature.required_headers:
            if req_header.lower() in headers:
                matched_features.append(f"required_header: {req_header}")
        
        # Check header patterns
        for pattern in signature.header_patterns:
            for header_name, header_value in headers.items():
                if re.search(pattern, header_value, re.IGNORECASE):
                    matched_features.append(f"header_pattern: {pattern}")
                    break
        
        # Check content patterns
        for pattern in signature.content_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                matched_features.append(f"content_pattern: {pattern}")
        
        return matched_features
    
    def _deduplicate_and_sort(self, detected_wafs: List[WAFInfo]) -> List[WAFInfo]:
        """Deduplicate and sort results"""
        
        # Group by WAF type
        waf_groups: Dict[str, List[Any]] = {}
        for waf in detected_wafs:
            if waf.waf_type not in waf_groups:
                waf_groups[waf.waf_type] = []  # type: ignore[index]
            waf_groups[waf.waf_type].append(waf)  # type: ignore[index]
        
        # Merge duplicates
        final_results = []
        for waf_type, waf_list in waf_groups.items():
            if len(waf_list) == 1:
                final_results.append(waf_list[0])
            else:
                # Take best result
                best_waf = max(waf_list, key=lambda x: x.confidence)
                
                # Merge detected_features
                all_features = []
                for waf in waf_list:
                    all_features.extend(waf.detected_features)
                best_waf.detected_features = list(set(all_features))
                
                final_results.append(best_waf)
        
        # Sort by confidence
        final_results.sort(key=lambda x: x.confidence, reverse=True)
        
        return final_results
    
    def _create_cache_key(
        self,
        headers: Dict[str, str],
        content: str,
        status_code: int
    ) -> str:
        """Create cache key"""
        
        # Create hash based on key parameters
        key_data = {
            'headers_hash': hashlib.md5(str(sorted(headers.items())).encode()).hexdigest()[:8],
            'content_hash': hashlib.md5(content[:1000].encode()).hexdigest()[:8],
            'status_code': status_code
        }
        
        return f"{key_data['headers_hash']}_{key_data['content_hash']}_{key_data['status_code']}"
    
    def learn_from_response(
        self,
        waf_type: WAFType,
        headers: Dict[str, str],
        content: str,
        status_code: int
    ):
        """
        Learn from new response.
        
        Args:
            waf_type: WAF type
            headers: Headers
            content: Content
            status_code: Status code
        """
        
        # Extract new patterns
        new_header_patterns = self._extract_header_patterns(headers)
        new_content_patterns = self._extract_content_patterns(content)
        
        # Create new signature
        learned_signature = WAFSignature(
            waf_type=waf_type,
            name=f"{waf_type.value.replace('_', ' ').title()} (Learned)",
            header_patterns=new_header_patterns,
            required_headers=[],
            content_patterns=new_content_patterns,
            error_page_patterns=[],
            status_codes=[status_code] if status_code != 200 else [],
            confidence_weight=0.6,  # Lower weight for learned signatures
            source="learned"
        )
        
        self.signatures_db.add_signature(learned_signature)
        
        logger.info(f"Learned new signature for {waf_type.value}")
    
    def _extract_header_patterns(self, headers: Dict[str, str]) -> List[str]:
        """Extract patterns from headers"""
        patterns = []
        
        for header_name, header_value in headers.items():
            header_name = header_name.lower()
            header_value = header_value.lower()
            
            # Look for WAF-specific headers
            if any(keyword in header_name for keyword in [
                'waf', 'firewall', 'security', 'protection', 'guard',
                'shield', 'block', 'filter', 'ray', 'incident'
            ]):
                patterns.append(f"{header_name}:")
            
            # Look for WAF-specific values
            waf_keywords = [
                'cloudflare', 'incapsula', 'sucuri', 'akamai', 'aws',
                'barracuda', 'fortinet', 'f5', 'bigip', 'modsecurity'
            ]
            for keyword in waf_keywords:
                if keyword in header_value:
                    patterns.append(f"{header_name}:.*{keyword}")
        
        return patterns
    
    def _extract_content_patterns(self, content: str) -> List[str]:
        """Extract patterns from content"""
        patterns = []
        content = content.lower()
        
        # Look for WAF-specific strings
        waf_keywords = [
            'cloudflare', 'incapsula', 'sucuri', 'akamai', 'aws waf',
            'barracuda', 'fortinet', 'f5 big-ip', 'modsecurity',
            'access denied', 'blocked', 'incident id', 'ray id',
            'security violation', 'firewall', 'unauthorized'
        ]
        
        for keyword in waf_keywords:
            if keyword in content:
                patterns.append(keyword)
        
        return patterns
    
    def export_signatures(self, export_path: str) -> bool:
        """
        Export signatures to file.
        
        Args:
            export_path: Export path
            
        Returns:
            True if successful
        """
        try:
            self.signatures_db.signatures_path = export_path
            self.signatures_db.save_signatures()
            return True
        except Exception as e:
            logger.error(f"Error exporting signatures: {e}")
            return False
    
    def get_fingerprinting_stats(self) -> Dict[str, Any]:
        """Fingerprinting statistics"""
        return {
            'total_signatures': len(self.signatures_db.get_all_signatures()),
            'signatures_by_waf': {
                waf_type.value: len(signatures)
                for waf_type, signatures in self.signatures_db.signatures.items()
            },
            'cache_size': len(self.fingerprint_cache),
            'supported_wafs': [waf_type.value for waf_type in self.signatures_db.signatures.keys()]
        }