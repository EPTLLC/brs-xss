#!/usr/bin/env python3

"""
BRS-XSS WAF Detector

Main orchestrator for WAF detection system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

import asyncio
from typing import List, Optional, Dict, Any

from .waf_types import WAFType, WAFInfo
from .header_detector import HeaderDetector
from .content_detector import ContentDetector  
from .behavior_detector import BehaviorDetector
from .detection_engine import WAFDetectionEngine
from ..core.http_client import HTTPClient
from ..utils.logger import Logger

logger = Logger("waf.waf_detector")


class WAFDetector:
    """
    Main WAF detector orchestrator.
    
    Coordinates multiple specialized detectors for comprehensive
    WAF detection and analysis.
    """
    
    def __init__(self, http_client: Optional[HTTPClient] = None):
        """
        Initialize WAF detector.
        
        Args:
            http_client: HTTP client for requests
        """
        self.http_client = http_client or HTTPClient()
        self._owns_http_client = http_client is None  # Track if we created the client
        
        # Initialize specialized detectors
        self.header_detector = HeaderDetector()
        self.content_detector = ContentDetector()
        self.behavior_detector = BehaviorDetector()
        self.detection_engine = WAFDetectionEngine()
        
        # Detection state
        self.detected_wafs: List[WAFInfo] = []
        self.detection_history: List[Dict[str, Any]] = []
        
        logger.info("WAF detector initialized")
    
    async def detect_waf(self, url: str) -> List[WAFInfo]:
        """
        Main WAF detection method.
        
        Args:
            url: Target URL for detection
            
        Returns:
            List of detected WAFs
        """
        logger.info(f"Starting WAF detection for {url}")
        
        detected_wafs = []
        
        # Phase 1: Passive detection (headers only)
        passive_wafs = await self._passive_detection(url)
        detected_wafs.extend(passive_wafs)
        
        # Phase 2: Content-based detection
        content_wafs = await self._content_detection(url)
        detected_wafs.extend(content_wafs)
        
        # Phase 3: Active detection (behavioral analysis) - OPTIMIZED
        if not detected_wafs and len(passive_wafs) == 0:  # Only if nothing found yet
            behavioral_wafs = await self._behavioral_detection_fast(url)
            detected_wafs.extend(behavioral_wafs)
        
        # Phase 4: ML-based classification - OPTIMIZED
        if detected_wafs:
            ml_enhanced = await self._enhance_with_ml_fast(detected_wafs, url)
            detected_wafs = ml_enhanced
        
        # Remove duplicates and merge information
        final_wafs = self._merge_detections(detected_wafs)
        
        # Cache results
        self.detected_wafs = final_wafs
        self.detection_history.append({
            'url': url,
            'timestamp': asyncio.get_event_loop().time(),
            'detected_wafs': len(final_wafs)
        })
        
        logger.info(f"WAF detection complete: {len(final_wafs)} WAFs detected")
        return final_wafs
    
    async def close(self):
        """Close WAF detector and cleanup resources"""
        if self._owns_http_client and self.http_client:
            await self.http_client.close()
    
    async def _passive_detection(self, url: str) -> List[WAFInfo]:
        """Passive detection using only headers"""
        try:
            response = await self.http_client.get(url)
            
            # Header-based detection
            header_waf = self.header_detector.detect_from_headers(response.headers)
            
            if header_waf:
                logger.debug(f"Passive detection found: {header_waf.name}")
                return [header_waf]
            
        except Exception as e:
            logger.warning(f"Passive detection failed: {e}")
        
        return []
    
    async def _content_detection(self, url: str) -> List[WAFInfo]:
        """Content-based detection"""
        detected_wafs = []
        
        try:
            # Test with normal request
            response = await self.http_client.get(url)
            
            content_waf = self.content_detector.detect_from_content(
                response.text, "content_analysis"
            )
            
            if content_waf:
                detected_wafs.append(content_waf)
            
            # Test with ONE suspicious request only (fast mode)
            suspicious_waf = await self._test_one_suspicious_request(url)
            if suspicious_waf:
                detected_wafs.append(suspicious_waf)
                
        except Exception as e:
            logger.warning(f"Content detection failed: {e}")
        
        return detected_wafs
    
    async def _test_suspicious_request(self, url: str) -> Optional[WAFInfo]:
        """Test with suspicious parameters to trigger WAF"""
        test_payloads = [
            "?test=<script>alert(1)</script>",
            "?id=1' OR '1'='1",
            "?search=../../../etc/passwd",
            "?input=javascript:alert(1)"
        ]
        
        for payload in test_payloads:
            try:
                test_url = url + payload
                response = await self.http_client.get(test_url)
                
                # Check if response indicates blocking
                if response.status_code in [403, 406, 409, 501, 503]:
                    waf_info = self.content_detector.detect_from_content(
                        response.text, "active_probing"
                    )
                    
                    if waf_info:
                        waf_info.detected_features.append(f"blocked_payload:{payload}")
                        return waf_info
                
            except Exception as e:
                logger.debug(f"Test payload failed: {e}")
                continue
        
        return None
    
    async def _behavioral_detection(self, url: str) -> List[WAFInfo]:
        """Behavioral analysis detection"""
        responses = []
        timing_data = []
        
        try:
            # Send multiple requests to analyze behavior
            for i in range(5):
                start_time = asyncio.get_event_loop().time()
                
                response = await self.http_client.get(
                    url,
                    headers={'User-Agent': f'TestAgent-{i}'}
                )
                
                end_time = asyncio.get_event_loop().time()
                
                responses.append(response)
                timing_data.append(end_time - start_time)
                
                # Small delay between requests
                await asyncio.sleep(0.5)
            
            # Analyze behavioral patterns
            behavioral_waf = self.behavior_detector.analyze_response_behavior(
                responses, timing_data
            )
            
            if behavioral_waf:
                return [behavioral_waf]
                
        except Exception as e:
            logger.warning(f"Behavioral detection failed: {e}")
        
        return []
    
    async def _enhance_with_ml(self, detected_wafs: List[WAFInfo], url: str) -> List[WAFInfo]:
        """Enhance detection results with ML classification"""
        try:
            enhanced_wafs = []
            
            for waf_info in detected_wafs:
                # ML enhancement - disabled until classify_waf method is implemented
                # TODO: Implement classify_waf method in detection_engine
                # ml_result = await self.detection_engine.classify_waf(
                #     url, waf_info.detected_features
                # )
                ml_result = None
                
                if ml_result:
                    # Update confidence based on ML results
                    waf_info.confidence = min(
                        waf_info.confidence + ml_result.get('confidence_boost', 0.0),
                        1.0
                    )
                    
                    # Add ML features
                    waf_info.detected_features.extend(
                        ml_result.get('ml_features', [])
                    )
                
                enhanced_wafs.append(waf_info)
            
            return enhanced_wafs
            
        except Exception as e:
            logger.warning(f"ML enhancement failed: {e}")
            return detected_wafs
    
    def _merge_detections(self, detected_wafs: List[WAFInfo]) -> List[WAFInfo]:
        """Merge duplicate detections and consolidate information"""
        if not detected_wafs:
            return []
        
        # Group by WAF type
        waf_groups: Dict[str, List[WAFInfo]] = {}
        for waf in detected_wafs:
            waf_type = waf.waf_type
            if waf_type not in waf_groups:
                waf_groups[waf_type] = []  # type: ignore[index]
            waf_groups[waf_type].append(waf)  # type: ignore[index]
        
        # Merge each group
        merged_wafs = []
        for waf_type, waf_list in waf_groups.items():  # type: ignore[assignment]
            if len(waf_list) == 1:
                merged_wafs.append(waf_list[0])
            else:
                merged_waf = self._merge_waf_group(waf_list)
                merged_wafs.append(merged_waf)
        
        # Sort by confidence
        merged_wafs.sort(key=lambda w: w.confidence, reverse=True)
        
        return merged_wafs
    
    def _merge_waf_group(self, waf_list: List[WAFInfo]) -> WAFInfo:
        """Merge multiple detections of the same WAF type"""
        # Use the detection with highest confidence as base
        base_waf = max(waf_list, key=lambda w: w.confidence)
        
        # Merge features from all detections
        all_features = []
        all_methods = []
        
        for waf in waf_list:
            all_features.extend(waf.detected_features)
            all_methods.append(waf.detection_method)
        
        # Create merged WAF info
        merged_waf = WAFInfo(
            waf_type=base_waf.waf_type,
            name=base_waf.name,
            confidence=min(base_waf.confidence + 0.1, 1.0),  # Boost for multiple detections
            detection_method="|".join(set(all_methods)),
            detected_features=list(set(all_features)),
            version=base_waf.version,
            blocking_level=base_waf.blocking_level
            # additional_info removed - not supported by WAFInfo
        )
        
        return merged_waf
    
    async def quick_detect(self, url: str) -> Optional[WAFInfo]:
        """
        Quick WAF detection using only passive methods.
        
        Args:
            url: Target URL
            
        Returns:
            First detected WAF or None
        """
        try:
            response = await self.http_client.get(url)
            
            # Try header detection first
            header_waf = self.header_detector.detect_from_headers(response.headers)
            if header_waf:
                return header_waf
            
            # Try content detection
            content_waf = self.content_detector.detect_from_content(response.text)
            if content_waf:
                return content_waf
            
        except Exception as e:
            logger.warning(f"Quick detection failed: {e}")
        
        return None
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get WAF detection statistics"""
        total_detections = len(self.detection_history)
        
        if total_detections == 0:
            return {'total_detections': 0}
        
        successful_detections = sum(
            1 for entry in self.detection_history 
            if entry['detected_wafs'] > 0
        )
        
        return {
            'total_detections': total_detections,
            'successful_detections': successful_detections,
            'success_rate': successful_detections / total_detections,
            'currently_detected': len(self.detected_wafs),
            'last_detection': self.detection_history[-1] if self.detection_history else None
        }
    
    def reset_detection_state(self):
        """Reset detection state and history"""
        self.detected_wafs.clear()
        self.detection_history.clear()
        logger.info("WAF detection state reset")
    
    async def detect_multiple_urls(self, urls: List[str]) -> Dict[str, List[WAFInfo]]:
        """
        Detect WAFs for multiple URLs efficiently.
        
        Args:
            urls: List of URLs to test
            
        Returns:
            Dictionary mapping URLs to detected WAFs
        """
        results: Dict[str, Any] = {}
        
        logger.info(f"Starting batch WAF detection for {len(urls)} URLs")
        
        # Process URLs concurrently
        tasks = [self.detect_waf(url) for url in urls]
        
        try:
            detection_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(detection_results):
                url = urls[i]
                if isinstance(result, Exception):
                    logger.error(f"Detection failed for {url}: {result}")
                    results[url] = []
                else:
                    results[url] = result
                    
        except Exception as e:
            logger.error(f"Batch detection failed: {e}")
            # Fallback to individual detection
            for url in urls:
                try:
                    results[url] = await self.detect_waf(url)
                except Exception as url_error:
                    logger.error(f"Individual detection failed for {url}: {url_error}")
                    results[url] = []
        
        logger.info(f"Batch detection completed: {len(results)} results")
        return results
    
    async def _behavioral_detection_fast(self, url: str) -> List[WAFInfo]:
        """Fast behavioral detection - only ONE test request"""
        try:
            # Single test with most common XSS payload
            test_payload = "?test=<script>alert(1)</script>"
            test_url = url + test_payload
            
            response = await self.http_client.get(test_url)
            
            # Quick behavioral analysis
            if response.status_code in [403, 406, 409, 418]:
                return [WAFInfo(
                    waf_type=WAFType.UNKNOWN,
                    name="Generic WAF (Fast Detection)",
                    confidence=0.7,
                    detection_method="fast_behavioral",
                    response_headers=dict(response.headers) if hasattr(response, 'headers') else {}
                )]
                
        except Exception as e:
            logger.debug(f"Fast behavioral detection failed: {e}")
        
        return []
    
    async def _enhance_with_ml_fast(self, detected_wafs: List[WAFInfo], url: str) -> List[WAFInfo]:
        """Fast ML enhancement - skip heavy processing"""
        # Simply return original results for speed
        return detected_wafs
    
    async def _test_one_suspicious_request(self, url: str) -> Optional[WAFInfo]:
        """Test with ONE suspicious payload only"""
        try:
            # Most effective XSS payload for WAF detection
            test_payload = "?test=<script>alert(1)</script>"
            test_url = url + test_payload
            
            response = await self.http_client.get(test_url)
            
            # Quick WAF indicators
            waf_indicators = [
                response.status_code in [403, 406, 409, 418],
                "blocked" in response.text.lower(),
                "firewall" in response.text.lower(),
                "security" in response.text.lower()
            ]
            
            if any(waf_indicators):
                return WAFInfo(
                    waf_type=WAFType.UNKNOWN,
                    name="WAF Detected (Suspicious Request)",
                    confidence=0.8,
                    detection_method="suspicious_request",
                    response_headers=dict(response.headers) if hasattr(response, 'headers') else {}
                )
                
        except Exception as e:
            logger.debug(f"Suspicious request test failed: {e}")
        
        return None