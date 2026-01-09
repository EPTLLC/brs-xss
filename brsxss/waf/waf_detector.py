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
from typing import Optional, Any

from .waf_types import WAFType, WAFInfo
from .header_detector import HeaderDetector
from .content_detector import ContentDetector
from .behavior_detector import BehaviorDetector
from .detection_engine import WAFDetectionEngine
from .confidence_engine import ConfidenceEngine, ConfidenceLevel
from .adaptive_bypass import AdaptiveBypassSelector, BypassTechnique
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

        # Confidence scoring and adaptive bypass
        self.confidence_engine = ConfidenceEngine()
        self.bypass_selector = AdaptiveBypassSelector()

        # Detection state
        self.detected_wafs: list[WAFInfo] = []
        self.detection_history: list[dict[str, Any]] = []

        logger.info("WAF detector initialized with confidence scoring")

    async def detect_waf(self, url: str) -> list[WAFInfo]:
        """
        Main WAF detection method.

        Args:
            url: Target URL for detection

        Returns:
            list of detected WAFs
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

        # Phase 4: Confidence normalization
        if detected_wafs:
            detected_wafs = self._normalize_confidence(detected_wafs)

        # Remove duplicates and merge information
        final_wafs = self._merge_detections(detected_wafs)

        # Cache results
        self.detected_wafs = final_wafs
        self.detection_history.append(
            {
                "url": url,
                "timestamp": asyncio.get_event_loop().time(),
                "detected_wafs": len(final_wafs),
            }
        )

        logger.info(f"WAF detection complete: {len(final_wafs)} WAFs detected")
        return final_wafs

    async def close(self):
        """Close WAF detector and cleanup resources"""
        if self._owns_http_client and self.http_client:
            await self.http_client.close()

    async def _passive_detection(self, url: str) -> list[WAFInfo]:
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

    async def _content_detection(self, url: str) -> list[WAFInfo]:
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
            "?input=javascript:alert(1)",
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

    async def _behavioral_detection(self, url: str) -> list[WAFInfo]:
        """Behavioral analysis detection"""
        responses = []
        timing_data = []

        try:
            # Send multiple requests to analyze behavior
            for i in range(5):
                start_time = asyncio.get_event_loop().time()

                response = await self.http_client.get(
                    url, headers={"User-Agent": f"TestAgent-{i}"}
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

    def _normalize_confidence(self, detected_wafs: list[WAFInfo]) -> list[WAFInfo]:
        """Normalize confidence scores using confidence engine"""
        if not detected_wafs:
            return []

        normalized = []
        for waf in detected_wafs:
            # Build evidence from detected features
            evidence_items = []
            for feature in waf.detected_features:
                if feature.startswith("required_header:"):
                    evidence_items.append(
                        self.confidence_engine.create_evidence(
                            source="required_header",
                            pattern=feature,
                            weight=1.0,
                            description=f"Required header found: {feature}",
                        )
                    )
                elif feature.startswith("header_pattern:"):
                    evidence_items.append(
                        self.confidence_engine.create_evidence(
                            source="header_pattern",
                            pattern=feature,
                            weight=0.8,
                            description=f"Header pattern matched: {feature}",
                        )
                    )
                elif feature.startswith("content_pattern:"):
                    evidence_items.append(
                        self.confidence_engine.create_evidence(
                            source="content_pattern",
                            pattern=feature,
                            weight=0.7,
                            description=f"Content pattern matched: {feature}",
                        )
                    )
                else:
                    evidence_items.append(
                        self.confidence_engine.create_evidence(
                            source="status_code",
                            pattern=feature,
                            weight=0.5,
                            description=f"Other evidence: {feature}",
                        )
                    )

            # Recalculate confidence if we have evidence
            if evidence_items:
                new_conf, level = self.confidence_engine.calculate_confidence(
                    evidence_items
                )
                waf.confidence = max(waf.confidence, new_conf)  # Keep higher value

            normalized.append(waf)

        return normalized

    def _merge_detections(self, detected_wafs: list[WAFInfo]) -> list[WAFInfo]:
        """Merge duplicate detections and consolidate information"""
        if not detected_wafs:
            return []

        # Group by WAF type
        waf_groups: dict[str, list[WAFInfo]] = {}
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

    def _merge_waf_group(self, waf_list: list[WAFInfo]) -> WAFInfo:
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
            confidence=min(
                base_waf.confidence + 0.1, 1.0
            ),  # Boost for multiple detections
            detection_method="|".join(set(all_methods)),
            detected_features=list(set(all_features)),
            version=base_waf.version,
            blocking_level=base_waf.blocking_level,
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

    def get_detection_statistics(self) -> dict[str, Any]:
        """Get WAF detection statistics"""
        total_detections = len(self.detection_history)

        if total_detections == 0:
            return {"total_detections": 0}

        successful_detections = sum(
            1 for entry in self.detection_history if entry["detected_wafs"] > 0
        )

        return {
            "total_detections": total_detections,
            "successful_detections": successful_detections,
            "success_rate": successful_detections / total_detections,
            "currently_detected": len(self.detected_wafs),
            "last_detection": (
                self.detection_history[-1] if self.detection_history else None
            ),
        }

    def reset_detection_state(self):
        """Reset detection state and history"""
        self.detected_wafs.clear()
        self.detection_history.clear()
        logger.info("WAF detection state reset")

    def get_bypass_recommendations(
        self, waf_info: Optional[WAFInfo] = None
    ) -> list[BypassTechnique]:
        """
        Get recommended bypass techniques for detected WAF.

        Args:
            waf_info: Specific WAF info, or use last detected

        Returns:
            Ordered list of recommended bypass techniques
        """
        if waf_info is None:
            if not self.detected_wafs:
                # No WAF detected - return generic techniques
                return self.bypass_selector.get_ordered_techniques(
                    WAFInfo(waf_type=WAFType.UNKNOWN, name="Unknown"),
                    ConfidenceLevel.UNCERTAIN,
                )
            waf_info = self.detected_wafs[0]  # Use highest confidence WAF

        # Determine confidence level
        if waf_info.confidence >= 0.8:
            level = ConfidenceLevel.HIGH
        elif waf_info.confidence >= 0.5:
            level = ConfidenceLevel.MEDIUM
        elif waf_info.confidence >= 0.3:
            level = ConfidenceLevel.LOW
        else:
            level = ConfidenceLevel.UNCERTAIN

        return self.bypass_selector.get_ordered_techniques(waf_info, level)

    def record_bypass_result(
        self, waf_type: WAFType, technique: BypassTechnique, success: bool
    ):
        """Record bypass attempt result for learning"""
        if success:
            self.bypass_selector.record_success(waf_type, technique)
        else:
            self.bypass_selector.record_failure(waf_type, technique)

    async def detect_multiple_urls(self, urls: list[str]) -> dict[str, list[WAFInfo]]:
        """
        Detect WAFs for multiple URLs efficiently.

        Args:
            urls: list of URLs to test

        Returns:
            Dictionary mapping URLs to detected WAFs
        """
        results: dict[str, Any] = {}

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

    async def _behavioral_detection_fast(self, url: str) -> list[WAFInfo]:
        """Fast behavioral detection - only ONE test request"""
        try:
            # Single test with most common XSS payload
            test_payload = "?test=<script>alert(1)</script>"
            test_url = url + test_payload

            response = await self.http_client.get(test_url)

            # Quick behavioral analysis
            if response.status_code in [403, 406, 409, 418]:
                return [
                    WAFInfo(
                        waf_type=WAFType.UNKNOWN,
                        name="Generic WAF (Fast Detection)",
                        confidence=0.7,
                        detection_method="fast_behavioral",
                        response_headers=(
                            dict(response.headers)
                            if hasattr(response, "headers")
                            else {}
                        ),
                    )
                ]

        except Exception as e:
            logger.debug(f"Fast behavioral detection failed: {e}")

        return []

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
                "security" in response.text.lower(),
            ]

            if any(waf_indicators):
                return WAFInfo(
                    waf_type=WAFType.UNKNOWN,
                    name="WAF Detected (Suspicious Request)",
                    confidence=0.8,
                    detection_method="suspicious_request",
                    response_headers=(
                        dict(response.headers) if hasattr(response, "headers") else {}
                    ),
                )

        except Exception as e:
            logger.debug(f"Suspicious request test failed: {e}")

        return None
