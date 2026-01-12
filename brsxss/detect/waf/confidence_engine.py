#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 25 Dec 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

WAF Confidence Scoring Engine

Provides multi-factor confidence scoring for WAF detection with:
- Weighted evidence aggregation
- Confidence thresholds (high/medium/low)
- Fallback mechanism for uncertain detections
"""

from typing import Any
from dataclasses import dataclass, field
from enum import Enum

from .waf_types import WAFType
from brsxss.utils.logger import Logger

logger = Logger("waf.confidence_engine")


class ConfidenceLevel(Enum):
    """Confidence levels for WAF detection"""

    HIGH = "high"  # >= 0.8 - Strong evidence
    MEDIUM = "medium"  # 0.5-0.8 - Moderate evidence
    LOW = "low"  # 0.3-0.5 - Weak evidence
    UNCERTAIN = "uncertain"  # < 0.3 - Insufficient evidence


@dataclass
class EvidenceItem:
    """Single piece of evidence for WAF detection"""

    source: str  # header, content, behavior, status_code
    pattern: str  # Matched pattern
    weight: float  # Evidence weight (0-1)
    description: str  # Human-readable description


@dataclass
class ConfidenceResult:
    """Result of confidence calculation"""

    waf_type: WAFType
    confidence: float
    level: ConfidenceLevel
    evidence: list[EvidenceItem] = field(default_factory=list)
    fallback_candidates: list[WAFType] = field(default_factory=list)


class ConfidenceEngine:
    """
    Multi-factor confidence scoring for WAF detection.

    Aggregates evidence from multiple sources:
    - HTTP headers (highest weight)
    - Response content (medium weight)
    - Behavioral patterns (medium weight)
    - Status codes (low weight)
    """

    # Evidence source weights
    WEIGHTS = {
        "required_header": 0.35,  # Required header present
        "header_pattern": 0.25,  # Header pattern match
        "content_pattern": 0.20,  # Content pattern match
        "error_page": 0.15,  # Error page pattern
        "status_code": 0.05,  # Status code match
    }

    # Confidence thresholds
    THRESHOLDS = {
        "high": 0.80,
        "medium": 0.50,
        "low": 0.30,
    }

    def __init__(self):
        logger.info("Confidence engine initialized")

    def calculate_confidence(
        self, evidence_items: list[EvidenceItem]
    ) -> tuple[float, ConfidenceLevel]:
        """
        Calculate overall confidence from evidence items.

        Args:
            evidence_items: list of evidence items

        Returns:
            tuple of (confidence score, confidence level)
        """
        if not evidence_items:
            return 0.0, ConfidenceLevel.UNCERTAIN

        # Aggregate weighted evidence
        total_weight = 0.0
        weighted_sum = 0.0

        for item in evidence_items:
            source_weight = self.WEIGHTS.get(item.source, 0.1)
            weighted_sum += item.weight * source_weight
            total_weight += source_weight

        # Normalize confidence
        if total_weight > 0:
            confidence = min(1.0, weighted_sum / total_weight)
        else:
            confidence = 0.0

        # Boost for multiple evidence sources
        unique_sources = len(set(item.source for item in evidence_items))
        if unique_sources >= 3:
            confidence = min(1.0, confidence * 1.15)  # 15% boost
        elif unique_sources >= 2:
            confidence = min(1.0, confidence * 1.08)  # 8% boost

        # Determine confidence level
        level = self._get_confidence_level(confidence)

        return confidence, level

    def _get_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Determine confidence level from score"""
        if confidence >= self.THRESHOLDS["high"]:
            return ConfidenceLevel.HIGH
        elif confidence >= self.THRESHOLDS["medium"]:
            return ConfidenceLevel.MEDIUM
        elif confidence >= self.THRESHOLDS["low"]:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.UNCERTAIN

    def apply_fallback(
        self, primary_result: ConfidenceResult, all_candidates: list[ConfidenceResult]
    ) -> ConfidenceResult:
        """
        Apply fallback logic for uncertain detections.

        If primary result is uncertain, try to find a better candidate
        or return generic WAF detection.

        Args:
            primary_result: Primary detection result
            all_candidates: All candidate results

        Returns:
            Best result after fallback logic
        """
        # High confidence - no fallback needed
        if primary_result.level == ConfidenceLevel.HIGH:
            return primary_result

        # Medium confidence - check for better candidates
        if primary_result.level == ConfidenceLevel.MEDIUM:
            better_candidates = [
                c
                for c in all_candidates
                if c.confidence > primary_result.confidence
                and c.waf_type != primary_result.waf_type
            ]

            if better_candidates:
                best = max(better_candidates, key=lambda x: x.confidence)
                primary_result.fallback_candidates = [
                    c.waf_type for c in better_candidates[:3]
                ]

                # If significantly better, switch
                if best.confidence - primary_result.confidence > 0.2:
                    logger.debug(
                        f"Fallback: switching from {primary_result.waf_type} to {best.waf_type}"
                    )
                    return best

            return primary_result

        # Low/Uncertain confidence - apply generic fallback
        if primary_result.level in [ConfidenceLevel.LOW, ConfidenceLevel.UNCERTAIN]:
            # Check if any candidate has medium+ confidence
            medium_plus = [
                c
                for c in all_candidates
                if c.level in [ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM]
            ]

            if medium_plus:
                best = max(medium_plus, key=lambda x: x.confidence)
                logger.debug(
                    f"Fallback: using {best.waf_type} instead of uncertain result"
                )
                return best

            # No good candidates - return generic WAF if any evidence exists
            if primary_result.evidence:
                primary_result.waf_type = WAFType.UNKNOWN
                primary_result.fallback_candidates = list(
                    [
                        c.waf_type
                        for c in all_candidates
                        if c.waf_type != WAFType.UNKNOWN
                    ][:5]
                )
                return primary_result

        return primary_result

    def merge_evidence(
        self, results: list[ConfidenceResult]
    ) -> dict[WAFType, ConfidenceResult]:
        """
        Merge evidence from multiple detection passes.

        Args:
            results: list of confidence results

        Returns:
            Dictionary of WAF type to merged result
        """
        merged: dict[WAFType, ConfidenceResult] = {}

        for result in results:
            waf_type = result.waf_type

            if waf_type not in merged:
                merged[waf_type] = result
            else:
                # Merge evidence
                existing = merged[waf_type]
                existing.evidence.extend(result.evidence)

                # Recalculate confidence
                new_conf, new_level = self.calculate_confidence(existing.evidence)
                existing.confidence = new_conf
                existing.level = new_level

        return merged

    def create_evidence(
        self, source: str, pattern: str, weight: float, description: str
    ) -> EvidenceItem:
        """Factory method for creating evidence items"""
        return EvidenceItem(
            source=source, pattern=pattern, weight=weight, description=description
        )

    def get_confidence_summary(self, result: ConfidenceResult) -> dict[str, Any]:
        """Get human-readable confidence summary"""
        return {
            "waf_type": result.waf_type.value,
            "confidence": round(result.confidence, 3),
            "level": result.level.value,
            "evidence_count": len(result.evidence),
            "evidence_sources": list(set(e.source for e in result.evidence)),
            "fallback_candidates": [w.value for w in result.fallback_candidates],
            "is_reliable": result.level
            in [ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM],
        }
