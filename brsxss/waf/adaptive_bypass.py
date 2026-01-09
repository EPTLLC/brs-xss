#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 25 Dec 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Adaptive WAF Bypass Selection

Selects optimal bypass techniques based on:
- Detected WAF type
- Confidence level
- Previous bypass success/failure
"""

from typing import Dict, List
from dataclasses import dataclass, field
from enum import Enum

from .waf_types import WAFType, WAFInfo
from .confidence_engine import ConfidenceLevel
from ..utils.logger import Logger

logger = Logger("waf.adaptive_bypass")


class BypassTechnique(Enum):
    """Available bypass techniques"""

    # Encoding techniques
    URL_ENCODING = "url_encoding"
    DOUBLE_URL_ENCODING = "double_url_encoding"
    UNICODE_ENCODING = "unicode_encoding"
    HTML_ENTITY_ENCODING = "html_entity_encoding"
    HEX_ENCODING = "hex_encoding"
    BASE64_ENCODING = "base64_encoding"

    # Case manipulation
    MIXED_CASE = "mixed_case"
    ALTERNATING_CASE = "alternating_case"

    # Whitespace manipulation
    TAB_INJECTION = "tab_injection"
    NEWLINE_INJECTION = "newline_injection"
    NULL_BYTE_INJECTION = "null_byte_injection"
    COMMENT_INJECTION = "comment_injection"

    # Payload mutation
    TAG_SPLITTING = "tag_splitting"
    ATTRIBUTE_BREAKING = "attribute_breaking"
    PROTOCOL_VARIATION = "protocol_variation"

    # Advanced techniques
    POLYGLOT = "polyglot"
    DOM_BASED = "dom_based"
    MUTATION_XSS = "mutation_xss"
    TEMPLATE_INJECTION = "template_injection"


@dataclass
class BypassStrategy:
    """Bypass strategy for specific WAF"""

    waf_type: WAFType
    primary_techniques: List[BypassTechnique]
    fallback_techniques: List[BypassTechnique]
    avoid_techniques: List[BypassTechnique] = field(default_factory=list)
    notes: str = ""


class AdaptiveBypassSelector:
    """
    Selects optimal bypass techniques based on WAF detection.

    Uses a knowledge base of WAF-specific bypass strategies
    with fallback for unknown WAFs.
    """

    def __init__(self):
        self._init_strategies()
        self.success_history: Dict[str, Dict[BypassTechnique, int]] = {}
        logger.info("Adaptive bypass selector initialized")

    def _init_strategies(self):
        """Initialize WAF-specific bypass strategies"""
        self.strategies: Dict[WAFType, BypassStrategy] = {
            WAFType.CLOUDFLARE: BypassStrategy(
                waf_type=WAFType.CLOUDFLARE,
                primary_techniques=[
                    BypassTechnique.UNICODE_ENCODING,
                    BypassTechnique.MUTATION_XSS,
                    BypassTechnique.DOM_BASED,
                    BypassTechnique.POLYGLOT,
                ],
                fallback_techniques=[
                    BypassTechnique.DOUBLE_URL_ENCODING,
                    BypassTechnique.COMMENT_INJECTION,
                    BypassTechnique.TAG_SPLITTING,
                ],
                avoid_techniques=[
                    BypassTechnique.URL_ENCODING,  # Well detected
                ],
                notes="Cloudflare has strong pattern detection. Use mutation and DOM-based techniques.",
            ),
            WAFType.AWS_WAF: BypassStrategy(
                waf_type=WAFType.AWS_WAF,
                primary_techniques=[
                    BypassTechnique.UNICODE_ENCODING,
                    BypassTechnique.HEX_ENCODING,
                    BypassTechnique.POLYGLOT,
                ],
                fallback_techniques=[
                    BypassTechnique.MIXED_CASE,
                    BypassTechnique.COMMENT_INJECTION,
                    BypassTechnique.ATTRIBUTE_BREAKING,
                ],
                avoid_techniques=[],
                notes="AWS WAF rules are configurable. Test multiple techniques.",
            ),
            WAFType.AKAMAI: BypassStrategy(
                waf_type=WAFType.AKAMAI,
                primary_techniques=[
                    BypassTechnique.UNICODE_ENCODING,
                    BypassTechnique.MUTATION_XSS,
                    BypassTechnique.TEMPLATE_INJECTION,
                ],
                fallback_techniques=[
                    BypassTechnique.DOUBLE_URL_ENCODING,
                    BypassTechnique.NULL_BYTE_INJECTION,
                    BypassTechnique.DOM_BASED,
                ],
                avoid_techniques=[
                    BypassTechnique.URL_ENCODING,
                ],
                notes="Akamai Kona has strong pattern matching. Use encoding chains.",
            ),
            WAFType.INCAPSULA: BypassStrategy(
                waf_type=WAFType.INCAPSULA,
                primary_techniques=[
                    BypassTechnique.UNICODE_ENCODING,
                    BypassTechnique.HEX_ENCODING,
                    BypassTechnique.POLYGLOT,
                ],
                fallback_techniques=[
                    BypassTechnique.COMMENT_INJECTION,
                    BypassTechnique.TAG_SPLITTING,
                    BypassTechnique.MIXED_CASE,
                ],
                avoid_techniques=[],
                notes="Imperva/Incapsula. Try encoding variations.",
            ),
            WAFType.MODSECURITY: BypassStrategy(
                waf_type=WAFType.MODSECURITY,
                primary_techniques=[
                    BypassTechnique.COMMENT_INJECTION,
                    BypassTechnique.MIXED_CASE,
                    BypassTechnique.TAB_INJECTION,
                ],
                fallback_techniques=[
                    BypassTechnique.UNICODE_ENCODING,
                    BypassTechnique.NEWLINE_INJECTION,
                    BypassTechnique.ATTRIBUTE_BREAKING,
                ],
                avoid_techniques=[],
                notes="ModSecurity CRS. Whitespace and comment tricks often work.",
            ),
            WAFType.F5_BIG_IP: BypassStrategy(
                waf_type=WAFType.F5_BIG_IP,
                primary_techniques=[
                    BypassTechnique.UNICODE_ENCODING,
                    BypassTechnique.DOUBLE_URL_ENCODING,
                    BypassTechnique.POLYGLOT,
                ],
                fallback_techniques=[
                    BypassTechnique.HEX_ENCODING,
                    BypassTechnique.MUTATION_XSS,
                    BypassTechnique.DOM_BASED,
                ],
                avoid_techniques=[],
                notes="F5 ASM. Encoding chains and polyglots.",
            ),
            WAFType.BARRACUDA: BypassStrategy(
                waf_type=WAFType.BARRACUDA,
                primary_techniques=[
                    BypassTechnique.MIXED_CASE,
                    BypassTechnique.COMMENT_INJECTION,
                    BypassTechnique.TAB_INJECTION,
                ],
                fallback_techniques=[
                    BypassTechnique.UNICODE_ENCODING,
                    BypassTechnique.TAG_SPLITTING,
                    BypassTechnique.POLYGLOT,
                ],
                avoid_techniques=[],
                notes="Barracuda WAF. Case and whitespace manipulation.",
            ),
            WAFType.FORTINET: BypassStrategy(
                waf_type=WAFType.FORTINET,
                primary_techniques=[
                    BypassTechnique.UNICODE_ENCODING,
                    BypassTechnique.HEX_ENCODING,
                    BypassTechnique.COMMENT_INJECTION,
                ],
                fallback_techniques=[
                    BypassTechnique.MIXED_CASE,
                    BypassTechnique.DOUBLE_URL_ENCODING,
                    BypassTechnique.POLYGLOT,
                ],
                avoid_techniques=[],
                notes="FortiWeb. Encoding-based bypasses.",
            ),
            WAFType.SUCURI: BypassStrategy(
                waf_type=WAFType.SUCURI,
                primary_techniques=[
                    BypassTechnique.UNICODE_ENCODING,
                    BypassTechnique.MUTATION_XSS,
                    BypassTechnique.DOM_BASED,
                ],
                fallback_techniques=[
                    BypassTechnique.DOUBLE_URL_ENCODING,
                    BypassTechnique.POLYGLOT,
                    BypassTechnique.TEMPLATE_INJECTION,
                ],
                avoid_techniques=[],
                notes="Sucuri CloudProxy. DOM-based and mutation XSS.",
            ),
        }

        # Default strategy for unknown WAFs
        self.default_strategy = BypassStrategy(
            waf_type=WAFType.UNKNOWN,
            primary_techniques=[
                BypassTechnique.UNICODE_ENCODING,
                BypassTechnique.MIXED_CASE,
                BypassTechnique.COMMENT_INJECTION,
                BypassTechnique.POLYGLOT,
            ],
            fallback_techniques=[
                BypassTechnique.DOUBLE_URL_ENCODING,
                BypassTechnique.HEX_ENCODING,
                BypassTechnique.TAB_INJECTION,
                BypassTechnique.MUTATION_XSS,
                BypassTechnique.DOM_BASED,
            ],
            avoid_techniques=[],
            notes="Unknown WAF. Try broad range of techniques.",
        )

    def get_bypass_strategy(
        self, waf_info: WAFInfo, confidence_level: ConfidenceLevel
    ) -> BypassStrategy:
        """
        Get bypass strategy for detected WAF.

        Args:
            waf_info: Detected WAF info
            confidence_level: Detection confidence level

        Returns:
            Bypass strategy
        """
        waf_type = waf_info.waf_type

        # High confidence - use specific strategy
        if confidence_level == ConfidenceLevel.HIGH:
            strategy = self.strategies.get(waf_type, self.default_strategy)
            logger.debug(
                f"Using specific strategy for {waf_type.value} (high confidence)"
            )
            return strategy

        # Medium confidence - merge specific + default
        if confidence_level == ConfidenceLevel.MEDIUM:
            specific = self.strategies.get(waf_type)
            if specific:
                merged = BypassStrategy(
                    waf_type=waf_type,
                    primary_techniques=specific.primary_techniques[:2]
                    + self.default_strategy.primary_techniques[:2],
                    fallback_techniques=specific.fallback_techniques
                    + self.default_strategy.fallback_techniques,
                    avoid_techniques=specific.avoid_techniques,
                    notes=f"Merged strategy (medium confidence): {specific.notes}",
                )
                logger.debug(
                    f"Using merged strategy for {waf_type.value} (medium confidence)"
                )
                return merged
            return self.default_strategy

        # Low/Uncertain - use default broad strategy
        logger.debug("Using default strategy (low/uncertain confidence)")
        return self.default_strategy

    def get_ordered_techniques(
        self, waf_info: WAFInfo, confidence_level: ConfidenceLevel
    ) -> List[BypassTechnique]:
        """
        Get ordered list of bypass techniques to try.

        Args:
            waf_info: Detected WAF info
            confidence_level: Detection confidence level

        Returns:
            Ordered list of techniques (primary first, then fallback)
        """
        strategy = self.get_bypass_strategy(waf_info, confidence_level)

        # Build ordered list
        techniques = []

        # Add primary techniques
        for tech in strategy.primary_techniques:
            if tech not in strategy.avoid_techniques:
                techniques.append(tech)

        # Add fallback techniques
        for tech in strategy.fallback_techniques:
            if tech not in strategy.avoid_techniques and tech not in techniques:
                techniques.append(tech)

        # Adjust order based on success history
        waf_key = waf_info.waf_type.value
        if waf_key in self.success_history:
            history = self.success_history[waf_key]
            techniques.sort(key=lambda t: history.get(t, 0), reverse=True)

        return techniques

    def record_success(self, waf_type: WAFType, technique: BypassTechnique):
        """Record successful bypass for learning"""
        waf_key = waf_type.value
        if waf_key not in self.success_history:
            self.success_history[waf_key] = {}

        if technique not in self.success_history[waf_key]:
            self.success_history[waf_key][technique] = 0

        self.success_history[waf_key][technique] += 1
        logger.debug(f"Recorded success: {technique.value} for {waf_key}")

    def record_failure(self, waf_type: WAFType, technique: BypassTechnique):
        """Record failed bypass attempt"""
        waf_key = waf_type.value
        if waf_key not in self.success_history:
            self.success_history[waf_key] = {}

        if technique not in self.success_history[waf_key]:
            self.success_history[waf_key][technique] = 0

        # Decrease score (but don't go negative)
        self.success_history[waf_key][technique] = max(
            0, self.success_history[waf_key][technique] - 1
        )

    def get_technique_stats(self) -> Dict[str, Dict[str, int]]:
        """Get bypass technique statistics"""
        return {
            waf: {tech.value: count for tech, count in techniques.items()}
            for waf, techniques in self.success_history.items()
        }
