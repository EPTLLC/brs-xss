#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Refactored - payload-aware confidence with DOM/event handler boosts
Telegram: https://t.me/EasyProTech

Confidence Calculator - calculates confidence scores with:
- DOM execution confirmation boosts
- Event handler determinism factors
- Payload analysis integration
- Context hierarchy awareness
"""

from typing import Any, Optional, TYPE_CHECKING
from dataclasses import dataclass
from enum import Enum

from brsxss.utils.logger import Logger
from .config_manager import ConfigManager

if TYPE_CHECKING:
    from .payload_analyzer import AnalyzedPayload

logger = Logger("core.confidence_calculator")


class ConfidenceLevel(Enum):
    """Human-readable confidence levels"""

    DEFINITE = "definite"  # 95-100%
    VERY_HIGH = "very_high"  # 85-95%
    HIGH = "high"  # 70-85%
    MEDIUM = "medium"  # 50-70%
    LOW = "low"  # 30-50%
    UNCERTAIN = "uncertain"  # <30%


@dataclass
class ConfidenceResult:
    """Detailed confidence calculation result"""

    score: float
    level: ConfidenceLevel
    percentage: int
    factors: dict[str, float]
    primary_reason: str
    is_dom_confirmed: bool = False
    is_deterministic: bool = False


class ConfidenceCalculator:
    """
    Calculates the confidence score of XSS vulnerabilities.

    Enhanced to properly weight:
    - DOM execution confirmation (very high boost)
    - Deterministic event handlers (onerror, onload)
    - External script loads (definitive)
    - Context hierarchy depth
    """

    # Event handlers that execute without user interaction
    AUTO_EXECUTE_HANDLERS: set[str] = {
        "onerror",
        "onload",
        "onreadystatechange",
        "onpageshow",
        "onbeforeunload",
        "onautocomplete",
        "oncanplay",
        "oncanplaythrough",
        "ondurationchange",
        "onemptied",
        "onended",
        "onloadeddata",
        "onloadedmetadata",
        "onloadstart",
        "onprogress",
        "onstalled",
        "onsuspend",
        "ontimeupdate",
        "onanimationstart",
        "onanimationend",
        "onanimationiteration",
        "ontransitionend",
    }

    # User-interaction event handlers
    USER_INTERACTION_HANDLERS: set[str] = {
        "onclick",
        "ondblclick",
        "onmousedown",
        "onmouseup",
        "onmouseover",
        "onmouseout",
        "onfocus",
        "onblur",
        "onkeydown",
        "onkeyup",
        "onchange",
        "onsubmit",
    }

    def __init__(self, config: Optional[ConfigManager] = None):
        """Initialize confidence calculator"""
        self.config = config or ConfigManager()

        # Default weights - can be overridden by config
        self.weights = self.config.get(
            "scoring.confidence_weights",
            {
                "reflection_quality": 0.25,
                "context_certainty": 0.20,
                "payload_analysis": 0.15,
                "detection_method": 0.15,
                "dom_confirmation": 0.15,
                "trigger_determinism": 0.10,
            },
        )

    def calculate(
        self,
        reflection_result: Any = None,
        context_info: Optional[dict[str, Any]] = None,
        payload: str = "",
        dom_confirmed: bool = False,
        dom_result: Any = None,
        classification_result: Any = None,
        context_analysis: Any = None,
    ) -> ConfidenceResult:
        """
        Calculate comprehensive confidence score.

        Args:
            reflection_result: Reflection analysis result
            context_info: Legacy context information dict
            payload: XSS payload string
            dom_confirmed: Whether headless browser confirmed execution
            dom_result: Full DOM detection result
            classification_result: XSSTypeClassifier result
            context_analysis: ContextParser result

        Returns:
            ConfidenceResult with score, level, and breakdown
        """

        context_info = context_info or {}
        factors = {}

        # 1. Reflection quality (0-1)
        factors["reflection"] = self._calculate_reflection_confidence(reflection_result)

        # 2. Context certainty (0-1)
        factors["context"] = self._calculate_context_confidence(
            context_info, context_analysis
        )

        # 3. Payload analysis (0-1)
        factors["payload"] = self._calculate_payload_confidence(
            payload, classification_result
        )

        # 4. Detection method confidence (0-1)
        factors["detection"] = self._calculate_detection_confidence(
            reflection_result, context_info, dom_result
        )

        # 5. DOM confirmation boost (0-1)
        factors["dom_confirmation"] = self._calculate_dom_confirmation_confidence(
            dom_confirmed, dom_result
        )

        # 6. Trigger determinism (0-1)
        factors["trigger_determinism"] = self._calculate_trigger_determinism(
            payload, classification_result
        )

        # Calculate weighted score
        weighted_score = sum(
            factors[k] * self.weights.get(k.replace("_confidence", ""), 0.1)
            for k in factors
        )

        # Apply DOM confirmation multiplier if confirmed
        if dom_confirmed:
            # DOM confirmation is definitive evidence
            weighted_score = max(weighted_score, 0.90)

        # External script load is definitive
        if self._is_external_script_load(payload):
            weighted_score = max(weighted_score, 0.95)

        # Auto-execute event handler with reflection is very high
        if self._has_auto_execute_handler(payload) and factors["reflection"] > 0.6:
            weighted_score = max(weighted_score, 0.85)

        # Cap at 1.0
        final_score = min(1.0, max(0.0, weighted_score))

        # Determine confidence level
        level = self._score_to_level(final_score)

        # Primary reason
        primary_reason = self._determine_primary_reason(factors, dom_confirmed, payload)

        result = ConfidenceResult(
            score=final_score,
            level=level,
            percentage=int(final_score * 100),
            factors=factors,
            primary_reason=primary_reason,
            is_dom_confirmed=dom_confirmed,
            is_deterministic=self._has_auto_execute_handler(payload),
        )

        logger.info(
            f"Confidence: {result.percentage}% ({level.value}) - {primary_reason}"
        )

        return result

    # Legacy interface compatibility
    def calculate_confidence(
        self, reflection_result: Any, context_info: dict[str, Any], payload: str
    ) -> float:
        """
        Legacy interface - returns just the score.

        Use calculate() for full result.
        """
        result = self.calculate(
            reflection_result=reflection_result,
            context_info=context_info,
            payload=payload,
        )
        return result.score

    def _calculate_reflection_confidence(self, reflection_result: Any) -> float:
        """Calculate confidence based on reflection quality"""
        if not reflection_result:
            return 0.1

        reflection_type = getattr(reflection_result, "reflection_type", None)
        if not reflection_type:
            # Try overall_reflection_type
            reflection_type = getattr(
                reflection_result, "overall_reflection_type", None
            )

        if not reflection_type:
            return 0.2

        reflection_value = (
            reflection_type.value
            if hasattr(reflection_type, "value")
            else str(reflection_type)
        ).lower()

        # Confidence mapping
        reflection_confidences = {
            "exact": 0.95,
            "reflected_raw": 0.95,
            "partial": 0.80,
            "encoded": 0.70,
            "html_encoded": 0.65,
            "url_encoded": 0.65,
            "filtered": 0.55,
            "obfuscated": 0.60,
            "modified": 0.70,
            "not_reflected": 0.10,
            "none": 0.10,
        }

        base = reflection_confidences.get(reflection_value, 0.5)

        # Completeness bonus
        completeness = getattr(reflection_result, "completeness", 0.5)
        char_preserved = getattr(reflection_result, "characters_preserved", 0.5)
        detail_bonus = (completeness + char_preserved) / 2 * 0.15

        return min(1.0, base + detail_bonus)

    def _calculate_context_confidence(
        self, context_info: dict[str, Any], context_analysis: Any = None
    ) -> float:
        """Calculate confidence based on context analysis"""
        base = 0.5

        # Use new ContextAnalysis if available
        if context_analysis:
            primary = getattr(context_analysis, "primary_context", None)
            if primary:
                # Deeper hierarchy = more certain about context
                depth = len(getattr(primary, "hierarchy", []))
                base += min(0.3, depth * 0.1)

                # Known attribute type
                attr_type = getattr(primary, "attribute_type", None)
                if attr_type:
                    base += 0.15

                # Can execute JS = higher confidence in exploitability
                if getattr(context_analysis, "can_execute_js", False):
                    base += 0.1

                return min(1.0, base)

        # Fall back to legacy context_info
        context_type = context_info.get("context_type", "unknown")
        specific_context = context_info.get("specific_context", "")

        if context_type != "unknown":
            base += 0.25

        if specific_context in [
            "javascript",
            "javascript_expression",
            "javascript_statement",
        ]:
            base += 0.15

        if context_info.get("tag_name"):
            base += 0.08

        if context_info.get("attribute_name"):
            base += 0.08

        # Filter/encoding detection
        if context_info.get("filters_detected"):
            base += 0.05
        if context_info.get("encoding_detected", "none") != "none":
            base += 0.05

        return min(1.0, base)

    def _calculate_payload_confidence(
        self, payload: str, classification_result: Any = None
    ) -> float:
        """Calculate confidence based on payload analysis"""
        base = 0.5
        payload_lower = payload.lower()

        # Use classification result if available
        if classification_result:
            # Get confidence modifier from classifier
            modifier = getattr(classification_result, "confidence_modifier", 0)
            base += modifier

            # Deterministic triggers
            details = getattr(classification_result, "details", {})
            if details.get("is_deterministic"):
                base += 0.2
            if details.get("dom_confirmed"):
                base += 0.15

            return min(1.0, base)

        # Pattern-based analysis
        high_confidence_patterns = [
            ("<script", 0.15),
            ("onerror=", 0.15),
            ("onload=", 0.15),
            ("src=", 0.10),
            ("javascript:", 0.12),
            ("eval(", 0.12),
        ]

        for pattern, boost in high_confidence_patterns:
            if pattern in payload_lower:
                base += boost

        # Length bonus (more complex payloads are more targeted)
        if len(payload) > 30:
            base += 0.05
        if len(payload) > 60:
            base += 0.05

        return min(1.0, base)

    def _calculate_detection_confidence(
        self,
        reflection_result: Any,
        context_info: dict[str, Any],
        dom_result: Any = None,
    ) -> float:
        """Calculate confidence based on detection methods used"""
        methods: float = 0.0

        if reflection_result:
            methods += 1.0
            if getattr(reflection_result, "reflection_type", None):
                methods += 0.5

        if context_info.get("context_type", "unknown") != "unknown":
            methods += 1.0

        if context_info.get("filters_detected"):
            methods += 0.5

        if dom_result:
            methods += 2.0  # DOM confirmation is strong
            if getattr(dom_result, "vulnerable", False):
                methods += 1.0

        # More methods = higher confidence
        return min(1.0, 0.4 + methods * 0.12)

    def _calculate_dom_confirmation_confidence(
        self, dom_confirmed: bool, dom_result: Any = None
    ) -> float:
        """Calculate confidence boost from DOM confirmation"""
        if not dom_confirmed:
            return 0.3  # No DOM confirmation, neutral

        # DOM confirmed = very high confidence
        base = 0.95

        if dom_result:
            # Check for additional DOM evidence
            console_logs = getattr(dom_result, "console_logs", [])
            if console_logs:
                base = min(1.0, base + 0.03)

            screenshot = getattr(dom_result, "screenshot_path", None)
            if screenshot:
                base = min(1.0, base + 0.02)

        return base

    def _calculate_trigger_determinism(
        self, payload: str, classification_result: Any = None
    ) -> float:
        """Calculate confidence based on trigger determinism"""

        if classification_result:
            details = getattr(classification_result, "details", {})
            if details.get("is_deterministic"):
                return 0.95
            if details.get("requires_interaction"):
                return 0.60

        # Pattern-based
        payload_lower = payload.lower()

        for handler in self.AUTO_EXECUTE_HANDLERS:
            if handler in payload_lower:
                return 0.90

        for handler in self.USER_INTERACTION_HANDLERS:
            if handler in payload_lower:
                return 0.65

        if "<script" in payload_lower:
            return 0.85

        return 0.5

    def _has_auto_execute_handler(self, payload: str) -> bool:
        """Check if payload has auto-executing event handler"""
        payload_lower = payload.lower()
        for handler in self.AUTO_EXECUTE_HANDLERS:
            if handler in payload_lower:
                return True
        return "<script" in payload_lower

    def _is_external_script_load(self, payload: str) -> bool:
        """Check if payload loads external script"""
        import re

        pattern = r"<\s*script[^>]+src\s*="
        return bool(re.search(pattern, payload, re.IGNORECASE))

    def _score_to_level(self, score: float) -> ConfidenceLevel:
        """Convert numeric score to confidence level"""
        if score >= 0.95:
            return ConfidenceLevel.DEFINITE
        elif score >= 0.85:
            return ConfidenceLevel.VERY_HIGH
        elif score >= 0.70:
            return ConfidenceLevel.HIGH
        elif score >= 0.50:
            return ConfidenceLevel.MEDIUM
        elif score >= 0.30:
            return ConfidenceLevel.LOW
        return ConfidenceLevel.UNCERTAIN

    def _determine_primary_reason(
        self, factors: dict[str, float], dom_confirmed: bool, payload: str
    ) -> str:
        """Determine the primary reason for confidence level"""

        if dom_confirmed:
            return "DOM execution confirmed"

        if self._is_external_script_load(payload):
            return "External script load detected"

        if self._has_auto_execute_handler(payload):
            return "Auto-executing event handler"

        # Find highest factor
        max_factor = max(factors.items(), key=lambda x: x[1])

        reason_map = {
            "reflection": "Payload reflected in response",
            "context": "Clear injection context identified",
            "payload": "Known XSS pattern detected",
            "detection": "Multiple detection methods confirmed",
            "dom_confirmation": "DOM execution evidence",
            "trigger_determinism": "Deterministic trigger mechanism",
        }

        return reason_map.get(max_factor[0], "Auto-detected")

    def calculate_with_analyzed_payload(
        self,
        analyzed_payload: "AnalyzedPayload",
        reflection_result: Any = None,
        context_info: Optional[dict[str, Any]] = None,
        dom_confirmed: bool = False,
    ) -> ConfidenceResult:
        """
        Calculate confidence using AnalyzedPayload for more accurate results.

        This method uses the runtime-computed payload analysis for:
        - Deterministic execution detection
        - Trigger mechanism classification
        - External resource detection

        Args:
            analyzed_payload: Result from PayloadAnalyzer.analyze()
            reflection_result: Reflection analysis result
            context_info: Legacy context information
            dom_confirmed: Whether DOM execution was confirmed

        Returns:
            ConfidenceResult with adjusted confidence
        """

        context_info = context_info or {}
        factors = {}

        # 1. Reflection quality
        factors["reflection"] = self._calculate_reflection_confidence(reflection_result)

        # 2. Context certainty
        factors["context"] = self._calculate_context_confidence(context_info)

        # 3. Payload analysis - use AnalyzedPayload data
        base_payload_conf = 0.5

        if analyzed_payload.is_deterministic:
            base_payload_conf += 0.25
        if analyzed_payload.auto_executes:
            base_payload_conf += 0.15
        if (
            analyzed_payload.trigger_attribute
            and analyzed_payload.trigger_attribute in self.AUTO_EXECUTE_HANDLERS
        ):
            base_payload_conf += 0.10
        if analyzed_payload.contains_external_resource:
            base_payload_conf += 0.15
        if analyzed_payload.requires_interaction:
            base_payload_conf -= 0.10

        factors["payload"] = min(1.0, base_payload_conf)

        # 4. Detection method
        factors["detection"] = self._calculate_detection_confidence(
            reflection_result, context_info, None
        )

        # 5. DOM confirmation
        factors["dom_confirmation"] = 0.95 if dom_confirmed else 0.3

        # 6. Trigger determinism - use AnalyzedPayload
        if analyzed_payload.is_deterministic:
            factors["trigger_determinism"] = 0.95
        elif analyzed_payload.requires_interaction:
            factors["trigger_determinism"] = 0.60
        else:
            factors["trigger_determinism"] = 0.70

        # Calculate weighted score
        weighted_score = sum(
            factors[k] * self.weights.get(k.replace("_confidence", ""), 0.1)
            for k in factors
        )

        # Apply analyzed payload confidence boost
        weighted_score += analyzed_payload.confidence_boost

        # Apply minimum floors based on payload characteristics
        if dom_confirmed:
            weighted_score = max(weighted_score, 0.92)

        if analyzed_payload.contains_external_resource:
            weighted_score = max(weighted_score, 0.95)

        if analyzed_payload.is_deterministic and factors["reflection"] > 0.6:
            weighted_score = max(weighted_score, 0.88)

        # Specific handler boosts
        trigger_attr = analyzed_payload.trigger_attribute
        if trigger_attr:
            if trigger_attr == "onerror":
                weighted_score = max(weighted_score, 0.90)
            elif trigger_attr == "onload":
                weighted_score = max(weighted_score, 0.88)

        # Script tag inline execution
        if analyzed_payload.injection_class.value == "script_inline":
            weighted_score = max(weighted_score, 0.90)

        # Cap at 1.0
        final_score = min(1.0, max(0.0, weighted_score))

        # Determine level
        level = self._score_to_level(final_score)

        # Primary reason
        if dom_confirmed:
            primary_reason = "DOM execution confirmed"
        elif analyzed_payload.contains_external_resource:
            primary_reason = (
                f"External script load: {analyzed_payload.external_url or 'detected'}"
            )
        elif analyzed_payload.is_deterministic:
            primary_reason = f"Deterministic trigger: {analyzed_payload.trigger_vector}"
        elif analyzed_payload.trigger_attribute:
            primary_reason = f"Event handler: {analyzed_payload.trigger_element}.{analyzed_payload.trigger_attribute}"
        else:
            primary_reason = "Payload analysis"

        return ConfidenceResult(
            score=final_score,
            level=level,
            percentage=int(final_score * 100),
            factors=factors,
            primary_reason=primary_reason,
            is_dom_confirmed=dom_confirmed,
            is_deterministic=analyzed_payload.is_deterministic,
        )
