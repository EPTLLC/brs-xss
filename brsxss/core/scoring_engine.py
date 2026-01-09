#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Refactored - sync severity with confidence, integrate classifiers
Telegram: https://t.me/EasyProTech

Scoring Engine - calculates vulnerability scores with:
- Proper severity/confidence alignment
- XSS type classification integration
- Context hierarchy awareness
- Minimum severity enforcement based on trigger type
"""

from typing import Dict, Any, Optional, List

from .scoring_types import ScoringResult, SeverityLevel, ScoringWeights
from .impact_calculator import ImpactCalculator
from .exploitability_calculator import ExploitabilityCalculator
from .context_calculator import ContextCalculator
from .confidence_calculator import ConfidenceCalculator
from ..utils.logger import Logger
from .config_manager import ConfigManager

logger = Logger("core.scoring_engine")


class ScoringEngine:
    """
    Calculates vulnerability score based on multiple factors.

    Enhanced in v4.0.0:
    - Severity synced with confidence (99% confidence cannot be MEDIUM)
    - External script loads always HIGH+
    - DOM confirmed always HIGH+
    - Auto-execute event handlers always HIGH+
    """

    def __init__(self, config: Optional[ConfigManager] = None):
        """Initialize scoring engine"""
        self.config = config or ConfigManager()

        # Component calculators
        self.impact_calculator = ImpactCalculator(self.config)
        self.exploitability_calculator = ExploitabilityCalculator(self.config)
        self.context_calculator = ContextCalculator(self.config)
        self.confidence_calculator = ConfidenceCalculator(self.config)

        # Define the weights for combining component scores
        default_weights = {
            "impact": 0.4,
            "exploitability": 0.4,
            "context": 0.2,
            "reflection": 0.0,
        }
        configured = self.config.get("scoring.weights", default_weights)
        if isinstance(configured, dict):
            merged = {**default_weights, **configured}
            self.weights = ScoringWeights(
                impact=float(merged.get("impact", 0.4)),
                exploitability=float(merged.get("exploitability", 0.4)),
                context=float(merged.get("context", 0.2)),
                reflection=float(merged.get("reflection", 0.0)),
            )
        elif isinstance(configured, ScoringWeights):
            self.weights = configured
        else:
            self.weights = ScoringWeights(**default_weights)

        # Statistics
        self.total_assessments = 0
        self.vulnerability_counts = {level: 0 for level in SeverityLevel}

        logger.info("Scoring engine initialized")

    def score_vulnerability(
        self,
        payload: str,
        reflection_result: Any,
        context_info: Dict[str, Any],
        response: Any = None,
        dom_confirmed: bool = False,
        dom_result: Any = None,
        classification_result: Any = None,
        context_analysis: Any = None,
    ) -> ScoringResult:
        """
        Calculates a score by combining assessments from specialized calculators.

        Args:
            payload: XSS payload
            reflection_result: Reflection analysis result
            context_info: Context information dictionary
            response: HTTP response object
            dom_confirmed: Whether headless browser confirmed execution
            dom_result: Full DOM detection result
            classification_result: XSSTypeClassifier result
            context_analysis: ContextParser result

        Returns:
            ScoringResult with score, severity, confidence, and recommendations
        """
        self.total_assessments += 1
        logger.debug(f"Scoring vulnerability for payload: {payload[:50]}...")

        # 1. Component Scores (all scaled 0.0 - 1.0)
        impact = self.impact_calculator.calculate_impact_score(context_info, payload)
        exploitability = self.exploitability_calculator.calculate_exploitability_score(
            reflection_result
        )
        context = self.context_calculator.calculate_context_score(context_info)

        # 2. Weighted Average
        w = self.weights
        score = (
            (impact * w.impact)
            + (exploitability * w.exploitability)
            + (context * w.context)
        )

        # 3. Apply classification-based score boosts
        if classification_result:
            # Get minimum severity from classifier
            min_severity_str = getattr(
                classification_result, "severity_minimum", "medium"
            )
            confidence_mod = getattr(classification_result, "confidence_modifier", 0)

            # Boost score if classification indicates high severity
            if min_severity_str == "critical":
                score = max(score, 0.95)
            elif min_severity_str == "high":
                score = max(score, 0.70)

            # Apply confidence modifier
            score = min(1.0, score + confidence_mod * 0.1)

        # 4. Apply DOM confirmation boost
        if dom_confirmed:
            score = max(score, 0.75)  # DOM confirmed = minimum HIGH

        # 5. Final Score (scaled to 0-10)
        final_score = min(score * 10.0, 10.0)

        # 6. Calculate Confidence (enhanced)
        confidence_result = self.confidence_calculator.calculate(
            reflection_result=reflection_result,
            context_info=context_info,
            payload=payload,
            dom_confirmed=dom_confirmed,
            dom_result=dom_result,
            classification_result=classification_result,
            context_analysis=context_analysis,
        )
        confidence = confidence_result.score

        # 7. Determine Severity (with confidence alignment)
        severity = self._determine_severity(
            score=final_score,
            confidence=confidence,
            context_info=context_info,
            dom_confirmed=dom_confirmed,
            classification_result=classification_result,
            payload=payload,
        )

        # Track statistics
        self.vulnerability_counts[severity] = (
            self.vulnerability_counts.get(severity, 0) + 1
        )

        logger.info(
            f"Vulnerability scored: {final_score:.2f} ({severity.value}) "
            f"confidence={confidence:.0%}"
        )

        return ScoringResult(
            score=round(final_score, 2),
            severity=severity,
            confidence=round(confidence, 3),
            exploitation_likelihood=round(exploitability, 3),
            impact_score=round(impact, 2),
            context_score=round(context, 2),
            recommendations=self._get_recommendations(severity),
        )

    def _determine_severity(
        self,
        score: float,
        confidence: float,
        context_info: Optional[Dict[str, Any]] = None,
        dom_confirmed: bool = False,
        classification_result: Any = None,
        payload: str = "",
    ) -> SeverityLevel:
        """
        Determine severity level from score, confidence, and context.

        Key rules:
        - High confidence (>85%) cannot be below MEDIUM
        - Very high confidence (>95%) with DOM confirmed = minimum HIGH
        - External script load = minimum HIGH
        - Auto-execute event handler = minimum HIGH
        - Stored XSS = minimum HIGH, typically CRITICAL
        """
        context_info = context_info or {}
        payload_lower = payload.lower()

        # Start with score-based severity
        base_severity = self._score_to_severity(score)

        # === Confidence-based minimum severity ===
        # Very high confidence with definitive execution cannot be MEDIUM or below
        if confidence >= 0.95 and dom_confirmed:
            if base_severity in [
                SeverityLevel.LOW,
                SeverityLevel.MEDIUM,
                SeverityLevel.INFO,
            ]:
                logger.info(
                    f"Severity upgrade: {base_severity.value} -> HIGH "
                    f"(95%+ confidence with DOM confirmed)"
                )
                base_severity = SeverityLevel.HIGH

        # High confidence (85%+) should not be LOW/INFO
        if confidence >= 0.85:
            if base_severity in [SeverityLevel.LOW, SeverityLevel.INFO]:
                logger.info(
                    f"Severity upgrade: {base_severity.value} -> MEDIUM "
                    f"(85%+ confidence)"
                )
                base_severity = SeverityLevel.MEDIUM

        # === Classification-based minimum severity ===
        if classification_result:
            min_severity_str = getattr(classification_result, "severity_minimum", None)
            details = getattr(classification_result, "details", {})

            if min_severity_str:
                min_severity = self._string_to_severity(min_severity_str)
                if self._severity_rank(base_severity) < self._severity_rank(
                    min_severity
                ):
                    logger.info(
                        f"Severity upgrade: {base_severity.value} -> {min_severity.value} "
                        f"(classifier minimum)"
                    )
                    base_severity = min_severity

            # External script load = minimum HIGH
            if details.get("has_external_script"):
                if self._severity_rank(base_severity) < self._severity_rank(
                    SeverityLevel.HIGH
                ):
                    logger.info(
                        f"Severity upgrade: {base_severity.value} -> HIGH "
                        f"(external script load)"
                    )
                    base_severity = SeverityLevel.HIGH

            # Auto-execute (onerror, onload, etc.) = minimum HIGH
            if details.get("is_deterministic") and not details.get(
                "requires_interaction"
            ):
                if self._severity_rank(base_severity) < self._severity_rank(
                    SeverityLevel.HIGH
                ):
                    logger.info(
                        f"Severity upgrade: {base_severity.value} -> HIGH "
                        f"(deterministic auto-execute)"
                    )
                    base_severity = SeverityLevel.HIGH

        # === Payload-based checks (fallback if no classification) ===
        if not classification_result:
            # External script pattern
            import re

            if re.search(r"<\s*script[^>]+src\s*=", payload, re.IGNORECASE):
                if self._severity_rank(base_severity) < self._severity_rank(
                    SeverityLevel.HIGH
                ):
                    logger.info(
                        f"Severity upgrade: {base_severity.value} -> HIGH "
                        f"(external script pattern)"
                    )
                    base_severity = SeverityLevel.HIGH

            # Auto-execute event handlers
            auto_handlers = ["onerror", "onload", "onpageshow", "onbeforeunload"]
            for handler in auto_handlers:
                if handler in payload_lower:
                    if self._severity_rank(base_severity) < self._severity_rank(
                        SeverityLevel.HIGH
                    ):
                        logger.info(
                            f"Severity upgrade: {base_severity.value} -> HIGH "
                            f"(auto-execute handler: {handler})"
                        )
                        base_severity = SeverityLevel.HIGH
                    break

        # === Context-based overrides ===
        context_type = context_info.get(
            "specific_context", context_info.get("context_type", "")
        ).lower()

        # JavaScript contexts with auto-execution
        js_contexts = [
            "javascript",
            "javascript_expression",
            "javascript_statement",
            "js_string",
            "script",
            "script_content",
        ]
        if context_type in js_contexts:
            auto_exec = context_info.get("auto_execution", True)
            reflection_type = context_info.get("reflection_type", "reflected").lower()
            is_stored = reflection_type in ["stored", "persistent", "dom_stored"]

            if auto_exec:
                if is_stored:
                    if base_severity != SeverityLevel.CRITICAL:
                        logger.info(
                            f"Severity upgrade: {base_severity.value} -> CRITICAL "
                            f"(stored JS auto-exec)"
                        )
                        return SeverityLevel.CRITICAL
                else:
                    if self._severity_rank(base_severity) < self._severity_rank(
                        SeverityLevel.HIGH
                    ):
                        logger.info(
                            f"Severity upgrade: {base_severity.value} -> HIGH "
                            f"(reflected JS auto-exec)"
                        )
                        base_severity = SeverityLevel.HIGH

        # Event handler attributes = minimum HIGH
        if context_type == "html_attribute":
            attr_name = context_info.get("attribute_name", "").lower()
            event_handlers = [
                "onclick",
                "onerror",
                "onload",
                "onmouseover",
                "onfocus",
                "onblur",
                "oninput",
                "onchange",
                "onsubmit",
                "onanimationend",
                "ontoggle",
                "onpointerover",
                "onanimationstart",
            ]
            if any(attr_name.startswith(eh) for eh in event_handlers):
                if self._severity_rank(base_severity) < self._severity_rank(
                    SeverityLevel.HIGH
                ):
                    logger.info(
                        f"Severity upgrade: {base_severity.value} -> HIGH "
                        f"(event handler attribute)"
                    )
                    base_severity = SeverityLevel.HIGH

        # HTML content with event handler injection = minimum HIGH
        if context_type in ["html_content", "html_body", "html", "tag_content"]:
            html_event_patterns = [
                "onerror=",
                "onload=",
                "onclick=",
                "onmouseover=",
                "onfocus=",
                "<script",
                "<img",
                "<svg",
                "<body",
                "<iframe",
            ]
            has_html_execution = any(p in payload_lower for p in html_event_patterns)

            if has_html_execution:
                if self._severity_rank(base_severity) < self._severity_rank(
                    SeverityLevel.HIGH
                ):
                    logger.info(
                        f"Severity upgrade: {base_severity.value} -> HIGH "
                        f"(HTML event handler injection)"
                    )
                    base_severity = SeverityLevel.HIGH

        # HTML comment = maximum LOW (cap severity)
        if context_type in ["html_comment", "comment"]:
            if self._severity_rank(base_severity) > self._severity_rank(
                SeverityLevel.LOW
            ):
                logger.info(
                    f"Severity cap: {base_severity.value} -> LOW (HTML comment)"
                )
                return SeverityLevel.LOW

        return base_severity

    def _score_to_severity(self, score: float) -> SeverityLevel:
        """Convert numeric score to base severity"""
        if score >= 9.5:
            return SeverityLevel.CRITICAL
        elif score >= 7.0:
            return SeverityLevel.HIGH
        elif score >= 4.0:
            return SeverityLevel.MEDIUM
        elif score >= 1.0:
            return SeverityLevel.LOW
        elif score > 0.0:
            return SeverityLevel.INFO
        return SeverityLevel.NONE

    def _string_to_severity(self, s: str) -> SeverityLevel:
        """Convert string to SeverityLevel"""
        mapping = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
            "none": SeverityLevel.NONE,
        }
        return mapping.get(s.lower(), SeverityLevel.MEDIUM)

    def _severity_rank(self, severity: SeverityLevel) -> int:
        """Get numeric rank for severity comparison"""
        ranking = {
            SeverityLevel.NONE: 0,
            SeverityLevel.INFO: 1,
            SeverityLevel.LOW: 2,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.HIGH: 4,
            SeverityLevel.CRITICAL: 5,
        }
        return ranking.get(severity, 0)

    def _get_recommendations(self, severity: SeverityLevel) -> List[str]:
        """Get remediation advice based on severity."""
        if severity == SeverityLevel.CRITICAL:
            return [
                "Review and fix vulnerable code immediately",
                "Implement immediate input validation and sanitization",
                "Deploy Content Security Policy (CSP) with strict directives",
            ]
        elif severity == SeverityLevel.HIGH:
            return [
                "Prioritize fixing this vulnerability within the next sprint",
                "Apply context-specific output encoding (e.g., HTML, URL, JavaScript)",
                "Use a trusted, well-maintained library for sanitization",
            ]
        elif severity == SeverityLevel.MEDIUM:
            return [
                "Schedule a code review to identify similar issues",
                "Validate and sanitize all user input",
                "Implement proper HTML entity encoding",
            ]
        else:  # LOW / INFO / NONE
            return [
                "Keep web application frameworks updated",
                "Perform regular security testing and code reviews",
                "Train developers on secure coding practices",
            ]

    def get_statistics(self) -> Dict[str, Any]:
        """Get scoring engine statistics."""
        return {
            "total_assessments": self.total_assessments,
            "vulnerability_counts": {
                level.value: count for level, count in self.vulnerability_counts.items()
            },
            "weights": {
                "impact": self.weights.impact,
                "exploitability": self.weights.exploitability,
                "context": self.weights.context,
                "reflection": self.weights.reflection,
            },
        }

    def reset_statistics(self):
        """Reset scoring statistics"""
        self.total_assessments = 0
        self.vulnerability_counts = {level: 0 for level in SeverityLevel}
        logger.info("Scoring statistics reset")

    def update_weights(self, weights: ScoringWeights):
        """Update scoring weights."""
        self.weights = weights
        logger.info(f"Scoring weights updated: {weights}")

    def bulk_score_vulnerabilities(self, vulnerability_data: list) -> list:
        """Score multiple vulnerabilities efficiently."""
        results = []

        logger.info(f"Bulk scoring {len(vulnerability_data)} vulnerabilities")

        for i, vuln_data in enumerate(vulnerability_data):
            try:
                result = self.score_vulnerability(
                    payload=vuln_data["payload"],
                    reflection_result=vuln_data["reflection_result"],
                    context_info=vuln_data["context_info"],
                    response=vuln_data.get("response"),
                    dom_confirmed=vuln_data.get("dom_confirmed", False),
                    dom_result=vuln_data.get("dom_result"),
                    classification_result=vuln_data.get("classification_result"),
                    context_analysis=vuln_data.get("context_analysis"),
                )
                results.append(result)

                if (i + 1) % 10 == 0:
                    logger.debug(
                        f"Processed {i + 1}/{len(vulnerability_data)} vulnerabilities"
                    )

            except Exception as e:
                logger.error(f"Error scoring vulnerability {i}: {e}")
                continue

        logger.info(f"Bulk scoring completed: {len(results)} results")
        return results
