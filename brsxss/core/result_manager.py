#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Result Manager - Formats and aggregates scan results.
"""

import time
from typing import Any


class ResultManager:
    """Manages and formats vulnerability scan results"""

    @staticmethod
    def format_dom_vulnerability(dom_result) -> dict[str, Any]:
        """
        Format a DOM XSS result into the standard vulnerability dictionary.

        Args:
            dom_result: DOMXSSResult dataclass instance

        Returns:
            Formatted vulnerability dictionary
        """
        return {
            "url": dom_result.url,
            "vulnerable": dom_result.vulnerable,
            "vulnerability_type": "DOM XSS",
            "payload": dom_result.payload,
            "trigger_method": dom_result.trigger_method,
            "execution_context": dom_result.execution_context,
            "source": dom_result.source,
            "sink": dom_result.sink,
            "severity": "high" if dom_result.vulnerable else "info",
            "score": dom_result.score,
            "screenshot_path": dom_result.screenshot_path,
            "console_logs": dom_result.console_logs,
            "error_logs": dom_result.error_logs,
            "timestamp": time.time(),
        }

    @staticmethod
    def aggregate_dom_findings(
        base_url: str, vulnerable_results: list
    ) -> dict[str, Any]:
        """
        Aggregate multiple DOM XSS findings into single finding with evidence.

        Args:
            base_url: Base URL that was tested
            vulnerable_results: list of DOMXSSResult instances that are vulnerable

        Returns:
            Aggregated vulnerability dictionary
        """
        if not vulnerable_results:
            return {}

        # Get highest score result as primary
        primary = max(vulnerable_results, key=lambda r: r.score)

        # Collect all unique trigger methods and sources
        trigger_methods = list(set(r.trigger_method for r in vulnerable_results))
        sources = list(set(r.source for r in vulnerable_results))
        sinks = list(set(r.sink for r in vulnerable_results))

        # Collect evidence payloads
        evidence_payloads = [r.payload for r in vulnerable_results[:5]]

        context_chain = []
        if primary.source:
            context_chain.append(primary.source)
        if primary.sink:
            context_chain.append(primary.sink)
        context_str = " -> ".join(context_chain) if context_chain else "dom_flow"

        return {
            "url": base_url,
            "vulnerable": True,
            "vulnerability_type": "DOM XSS",
            "payload": primary.payload,
            "trigger_method": primary.trigger_method,
            "trigger_methods": trigger_methods,
            "execution_context": primary.execution_context,
            "source": primary.source,
            "sources": sources,
            "sink": primary.sink,
            "sinks": sinks,
            "context": context_str,
            "contexts": context_chain,
            "context_type": "dom_flow",
            "reflection_type": "dom_based",
            "severity": "high",
            "score": primary.score,
            "confidence": min(0.5 + (len(vulnerable_results) * 0.1), 0.99),
            "evidence_count": len(vulnerable_results),
            "evidence_payloads": evidence_payloads,
            "screenshot_path": primary.screenshot_path,
            "timestamp": time.time(),
        }

    @staticmethod
    def estimate_exploitation_likelihood(
        context_info: dict[str, Any], reflection_result: Any
    ) -> float:
        """
        Estimate the likelihood of successful exploitation.

        Args:
            context_info: Context analysis results
            reflection_result: Reflection detection results

        Returns:
            Likelihood score between 0.0 and 1.0
        """
        likelihood = 0.5  # Base likelihood

        # Context-based adjustments
        context_type = context_info.get("context_type", "unknown")
        specific_context = context_info.get("specific_context", context_type)

        # High-risk contexts
        high_risk_contexts = [
            "javascript",
            "javascript_expression",
            "javascript_statement",
            "html_attribute",
            "html_content",
        ]
        if specific_context in high_risk_contexts:
            likelihood += 0.2

        # Check for filters
        filters = context_info.get("filters_detected", [])
        if filters:
            likelihood -= 0.1 * min(len(filters), 3)

        # Check for encoding
        encoding = context_info.get("encoding_detected", "none")
        if encoding and encoding != "none":
            likelihood -= 0.15

        # Reflection quality adjustments
        if reflection_result:
            if hasattr(reflection_result, "reflection_points"):
                num_reflections = len(reflection_result.reflection_points)
                if num_reflections > 0:
                    likelihood += 0.1
                if num_reflections > 3:
                    likelihood += 0.1

            if hasattr(reflection_result, "exploitation_confidence"):
                likelihood = (
                    likelihood + reflection_result.exploitation_confidence
                ) / 2

        # Clamp to valid range
        return max(0.0, min(1.0, likelihood))

    @staticmethod
    def get_likelihood_level(likelihood: float) -> str:
        """
        Get human-readable likelihood level.

        Args:
            likelihood: Likelihood score between 0.0 and 1.0

        Returns:
            Likelihood level string
        """
        if likelihood >= 0.8:
            return "very_high"
        elif likelihood >= 0.6:
            return "high"
        elif likelihood >= 0.4:
            return "medium"
        elif likelihood >= 0.2:
            return "low"
        else:
            return "very_low"

    @staticmethod
    def get_likelihood_reason(
        context_info: dict[str, Any], reflection_result: Any
    ) -> str:
        """
        Get explanation for likelihood assessment.

        Args:
            context_info: Context analysis results
            reflection_result: Reflection detection results

        Returns:
            Human-readable explanation
        """
        reasons = []

        context_type = context_info.get(
            "specific_context", context_info.get("context_type", "unknown")
        )

        # Context-based reasons
        if context_type in ["javascript", "javascript_expression"]:
            reasons.append("Direct JavaScript context allows immediate code execution")
        elif context_type == "html_attribute":
            reasons.append("HTML attribute context with event handler potential")
        elif context_type == "html_content":
            reasons.append("HTML content context allows tag injection")

        # Filter-based reasons
        filters = context_info.get("filters_detected", [])
        if filters:
            reasons.append(f"Filters detected: {', '.join(filters[:3])}")

        # Encoding-based reasons
        encoding = context_info.get("encoding_detected", "none")
        if encoding and encoding != "none":
            reasons.append(f"Output encoding applied: {encoding}")

        # Reflection-based reasons
        if reflection_result and hasattr(reflection_result, "reflection_points"):
            num_reflections = len(reflection_result.reflection_points)
            if num_reflections > 0:
                reasons.append(f"Payload reflected {num_reflections} time(s)")

        return "; ".join(reasons) if reasons else "Standard exploitation conditions"
