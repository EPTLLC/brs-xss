#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Created - Classification Rules Matrix
Telegram: https://t.me/EasyProTech

Classification Rules Matrix - defines valid combinations of:
- Scan mode (quick/standard/deep)
- Source type (parameter/fragment/dom_api/storage)
- XSS type (Reflected/DOM-based/Stored)
- Confidence ceiling (mode-based caps)

This is the "truth table" for enterprise-grade reporting.
"""

from enum import Enum
from typing import Any, Optional
from dataclasses import dataclass


class ScanMode(Enum):
    """Scan modes with different depth/confidence characteristics"""

    QUICK = "quick"  # Fast heuristic scan
    STANDARD = "standard"  # Balanced scan
    DEEP = "deep"  # Full analysis
    STEALTH = "stealth"  # Low-profile scan


class SourceType(Enum):
    """Where user input originates"""

    URL_PARAMETER = "url_parameter"  # ?param=value
    URL_FRAGMENT = "url_fragment"  # #fragment
    URL_PATH = "url_path"  # /path/value
    FORM_INPUT = "form_input"  # POST form
    DOM_API = "dom_api"  # location, document
    STORAGE = "storage"  # localStorage/sessionStorage
    POSTMESSAGE = "postmessage"  # window.postMessage
    WEBSOCKET = "websocket"  # WebSocket data
    COOKIE = "cookie"  # document.cookie
    UNKNOWN = "unknown"  # Source not determined


class XSSTypeLabel(Enum):
    """XSS type labels for reports"""

    REFLECTED = "Reflected XSS"
    DOM_BASED = "DOM-Based XSS"
    DOM_EVENT_HANDLER = "DOM XSS (Event Handler)"
    DOM_SCRIPT = "DOM XSS (Script Injection)"
    DOM_INNERHTML = "DOM XSS (innerHTML)"
    STORED = "Stored XSS"
    MUTATION = "Mutation XSS"
    BLIND = "Blind XSS"
    # Quick mode labels (heuristic)
    POTENTIAL_DOM = "Potential DOM XSS"
    POTENTIAL_REFLECTED = "Potential Reflected XSS"
    UNCONFIRMED = "XSS (Unconfirmed)"


@dataclass
class ClassificationRule:
    """A single classification rule"""

    allowed_types: tuple[XSSTypeLabel, ...]
    confidence_ceiling: float
    requires_parameter: bool
    requires_dom_confirmation: bool
    label_suffix: str = ""  # e.g., "(heuristic)"


# ========================================
# CLASSIFICATION RULES MATRIX
# ========================================
# Format: (mode, source) -> ClassificationRule

RULES: dict[tuple[ScanMode, SourceType], ClassificationRule] = {
    # ========================================
    # QUICK MODE - Heuristic, lower confidence
    # ========================================
    (ScanMode.QUICK, SourceType.URL_PARAMETER): ClassificationRule(
        allowed_types=(XSSTypeLabel.REFLECTED, XSSTypeLabel.POTENTIAL_REFLECTED),
        confidence_ceiling=0.85,
        requires_parameter=True,
        requires_dom_confirmation=False,
        label_suffix=" (heuristic)",
    ),
    (ScanMode.QUICK, SourceType.URL_FRAGMENT): ClassificationRule(
        allowed_types=(XSSTypeLabel.DOM_BASED, XSSTypeLabel.POTENTIAL_DOM),
        confidence_ceiling=0.80,
        requires_parameter=False,
        requires_dom_confirmation=False,
        label_suffix=" (heuristic)",
    ),
    (ScanMode.QUICK, SourceType.UNKNOWN): ClassificationRule(
        # CRITICAL: unknown source = CANNOT be Reflected
        allowed_types=(
            XSSTypeLabel.DOM_BASED,
            XSSTypeLabel.POTENTIAL_DOM,
            XSSTypeLabel.UNCONFIRMED,
        ),
        confidence_ceiling=0.80,
        requires_parameter=False,
        requires_dom_confirmation=False,
        label_suffix=" (heuristic)",
    ),
    (ScanMode.QUICK, SourceType.DOM_API): ClassificationRule(
        allowed_types=(XSSTypeLabel.DOM_BASED, XSSTypeLabel.DOM_EVENT_HANDLER),
        confidence_ceiling=0.85,
        requires_parameter=False,
        requires_dom_confirmation=False,
        label_suffix=" (heuristic)",
    ),
    # ========================================
    # STANDARD MODE - Balanced
    # ========================================
    (ScanMode.STANDARD, SourceType.URL_PARAMETER): ClassificationRule(
        allowed_types=(XSSTypeLabel.REFLECTED,),
        confidence_ceiling=0.95,
        requires_parameter=True,
        requires_dom_confirmation=False,
    ),
    (ScanMode.STANDARD, SourceType.URL_FRAGMENT): ClassificationRule(
        allowed_types=(
            XSSTypeLabel.DOM_BASED,
            XSSTypeLabel.DOM_EVENT_HANDLER,
            XSSTypeLabel.DOM_SCRIPT,
        ),
        confidence_ceiling=0.95,
        requires_parameter=False,
        requires_dom_confirmation=False,
    ),
    (ScanMode.STANDARD, SourceType.UNKNOWN): ClassificationRule(
        # CRITICAL: unknown source = CANNOT be Reflected
        allowed_types=(
            XSSTypeLabel.DOM_BASED,
            XSSTypeLabel.DOM_EVENT_HANDLER,
            XSSTypeLabel.DOM_SCRIPT,
        ),
        confidence_ceiling=0.90,
        requires_parameter=False,
        requires_dom_confirmation=False,
    ),
    (ScanMode.STANDARD, SourceType.DOM_API): ClassificationRule(
        allowed_types=(
            XSSTypeLabel.DOM_BASED,
            XSSTypeLabel.DOM_EVENT_HANDLER,
            XSSTypeLabel.DOM_INNERHTML,
        ),
        confidence_ceiling=0.95,
        requires_parameter=False,
        requires_dom_confirmation=False,
    ),
    (ScanMode.STANDARD, SourceType.STORAGE): ClassificationRule(
        allowed_types=(XSSTypeLabel.STORED,),
        confidence_ceiling=0.95,
        requires_parameter=False,
        requires_dom_confirmation=False,
    ),
    # ========================================
    # DEEP MODE - Full confirmation
    # ========================================
    (ScanMode.DEEP, SourceType.URL_PARAMETER): ClassificationRule(
        allowed_types=(XSSTypeLabel.REFLECTED,),
        confidence_ceiling=1.0,
        requires_parameter=True,
        requires_dom_confirmation=True,
    ),
    (ScanMode.DEEP, SourceType.URL_FRAGMENT): ClassificationRule(
        allowed_types=(
            XSSTypeLabel.DOM_BASED,
            XSSTypeLabel.DOM_EVENT_HANDLER,
            XSSTypeLabel.DOM_SCRIPT,
        ),
        confidence_ceiling=1.0,
        requires_parameter=False,
        requires_dom_confirmation=True,
    ),
    (ScanMode.DEEP, SourceType.UNKNOWN): ClassificationRule(
        allowed_types=(
            XSSTypeLabel.DOM_BASED,
            XSSTypeLabel.DOM_EVENT_HANDLER,
            XSSTypeLabel.DOM_SCRIPT,
        ),
        confidence_ceiling=0.95,
        requires_parameter=False,
        requires_dom_confirmation=True,
    ),
}


# ========================================
# DETERMINISTIC PAYLOAD OVERRIDES
# ========================================
# These payloads always have high confidence regardless of mode

DETERMINISTIC_PATTERNS = {
    # Pattern: (min_confidence, type_override)
    "<script": (0.95, None),  # 95% confidence, no type override
    "onerror=": (0.90, XSSTypeLabel.DOM_EVENT_HANDLER),
    "onload=": (0.90, XSSTypeLabel.DOM_EVENT_HANDLER),
    "<script src=": (0.98, XSSTypeLabel.DOM_SCRIPT),  # External script = definitive
}


def get_rule(mode: ScanMode, source: SourceType) -> Optional[ClassificationRule]:
    """Get classification rule for mode/source combination"""
    return RULES.get((mode, source))


def validate_classification(
    mode: str,
    source: str,
    proposed_type: str,
    parameter: Optional[str],
    confidence: float,
    payload: str,
) -> dict[str, Any]:
    """
    Validate and potentially correct a classification.

    Returns:
        dict with 'valid', 'corrected_type', 'corrected_confidence', 'reason'
    """

    # Parse enums
    try:
        scan_mode = ScanMode(mode)
    except ValueError:
        scan_mode = ScanMode.STANDARD

    try:
        source_type = SourceType(source)
    except ValueError:
        source_type = SourceType.UNKNOWN

    # Get rule
    rule = get_rule(scan_mode, source_type)

    result = {
        "valid": True,
        "corrected_type": proposed_type,
        "corrected_confidence": confidence,
        "reason": None,
        "label_suffix": "",
    }

    # Apply deterministic pattern overrides first
    payload_lower = payload.lower()
    for pattern, (min_conf, type_override) in DETERMINISTIC_PATTERNS.items():
        if pattern in payload_lower:
            if confidence < min_conf:
                result["corrected_confidence"] = min_conf
                result["reason"] = (
                    f"Deterministic pattern '{pattern}' requires {min_conf*100:.0f}%+ confidence"
                )
            if type_override and "Reflected" in proposed_type:
                # Don't override to Reflected for deterministic DOM patterns
                if parameter in (None, "", "unknown"):
                    result["corrected_type"] = type_override.value
                    result["reason"] = "Parameter unknown, cannot be Reflected"

    if not rule:
        return result

    # Check parameter requirement
    param_is_known = parameter and parameter not in ("unknown", "")

    if rule.requires_parameter and not param_is_known:
        # Cannot use Reflected if parameter unknown
        if "Reflected" in proposed_type:
            result["valid"] = False
            result["corrected_type"] = XSSTypeLabel.DOM_BASED.value
            result["reason"] = "Parameter unknown, cannot be Reflected XSS"

    # Check confidence ceiling
    if confidence > rule.confidence_ceiling:
        result["corrected_confidence"] = rule.confidence_ceiling
        result["reason"] = (
            f"{mode} mode caps confidence at {rule.confidence_ceiling*100:.0f}%"
        )

    # Apply label suffix for quick mode
    corrected_type_str = str(result["corrected_type"])
    if rule.label_suffix and " (heuristic)" not in corrected_type_str:
        result["label_suffix"] = rule.label_suffix

    # Check if proposed type is allowed
    allowed_values = [t.value for t in rule.allowed_types]
    type_allowed = any(
        proposed_type == av or av in proposed_type for av in allowed_values
    )

    if not type_allowed:
        # Find best matching allowed type
        if "DOM" in proposed_type:
            for t in rule.allowed_types:
                if "DOM" in t.value:
                    result["corrected_type"] = t.value
                    break
        elif "Reflected" in proposed_type:
            for t in rule.allowed_types:
                if "Reflected" in t.value:
                    result["corrected_type"] = t.value
                    break

        if result["corrected_type"] == proposed_type:
            # Use first allowed type
            result["corrected_type"] = rule.allowed_types[0].value

        result["valid"] = False
        result["reason"] = f"Type '{proposed_type}' not allowed for {mode}/{source}"

    return result


def apply_classification_rules(
    vulnerability: dict[str, Any], scan_mode: str = "standard"
) -> dict[str, Any]:
    """
    Apply classification rules to a vulnerability dict.
    Modifies the dict in-place and returns it.
    """

    source = vulnerability.get("reflection_type", vulnerability.get("source", ""))
    proposed_type = vulnerability.get(
        "vulnerability_type", vulnerability.get("xss_type", "")
    )
    parameter = vulnerability.get("parameter", "")
    confidence = vulnerability.get("confidence", 0.8)
    payload = vulnerability.get("payload", "")

    # Infer source from parameter if not explicitly set
    # If parameter is known, source is likely url_parameter
    param_is_known = parameter and parameter not in ("unknown", "", "N/A")
    if not source or source == "unknown":
        if param_is_known:
            source = "url_parameter"
        else:
            source = "unknown"

    result = validate_classification(
        mode=scan_mode,
        source=source,
        proposed_type=proposed_type,
        parameter=parameter,
        confidence=confidence,
        payload=payload,
    )

    if not result["valid"] or result["corrected_type"] != proposed_type:
        vulnerability["vulnerability_type"] = result["corrected_type"]
        if result.get("classification_note"):
            vulnerability["classification_note"] = result["reason"]

    if result["corrected_confidence"] != confidence:
        vulnerability["confidence"] = result["corrected_confidence"]

    if result["label_suffix"]:
        vulnerability["label_suffix"] = result["label_suffix"]

    return vulnerability
