#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Created - Phase 9: Unified Finding Normalization
Telegram: https://t.me/EasyProTech

Finding Normalizer - Single normalization point for ALL findings.

CRITICAL RULE:
No finding should reach any report (PDF/JSON/SARIF)
without passing through normalize_finding().

Solves the problem:
- DOM fragment findings bypassed classification pipeline
- scanner findings passed, DOM - did not
- Different semantics in the same report

Architecture:
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ scanner.py       │    │ headless_        │    │ other sources    │
│ (parameter XSS)  │    │ detector.py      │    │ (blind, stored)  │
└────────┬─────────┘    │ (DOM fragment)   │    └────────┬─────────┘
         │              └────────┬─────────┘             │
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  normalize_finding()   │  ← SINGLE ENTRY POINT
                    │  - classification_rules│
                    │  - deterministic_boost │
                    │  - context_hierarchy   │
                    │  - dev_assertions      │
                    └────────────┬───────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │ PDF / JSON / SARIF     │
                    └────────────────────────┘
"""

from typing import Any
import re

from ..utils.logger import Logger

# Import classification components
try:
    from .classification_rules import apply_classification_rules
    from .payload_analyzer import get_payload_analyzer

    CLASSIFICATION_AVAILABLE = True
except ImportError:
    CLASSIFICATION_AVAILABLE = False

logger = Logger("core.finding_normalizer")


# ============================================
# DETERMINISTIC CONFIDENCE FLOORS
# ============================================
# These patterns ALWAYS get minimum confidence regardless of mode

CONFIDENCE_FLOORS = {
    # Pattern: (min_confidence, reason)
    "<script": (0.95, "script injection"),
    "<script src=": (0.98, "external script load"),
    "onerror=": (0.90, "event-handler execution"),
    "onload=": (0.90, "event-handler execution"),
    "onmouseover=": (0.85, "event-handler (user interaction)"),
    "onclick=": (0.80, "event-handler (user interaction)"),
    "javascript:": (0.85, "javascript URI"),
}

# ============================================
# XSS TYPE RULES
# ============================================
# parameter=unknown/None -> CANNOT be Reflected

REFLECTED_REQUIRES_PARAMETER = True  # Critical rule

RUNTIME_CONFIRMED_STATES = {
    "auto_immediate",
    "dom_confirmed",
    "runtime_confirmed",
    "browser_confirmed",
    "playwright_confirmed",
    "headless_confirmed",
}

LOW_INTERACTION_STATES = {
    "auto_immediate",
    "dom_confirmed",
    "runtime_confirmed",
    "browser_confirmed",
}

EXECUTION_LABELS = {
    "auto_immediate": "DOM instrumentation (auto execute)",
    "dom_confirmed": "DOM chain confirmed via Playwright",
    "runtime_confirmed": "Runtime execution confirmed",
    "browser_confirmed": "Browser execution confirmed",
    "playwright_confirmed": "Playwright runtime confirmed",
    "headless_confirmed": "Headless browser confirmed",
    "load_triggered": "Heuristic load-trigger (requires manual confirmation)",
    "event_handler": "Event-handler heuristic (manual confirmation)",
    "context_only": "Context reflection only (no runtime evidence)",
}


def normalize_finding(
    finding: dict[str, Any], mode: str = "standard"
) -> dict[str, Any]:
    """
    Normalize a finding through the unified pipeline.

    This is the SINGLE POINT of normalization for ALL findings.

    Steps:
    1. Apply classification rules (mode-based)
    2. Apply deterministic confidence floors
    3. Normalize context hierarchy
    4. Run dev assertions

    Args:
        finding: Vulnerability finding dict
        mode: Scan mode (quick/standard/deep)

    Returns:
        Normalized finding dict
    """

    if not finding:
        return finding

    # Make a copy to avoid mutating original
    f = dict(finding)

    # Extract key fields
    param = f.get("parameter", "")
    payload = f.get("payload", "")
    vuln_type = f.get("vulnerability_type", f.get("xss_type", ""))
    context = f.get("context", f.get("context_type", "unknown"))
    confidence = f.get("confidence", 0.8)

    payload_lower = payload.lower() if payload else ""

    # ========================================
    # STEP 1: Classification Rules
    # ========================================
    if CLASSIFICATION_AVAILABLE:
        f = apply_classification_rules(f, scan_mode=mode)
        # Re-extract after rules applied
        vuln_type = f.get("vulnerability_type", vuln_type)
        confidence = f.get("confidence", confidence)

    # ========================================
    # STEP 2: CRITICAL - Reflected XSS requires parameter
    # ========================================
    param_is_unknown = param in (None, "", "unknown", "N/A")
    is_reflected = "Reflected" in vuln_type if vuln_type else False

    if is_reflected and param_is_unknown:
        # VIOLATION: Cannot be Reflected without known parameter
        logger.warning(
            "CLASSIFICATION FIX: Reflected XSS with unknown parameter -> DOM-Based XSS"
        )

        # Determine DOM subtype from payload
        if "<script" in payload_lower:
            f["vulnerability_type"] = "DOM XSS (Script Injection)"
        elif any(h in payload_lower for h in ["onerror=", "onload=", "onmouseover="]):
            f["vulnerability_type"] = "DOM XSS (Event Handler)"
        elif "innerhtml" in payload_lower:
            f["vulnerability_type"] = "DOM XSS (innerHTML)"
        elif "DOM_XSS" in payload:
            # Payload contains DOM marker
            f["vulnerability_type"] = "DOM-Based XSS"
        else:
            f["vulnerability_type"] = "DOM-Based XSS"

        # Add heuristic suffix for quick mode
        if mode == "quick":
            f["vulnerability_type"] += " (heuristic)"

        vuln_type = f["vulnerability_type"]

    # ========================================
    # STEP 3: Deterministic Confidence Floors
    # ========================================
    for pattern, (min_conf, reason) in CONFIDENCE_FLOORS.items():
        if pattern in payload_lower:
            if confidence < min_conf:
                logger.debug(
                    f"CONFIDENCE BOOST: {pattern} requires {min_conf*100:.0f}%+, "
                    f"was {confidence*100:.0f}%"
                )
                f["confidence"] = min_conf
                f["confidence_reason"] = reason
                confidence = min_conf
            break  # Apply only first matching pattern

    # ========================================
    # STEP 4: Context Hierarchy Normalization
    # ========================================
    # If we have payload class info, use it to build hierarchical context
    f.get("payload_class", "")
    trigger_element = f.get("trigger_element", "")
    trigger_attribute = f.get("trigger_attribute", "")

    if context in ("html", "unknown") and (trigger_element or trigger_attribute):
        # Build hierarchical context
        if trigger_element and trigger_attribute:
            f["context"] = f"html > {trigger_element} > {trigger_attribute}"
        elif trigger_element:
            f["context"] = f"html > {trigger_element}"
        context = f["context"]

    # If still just 'html' but we can infer from payload
    if context == "html":
        if "<script" in payload_lower:
            f["context"] = "html > script"
        elif "onerror=" in payload_lower:
            # Extract element
            img_match = re.search(r"<(\w+)[^>]*onerror=", payload_lower)
            if img_match:
                f["context"] = f"html > {img_match.group(1)} > onerror"
            else:
                f["context"] = "html > tag > onerror"
        elif "onload=" in payload_lower:
            svg_match = re.search(r"<(\w+)[^>]*onload=", payload_lower)
            if svg_match:
                f["context"] = f"html > {svg_match.group(1)} > onload"
            else:
                f["context"] = "html > tag > onload"
        context = f["context"]

    # ========================================
    # STEP 5: Payload Analysis (if not done)
    # ========================================
    if CLASSIFICATION_AVAILABLE and not f.get("trigger_element"):
        try:
            analyzer = get_payload_analyzer()
            analysis = analyzer.analyze(payload)

            # Add missing fields
            if not f.get("trigger_element"):
                f["trigger_element"] = analysis.trigger_element
            if not f.get("trigger_attribute"):
                f["trigger_attribute"] = analysis.trigger_attribute
            if not f.get("trigger"):
                f["trigger"] = analysis.trigger_vector
            if not f.get("is_deterministic"):
                f["is_deterministic"] = analysis.is_deterministic
            if not f.get("requires_interaction"):
                f["requires_interaction"] = analysis.requires_interaction
            if not f.get("payload_class"):
                f["payload_class"] = analysis.payload_class_string
            if not f.get("execution"):
                f["execution"] = analysis.execution.value

        except Exception as e:
            logger.debug(f"Payload analysis failed: {e}")

    # ========================================
    # STEP 6: Dev Assertions
    # ========================================
    _run_assertions(f)

    return f


def normalize_findings(
    findings: list[dict[str, Any]], mode: str = "standard"
) -> list[dict[str, Any]]:
    """
    Normalize all findings in a list.

    Args:
        findings: list of vulnerability findings
        mode: Scan mode

    Returns:
        list of normalized findings
    """
    return [normalize_finding(f, mode) for f in findings]


def _run_assertions(finding: dict[str, Any]):
    """
    Run development assertions to catch logic errors.

    These should never fire in production if pipeline is correct.
    """
    param = finding.get("parameter", "")
    vuln_type = finding.get("vulnerability_type", "")
    confidence = finding.get("confidence", 0)

    param_is_unknown = param in (None, "", "unknown", "N/A")

    # ASSERTION 1: Reflected XSS requires known parameter
    if "Reflected" in vuln_type and param_is_unknown:
        logger.error(
            f"ASSERTION FAILED: Reflected XSS with unknown parameter! "
            f"Type={vuln_type}, Param={param}"
        )
        # In dev mode, could raise here
        # raise AssertionError("Reflected XSS requires known parameter")

    # ASSERTION 2: Confidence should be reasonable
    if confidence < 0 or confidence > 1:
        logger.error(f"ASSERTION FAILED: Invalid confidence {confidence}")

    # ASSERTION 3: <script> should have high confidence
    payload = finding.get("payload", "").lower()
    if "<script" in payload and confidence < 0.90:
        logger.warning(
            f"ASSERTION WARNING: Script injection with low confidence "
            f"({confidence*100:.0f}%)"
        )


# ============================================
# CONVENIENCE FUNCTION FOR REPORTS
# ============================================


def prepare_findings_for_report(
    findings: list[dict[str, Any]], mode: str = "standard"
) -> dict[str, list[dict[str, Any]]]:
    """
    Prepare findings for report generation.

    This is the ONLY function that should be called before
    generating PDF/JSON/SARIF reports.

    Args:
        findings: Raw findings from scanner/DOM detector
        mode: Scan mode used

    Returns:
        Normalized findings ready for reporting
    """
    logger.info(f"Normalizing {len(findings)} findings for {mode} mode report")

    normalized = normalize_findings(findings, mode)

    confirmed: list[dict[str, Any]] = []
    potential: list[dict[str, Any]] = []

    for f in normalized:
        severity = str(f.get("severity", "low")).lower()
        param = f.get("parameter", "")
        confidence = f.get("confidence", 0.0)
        vuln_type = f.get("vulnerability_type", "")
        execution_raw = f.get("execution")
        execution_state = str(execution_raw or "").lower()
        execution_present = execution_state not in ("", "none", "unknown")
        runtime_confirmed = execution_state in RUNTIME_CONFIRMED_STATES
        evidence_present = bool(f.get("evidence")) or bool(f.get("evidence_payloads"))
        if execution_present:
            execution_label = EXECUTION_LABELS.get(
                execution_state,
                "Heuristic context trace (manual confirmation required)",
            )
        else:
            execution_label = "Legacy finding (execution telemetry unavailable)"
        f["execution_proof"] = execution_label
        f["runtime_confirmed"] = runtime_confirmed

        # Heuristic for potential findings
        is_dom = "dom" in vuln_type.lower()
        has_source = bool(f.get("source"))
        has_sink = bool(f.get("sink"))
        is_reflected = "reflected" in vuln_type.lower()
        param_unknown = param in (None, "", "unknown", "N/A")

        requires_interaction = f.get("requires_interaction")
        if requires_interaction is None:
            requires_interaction = execution_state not in LOW_INTERACTION_STATES
            f["requires_interaction"] = requires_interaction

        confirmable = True
        if is_reflected and param_unknown:
            confirmable = False
        if is_dom and not (has_source and has_sink):
            confirmable = False
        if confidence < 0.5:
            confirmable = False

        # Severity-based confidence guardrails (unless runtime confirmed)
        min_conf = 0.5
        if severity in ("high", "critical"):
            min_conf = 0.7
        elif severity == "medium":
            min_conf = 0.55
        if (
            confidence < min_conf
            and not runtime_confirmed
            and (execution_present or evidence_present)
        ):
            confirmable = False

        # Reflected findings without runtime/evidence stay heuristic
        if (
            is_reflected
            and (execution_present or evidence_present)
            and not runtime_confirmed
            and not evidence_present
        ):
            confirmable = False
            existing_notes = f.get("notes")
            if isinstance(existing_notes, list):
                notes_list = existing_notes
            elif existing_notes:
                notes_list = [existing_notes]
            else:
                notes_list = []
            notes_list.append("No runtime evidence captured")
            f["notes"] = notes_list

        f["is_confirmed"] = confirmable
        f["status"] = "confirmed" if confirmable else "potential"

        # Human readable exploitability details
        user_interaction_text = (
            "No (auto execution)"
            if not requires_interaction
            else "Yes (victim must load crafted URL)"
        )
        persistence_text = (
            "Yes (stored vector)"
            if "stored" in vuln_type.lower()
            else "No (transient injection)"
        )
        authentication_flag = f.get("requires_authentication")
        if authentication_flag is None:
            authentication_text = "Not evaluated (scan unauthenticated)"
        else:
            authentication_text = "Yes" if authentication_flag else "No"
        f["exploitability"] = {
            "user_interaction": user_interaction_text,
            "persistence": persistence_text,
            "authentication": authentication_text,
        }

        # Human readable impact scope
        impact_scope = f.get("impact_scope")
        if not impact_scope and is_dom:
            scope_items = [
                "Potential cookie access (HttpOnly not verified)",
                "Potential session impact",
                "Same-origin DOM read/write",
            ]
            f["impact_scope"] = " | ".join(scope_items)
        elif not impact_scope:
            f["impact_scope"] = (
                "Potential cookie access (HttpOnly not verified) | Potential session impact"
            )

        if confirmable:
            confirmed.append(f)
        else:
            potential.append(f)

    # Log summary
    type_counts: dict[str, int] = {}
    for f in normalized:
        t = f.get("vulnerability_type", "Unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    for t, count in type_counts.items():
        logger.info(f"  {t}: {count}")

    return {"confirmed": confirmed, "potential": potential, "all": normalized}
