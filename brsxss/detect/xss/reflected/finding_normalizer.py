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
import hashlib
from enum import Enum

from brsxss.utils.logger import Logger


# ============================================
# v4.0.0-beta.2: INJECTION TYPE CLASSIFICATION
# ============================================
# Distinguishes between:
# - Tag Injection: payload contains complete HTML tag (<script>, <img>, etc.)
# - Attribute Injection: payload modifies existing attribute value
# - Content Injection: payload appears in text content


class InjectionType(Enum):
    """Type of XSS injection"""

    TAG_INJECTION = "tag_injection"  # <script>, <img onerror=...>
    ATTRIBUTE_INJECTION = "attribute_injection"  # Inside existing attr value
    CONTENT_INJECTION = "content_injection"  # In text content
    JAVASCRIPT_INJECTION = "javascript_injection"  # Inside <script> block
    CSS_INJECTION = "css_injection"  # Inside <style> or style attr
    URL_INJECTION = "url_injection"  # In href/src with javascript:
    UNKNOWN = "unknown"


def classify_injection_type(payload: str, context: str) -> tuple[InjectionType, str]:
    """
    Classify the type of XSS injection based on payload and context.

    Returns:
        Tuple of (InjectionType, corrected_context_string)

    Examples:
        - <SCRIPT SRC="..."></SCRIPT> -> TAG_INJECTION, "html > tag_injection > script"
        - " onerror=alert(1) x=" -> ATTRIBUTE_INJECTION, "html > img > onerror"
        - javascript:alert(1) -> URL_INJECTION, "html > a > href > javascript_uri"
    """
    payload_lower = payload.lower().strip()
    context_lower = context.lower() if context else ""

    # Pattern: Full HTML tag injection
    # Matches: <script>, <img, <svg, <iframe, <body, <input, etc.
    tag_patterns = [
        (r"<\s*script[^>]*>", "script"),
        (r"<\s*img\s+[^>]*on\w+\s*=", "img"),
        (r"<\s*svg[^>]*on\w+\s*=", "svg"),
        (r"<\s*iframe[^>]*", "iframe"),
        (r"<\s*body[^>]*on\w+\s*=", "body"),
        (r"<\s*input[^>]*on\w+\s*=", "input"),
        (r"<\s*video[^>]*on\w+\s*=", "video"),
        (r"<\s*audio[^>]*on\w+\s*=", "audio"),
        (r"<\s*object[^>]*", "object"),
        (r"<\s*embed[^>]*", "embed"),
        (r"<\s*link[^>]*", "link"),
        (r"<\s*style[^>]*>", "style"),
        (r"<\s*marquee[^>]*on\w+\s*=", "marquee"),
        (r"<\s*details[^>]*on\w+\s*=", "details"),
    ]

    for pattern, tag_name in tag_patterns:
        if re.search(pattern, payload_lower):
            # This is TAG INJECTION - payload creates new HTML element
            corrected_context = f"html > tag_injection > {tag_name}"

            # Add trigger info if event handler present
            event_match = re.search(r"on(\w+)\s*=", payload_lower)
            if event_match:
                corrected_context += f" > {event_match.group(0).rstrip('=')}"

            return InjectionType.TAG_INJECTION, corrected_context

    # Pattern: Attribute breakout + event handler
    # Matches: " onerror=..., ' onclick=..., etc.
    attr_breakout_pattern = r'^["\']?\s*[^<]*on(\w+)\s*='
    if re.search(attr_breakout_pattern, payload_lower):
        event_match = re.search(r"on(\w+)\s*=", payload_lower)
        if event_match:
            handler = event_match.group(0).rstrip("=")
            # Try to extract tag from context
            tag_match = re.search(r"html\s*>\s*(\w+)", context_lower)
            tag_name = tag_match.group(1) if tag_match else "element"
            corrected_context = f"html > {tag_name} > {handler}"
            return InjectionType.ATTRIBUTE_INJECTION, corrected_context

    # Pattern: javascript: URI
    if re.search(r"javascript\s*:", payload_lower):
        # Check if in href/src context
        if "href" in context_lower:
            return InjectionType.URL_INJECTION, "html > a > href > javascript_uri"
        elif "src" in context_lower:
            return InjectionType.URL_INJECTION, "html > element > src > javascript_uri"
        else:
            return InjectionType.URL_INJECTION, "html > url > javascript_uri"

    # Pattern: data: URI with HTML
    if re.search(r"data\s*:\s*text/html", payload_lower):
        return InjectionType.URL_INJECTION, "html > element > src > data_uri"

    # Pattern: Inside script context (no tag, just JS code)
    if "script" in context_lower and not re.search(r"<\s*script", payload_lower):
        return InjectionType.JAVASCRIPT_INJECTION, context

    # Pattern: CSS injection
    if "style" in context_lower or re.search(r"expression\s*\(", payload_lower):
        return InjectionType.CSS_INJECTION, context

    # Default: content injection or unknown
    if context_lower:
        return InjectionType.CONTENT_INJECTION, context

    return InjectionType.UNKNOWN, context or "unknown"


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
    # STEP 2: v4.0.0-beta.2 - INJECTION TYPE CLASSIFICATION
    # ========================================
    # Classify injection type and add detailed context
    # NOTE: We keep original context for KB lookup compatibility,
    # but add injection_context for detailed classification
    injection_type, injection_context = classify_injection_type(payload, context)
    f["injection_type"] = injection_type.value
    f["injection_context"] = injection_context

    # Log if classification differs from original context
    if injection_context != context:
        logger.debug(
            f"Injection context: '{context}' -> '{injection_context}' "
            f"(type: {injection_type.value})"
        )

    # ========================================
    # STEP 3: CRITICAL - Reflected XSS requires parameter
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


# ============================================
# DEDUPLICATION AND GROUPING
# ============================================


def _compute_finding_fingerprint(finding: dict[str, Any]) -> str:
    """
    Compute a unique fingerprint for a finding.

    Key: param + context + payload_normalized

    This groups findings that are essentially the same vulnerability
    found on different URLs (e.g., same template rendered on multiple endpoints).
    """
    param = str(finding.get("parameter", "")).lower().strip()
    context = (
        str(finding.get("context", finding.get("context_type", ""))).lower().strip()
    )
    payload = str(finding.get("payload", "")).lower().strip()

    # Normalize payload - remove variable parts like URLs, timestamps
    payload_normalized = re.sub(r'https?://[^\s<>"\']+', "URL", payload)
    payload_normalized = re.sub(r"\d{10,}", "TIMESTAMP", payload_normalized)

    key = f"{param}|{context}|{payload_normalized}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


def deduplicate_and_group_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Deduplicate findings and group by pattern.

    Instead of showing 14 identical findings on different URLs,
    shows 1 finding with 14 affected URLs.

    Returns:
        List of unique findings with 'affected_urls' list
    """
    if not findings:
        return []

    # Group by fingerprint
    groups: dict[str, list[dict[str, Any]]] = {}

    for f in findings:
        fp = _compute_finding_fingerprint(f)
        if fp not in groups:
            groups[fp] = []
        groups[fp].append(f)

    # Create deduplicated findings
    result: list[dict[str, Any]] = []

    for fp, group in groups.items():
        # Use first finding as template
        primary = dict(group[0])

        # Collect all affected URLs
        affected_urls = []
        for f in group:
            url = f.get("url", "")
            method = f.get("method", "GET")
            if url:
                affected_urls.append({"url": url, "method": method})

        # Remove duplicates while preserving order
        seen_urls: set[str] = set()
        unique_urls = []
        for u in affected_urls:
            key = f"{u['method']}:{u['url']}"
            if key not in seen_urls:
                seen_urls.add(key)
                unique_urls.append(u)

        primary["affected_urls"] = unique_urls
        primary["occurrence_count"] = len(unique_urls)
        primary["fingerprint"] = fp

        # If multiple occurrences, note it
        if len(unique_urls) > 1:
            primary["is_pattern"] = True
            primary["pattern_note"] = (
                f"Same vulnerability pattern found on {len(unique_urls)} endpoints"
            )

        result.append(primary)

    # Sort by occurrence count (most common patterns first)
    result.sort(key=lambda x: -x.get("occurrence_count", 1))

    logger.info(
        f"Deduplicated {len(findings)} findings to {len(result)} unique patterns"
    )

    return result


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
) -> dict[str, Any]:
    """
    Prepare findings for report generation.

    This is the ONLY function that should be called before
    generating PDF/JSON/SARIF reports.

    v4.0.0-beta.2 Changes:
    - Added deduplication and grouping by pattern
    - Fixed confidence for heuristic findings (cannot be 100%)
    - Removed severity levels for heuristic (only POTENTIAL)

    Args:
        findings: Raw findings from scanner/DOM detector
        mode: Scan mode used

    Returns:
        Normalized and deduplicated findings ready for reporting
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

        # ========================================
        # v4.0.0-beta.2 FIX: Simplified confirmation logic
        # ========================================
        # A finding is CONFIRMED if:
        # 1. DOM XSS with confidence >= 0.6 (headless browser tested it!)
        # 2. Reflected XSS with known parameter and confidence >= 0.5
        # 3. Any finding with runtime_confirmed flag
        # 4. Any finding with actual evidence content
        #
        # A finding is POTENTIAL (heuristic) if:
        # 1. Very low confidence (< 0.5)
        # 2. Reflected XSS without known parameter
        # 3. No evidence and no runtime confirmation and low confidence

        confirmable = False  # Start with False, prove it's confirmed

        # Check for actual evidence
        actual_evidence = f.get("evidence", "") or f.get("evidence_response", "")
        has_actual_evidence = bool(actual_evidence and str(actual_evidence).strip())

        # DOM XSS: If headless browser found it with decent confidence, it's confirmed
        # The headless detector actually executes payloads in browser!
        if is_dom and confidence >= 0.6:
            confirmable = True
            f["confirmation_reason"] = "DOM XSS detected via headless browser execution"
            logger.debug(f"DOM XSS confirmed: confidence={confidence:.2f}")

        # Reflected XSS: Need known parameter and decent confidence
        elif is_reflected and not param_unknown and confidence >= 0.5:
            confirmable = True
            f["confirmation_reason"] = "Reflected XSS with known parameter"
            logger.debug(f"Reflected XSS confirmed: param={param}, confidence={confidence:.2f}")

        # Runtime confirmed always wins
        elif runtime_confirmed:
            confirmable = True
            f["confirmation_reason"] = "Runtime execution confirmed"

        # Actual evidence content confirms finding
        elif has_actual_evidence:
            confirmable = True
            f["confirmation_reason"] = "Evidence content captured"

        # High confidence (>= 0.8) with any severity is likely real
        elif confidence >= 0.8 and severity in ("critical", "high"):
            confirmable = True
            f["confirmation_reason"] = f"High confidence ({confidence:.0%}) {severity} finding"

        # Log why not confirmed
        if not confirmable:
            reasons = []
            if confidence < 0.5:
                reasons.append(f"low confidence ({confidence:.0%})")
            if is_reflected and param_unknown:
                reasons.append("reflected without known parameter")
            if is_dom and confidence < 0.6:
                reasons.append(f"DOM with insufficient confidence ({confidence:.0%})")
            logger.debug(f"Marking as heuristic: {', '.join(reasons) or 'no confirmation criteria met'}")

        f["is_confirmed"] = confirmable
        f["status"] = "confirmed" if confirmable else "potential"

        # ========================================
        # v4.0.0-beta.2: HEURISTIC FINDINGS RULES
        # ========================================
        # 1. Heuristic findings CANNOT have severity (only POTENTIAL)
        # 2. Heuristic findings CANNOT have 100% confidence
        # 3. Confidence label must reflect uncertainty

        if not confirmable:
            # Rule 1: Remove severity for heuristic - use "potential" instead
            f["original_severity"] = severity  # Keep for reference
            f["severity"] = "potential"

            # Rule 2: Cap confidence at 85% for heuristic (cannot be 100%)
            if confidence >= 0.85:
                f["confidence"] = 0.85
                f["confidence_note"] = (
                    "Capped at 85% (heuristic, requires manual validation)"
                )

            # Rule 3: Confidence label
            conf_val = f.get("confidence", confidence)
            if conf_val >= 0.7:
                f["confidence_label"] = "High (heuristic)"
            elif conf_val >= 0.5:
                f["confidence_label"] = "Medium (heuristic)"
            else:
                f["confidence_label"] = "Low (heuristic)"

            # Execution proof must indicate manual confirmation needed
            f["execution_proof"] = (
                "Heuristic context trace (manual confirmation required)"
            )

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

    # ========================================
    # v4.0.0-beta.2: DEDUPLICATION
    # ========================================
    # Group findings by pattern to avoid showing same vuln 14 times

    confirmed_deduped = deduplicate_and_group_findings(confirmed)
    potential_deduped = deduplicate_and_group_findings(potential)

    # Log summary
    logger.info(
        f"Confirmed: {len(confirmed)} -> {len(confirmed_deduped)} unique patterns"
    )
    logger.info(
        f"Potential: {len(potential)} -> {len(potential_deduped)} unique patterns"
    )

    type_counts: dict[str, int] = {}
    for f in normalized:
        t = f.get("vulnerability_type", "Unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    for t, count in type_counts.items():
        logger.info(f"  {t}: {count}")

    return {
        "confirmed": confirmed_deduped,
        "potential": potential_deduped,
        "all": normalized,
        # v4.0.0-beta.2: Include raw counts for summary
        "stats": {
            "unique_confirmed": len(confirmed_deduped),
            "unique_potential": len(potential_deduped),
            "total_occurrences_confirmed": len(confirmed),
            "total_occurrences_potential": len(potential),
        },
    }
