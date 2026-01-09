#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Created - Runtime Payload Analysis
Telegram: https://t.me/EasyProTech

Payload Analyzer - computes runtime metadata for payloads from KB.

Architecture:
┌─────────────────────┐    ┌─────────────────────────────────────────────┐
│ BRS-KB (Static)     │    │ BRS-XSS PayloadAnalyzer (Runtime)           │
├─────────────────────┤    ├─────────────────────────────────────────────┤
│ payload: "<img..."  │ -> │ trigger_element: "img"                      │
│ contexts: ["html"]  │    │ trigger_attribute: "onerror"                │
│ severity: "high"    │    │ execution: "error_triggered"                │
│ tags: ["onerror"]   │    │ is_deterministic: true                      │
│                     │    │ xss_type_hint: "DOM XSS (Event Handler)"    │
│                     │    │ injection_class: "html_attribute_injection" │
│                     │    │ confidence_boost: 0.15                      │
└─────────────────────┘    └─────────────────────────────────────────────┘

This module COMPUTES what KB cannot store - runtime characteristics
that depend on payload structure analysis.
"""

from typing import Optional, Dict, Any, Set
from dataclasses import dataclass
from enum import Enum
import re

from ..utils.logger import Logger

logger = Logger("core.payload_analyzer")


class ExecutionType(Enum):
    """How the payload executes"""

    ERROR_TRIGGERED = "error_triggered"  # onerror - fires on resource error
    LOAD_TRIGGERED = "load_triggered"  # onload - fires on resource load
    AUTO_IMMEDIATE = "auto_immediate"  # <script> - immediate execution
    AUTO_DELAYED = "auto_delayed"  # animation/transition events
    USER_CLICK = "user_click"  # onclick, ondblclick
    USER_HOVER = "user_hover"  # onmouseover, onmouseenter
    USER_FOCUS = "user_focus"  # onfocus, onblur
    USER_INPUT = "user_input"  # onchange, oninput
    USER_SCROLL = "user_scroll"  # onscroll
    EXTERNAL_LOAD = "external_load"  # <script src="">
    NONE = "none"


class InjectionClass(Enum):
    """Computed injection classification"""

    SCRIPT_INLINE = "script_inline"  # <script>code</script>
    SCRIPT_EXTERNAL = "script_external"  # <script src="">
    HTML_ATTRIBUTE = "html_attribute"  # <img onerror="">
    EVENT_HANDLER = "event_handler"  # onerror=, onclick=
    JAVASCRIPT_URI = "javascript_uri"  # href="javascript:"
    DATA_URI = "data_uri"  # src="data:text/html"
    SVG_INJECTION = "svg_injection"  # <svg onload="">
    CSS_EXPRESSION = "css_expression"  # style="x:expression()"
    TEMPLATE = "template"  # {{payload}}
    EVAL_BASED = "eval_based"  # eval(), setTimeout()
    DOM_SINK = "dom_sink"  # innerHTML, document.write
    UNKNOWN = "unknown"


class XSSTypeHint(Enum):
    """XSS type hint computed from payload"""

    LIKELY_REFLECTED = "likely_reflected"
    LIKELY_DOM = "likely_dom"
    LIKELY_STORED = "likely_stored"
    DOM_EVENT_HANDLER = "DOM XSS (Event Handler)"
    DOM_INNERHTML = "DOM XSS (innerHTML)"
    DOM_SCRIPT = "DOM XSS (Script Injection)"
    DETERMINISTIC_DOM = "deterministic_dom"
    REQUIRES_INTERACTION = "requires_interaction"
    UNKNOWN = "unknown"


@dataclass
class AnalyzedPayload:
    """
    Complete runtime analysis of a payload.

    This is what BRS-XSS computes locally, not what KB stores.
    """

    # Original payload
    payload: str

    # Computed trigger info
    trigger_element: Optional[str] = None
    trigger_attribute: Optional[str] = None
    trigger_vector: str = ""  # e.g., "img.onerror", "script.src"

    # Execution characteristics
    execution: ExecutionType = ExecutionType.NONE
    is_deterministic: bool = False
    requires_interaction: bool = False
    auto_executes: bool = False

    # Injection classification
    injection_class: InjectionClass = InjectionClass.UNKNOWN

    # XSS type hint
    xss_type_hint: XSSTypeHint = XSSTypeHint.UNKNOWN

    # Confidence/severity modifiers
    confidence_boost: float = 0.0  # +0.0 to +0.3
    severity_minimum: str = "medium"  # "low", "medium", "high", "critical"

    # Additional computed metadata
    contains_external_resource: bool = False
    external_url: Optional[str] = None
    payload_complexity: str = "low"  # "low", "medium", "high"
    obfuscation_level: int = 0  # 0-5

    # Human readable
    description: str = ""
    payload_class_string: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for scanner/report"""
        return {
            "payload": self.payload,
            "trigger_element": self.trigger_element,
            "trigger_attribute": self.trigger_attribute,
            "trigger_vector": self.trigger_vector,
            "execution": self.execution.value,
            "is_deterministic": self.is_deterministic,
            "requires_interaction": self.requires_interaction,
            "auto_executes": self.auto_executes,
            "injection_class": self.injection_class.value,
            "xss_type_hint": self.xss_type_hint.value,
            "confidence_boost": self.confidence_boost,
            "severity_minimum": self.severity_minimum,
            "contains_external_resource": self.contains_external_resource,
            "external_url": self.external_url,
            "payload_complexity": self.payload_complexity,
            "obfuscation_level": self.obfuscation_level,
            "description": self.description,
            "payload_class": self.payload_class_string,
        }


class PayloadAnalyzer:
    """
    Runtime analyzer for XSS payloads.

    Takes raw payload strings from KB and computes:
    - Trigger element/attribute (img.onerror, script.src)
    - Execution type (auto, user-triggered)
    - Is deterministic (will definitely execute)
    - XSS type hints
    - Confidence/severity modifiers

    This is RUNTIME analysis, not static KB knowledge.
    """

    # ============================================
    # EVENT HANDLER CLASSIFICATION
    # ============================================

    # Auto-execute handlers (no user interaction)
    AUTO_HANDLERS: Dict[str, ExecutionType] = {
        # Error-triggered (most reliable)
        "onerror": ExecutionType.ERROR_TRIGGERED,
        # Load-triggered
        "onload": ExecutionType.LOAD_TRIGGERED,
        "onloadeddata": ExecutionType.LOAD_TRIGGERED,
        "onloadedmetadata": ExecutionType.LOAD_TRIGGERED,
        "onloadstart": ExecutionType.LOAD_TRIGGERED,
        "oncanplay": ExecutionType.LOAD_TRIGGERED,
        "oncanplaythrough": ExecutionType.LOAD_TRIGGERED,
        "ondurationchange": ExecutionType.LOAD_TRIGGERED,
        "onprogress": ExecutionType.LOAD_TRIGGERED,
        # Ready state
        "onreadystatechange": ExecutionType.AUTO_IMMEDIATE,
        "onpageshow": ExecutionType.AUTO_IMMEDIATE,
        # Animation/transition (auto delayed)
        "onanimationstart": ExecutionType.AUTO_DELAYED,
        "onanimationend": ExecutionType.AUTO_DELAYED,
        "onanimationiteration": ExecutionType.AUTO_DELAYED,
        "ontransitionend": ExecutionType.AUTO_DELAYED,
        "ontransitionstart": ExecutionType.AUTO_DELAYED,
        "ontransitionrun": ExecutionType.AUTO_DELAYED,
        # Media events
        "onemptied": ExecutionType.LOAD_TRIGGERED,
        "onended": ExecutionType.LOAD_TRIGGERED,
        "onstalled": ExecutionType.LOAD_TRIGGERED,
        "onsuspend": ExecutionType.LOAD_TRIGGERED,
        "ontimeupdate": ExecutionType.LOAD_TRIGGERED,
    }

    # User interaction handlers
    USER_HANDLERS: Dict[str, ExecutionType] = {
        # Click events
        "onclick": ExecutionType.USER_CLICK,
        "ondblclick": ExecutionType.USER_CLICK,
        "oncontextmenu": ExecutionType.USER_CLICK,
        "onmousedown": ExecutionType.USER_CLICK,
        "onmouseup": ExecutionType.USER_CLICK,
        # Hover events
        "onmouseover": ExecutionType.USER_HOVER,
        "onmouseout": ExecutionType.USER_HOVER,
        "onmouseenter": ExecutionType.USER_HOVER,
        "onmouseleave": ExecutionType.USER_HOVER,
        "onmousemove": ExecutionType.USER_HOVER,
        # Focus events
        "onfocus": ExecutionType.USER_FOCUS,
        "onblur": ExecutionType.USER_FOCUS,
        "onfocusin": ExecutionType.USER_FOCUS,
        "onfocusout": ExecutionType.USER_FOCUS,
        # Input events
        "onchange": ExecutionType.USER_INPUT,
        "oninput": ExecutionType.USER_INPUT,
        "onselect": ExecutionType.USER_INPUT,
        "onkeydown": ExecutionType.USER_INPUT,
        "onkeyup": ExecutionType.USER_INPUT,
        "onkeypress": ExecutionType.USER_INPUT,
        # Form events
        "onsubmit": ExecutionType.USER_CLICK,
        "onreset": ExecutionType.USER_CLICK,
        # Scroll
        "onscroll": ExecutionType.USER_SCROLL,
        "onwheel": ExecutionType.USER_SCROLL,
        # Drag
        "ondrag": ExecutionType.USER_CLICK,
        "ondragend": ExecutionType.USER_CLICK,
        "ondragenter": ExecutionType.USER_CLICK,
        "ondragleave": ExecutionType.USER_CLICK,
        "ondragover": ExecutionType.USER_CLICK,
        "ondragstart": ExecutionType.USER_CLICK,
        "ondrop": ExecutionType.USER_CLICK,
        # Touch
        "ontouchstart": ExecutionType.USER_CLICK,
        "ontouchend": ExecutionType.USER_CLICK,
        "ontouchmove": ExecutionType.USER_CLICK,
    }

    ALL_HANDLERS: Set[str] = set(AUTO_HANDLERS.keys()) | set(USER_HANDLERS.keys())

    # ============================================
    # REGEX PATTERNS
    # ============================================

    PATTERNS = {
        # Script tags
        "script_tag": re.compile(r"<\s*script[^>]*>(.*?)</\s*script\s*>", re.I | re.S),
        "script_src": re.compile(r'<\s*script[^>]+src\s*=\s*["\']?([^"\'>\s]+)', re.I),
        "script_open": re.compile(r"<\s*script[^>]*>", re.I),
        # Event handlers
        "event_handler": re.compile(r'\bon(\w+)\s*=\s*["\']?([^"\'>\s]*)', re.I),
        # Elements with handlers
        "tag_with_handler": re.compile(r"<\s*(\w+)[^>]*\bon\w+\s*=", re.I),
        # JavaScript URI
        "javascript_uri": re.compile(r'javascript\s*:\s*([^"\'>\s]*)', re.I),
        # Data URI
        "data_uri": re.compile(r'data\s*:\s*text/html[^"\'>\s]*', re.I),
        # SVG
        "svg_tag": re.compile(r"<\s*svg[^>]*>", re.I),
        # Eval family
        "eval_call": re.compile(r"\b(eval|setTimeout|setInterval|Function)\s*\(", re.I),
        # DOM sinks
        "innerHTML": re.compile(r"\.(innerHTML|outerHTML)\s*=", re.I),
        "document_write": re.compile(r"document\.(write|writeln)\s*\(", re.I),
        # External URL
        "external_url": re.compile(
            r'(?:src|href)\s*=\s*["\']?(https?://[^"\'>\s]+)', re.I
        ),
        # Obfuscation patterns
        "encoding": re.compile(
            r"(fromCharCode|charCodeAt|atob|btoa|unescape|decodeURI|encodeURI)", re.I
        ),
        "unicode_escape": re.compile(r"\\u[0-9a-f]{4}", re.I),
        "hex_escape": re.compile(r"\\x[0-9a-f]{2}", re.I),
        "html_entity": re.compile(r"&#x?[0-9a-f]+;", re.I),
    }

    def __init__(self):
        logger.info("Payload Analyzer initialized")

    def analyze(
        self, payload: str, kb_hints: Optional[Dict[str, Any]] = None
    ) -> AnalyzedPayload:
        """
        Analyze a payload and compute runtime metadata.

        Args:
            payload: Raw XSS payload string
            kb_hints: Optional hints from KB (contexts, tags, severity)

        Returns:
            AnalyzedPayload with computed metadata
        """
        kb_hints = kb_hints or {}
        result = AnalyzedPayload(payload=payload)

        # 1. Detect trigger element and attribute
        self._detect_trigger(payload, result)

        # 2. Determine execution type
        self._determine_execution(result)

        # 3. Classify injection type
        self._classify_injection(payload, result)

        # 4. Compute XSS type hint
        self._compute_xss_hint(payload, result, kb_hints)

        # 5. Calculate confidence boost
        self._calculate_confidence_boost(result)

        # 6. Determine minimum severity
        self._determine_severity_minimum(result)

        # 7. Check for external resources
        self._check_external_resources(payload, result)

        # 8. Analyze complexity and obfuscation
        self._analyze_complexity(payload, result)

        # 9. Generate description and payload class string
        self._generate_description(result)

        logger.debug(
            f"Analyzed payload: {result.trigger_vector} | "
            f"exec={result.execution.value} | "
            f"deterministic={result.is_deterministic} | "
            f"boost={result.confidence_boost:+.2f}"
        )

        return result

    def _detect_trigger(self, payload: str, result: AnalyzedPayload):
        """Detect trigger element and attribute from payload"""

        # Check for event handlers
        handler_match = self.PATTERNS["event_handler"].search(payload)
        if handler_match:
            handler_name = "on" + handler_match.group(1).lower()
            result.trigger_attribute = handler_name

            # Find the element
            tag_match = self.PATTERNS["tag_with_handler"].search(payload)
            if tag_match:
                result.trigger_element = tag_match.group(1).lower()
            else:
                # Try to infer from common patterns
                payload_lower = payload.lower()
                if "<img" in payload_lower:
                    result.trigger_element = "img"
                elif "<svg" in payload_lower:
                    result.trigger_element = "svg"
                elif "<body" in payload_lower:
                    result.trigger_element = "body"
                elif "<div" in payload_lower:
                    result.trigger_element = "div"
                elif "<input" in payload_lower:
                    result.trigger_element = "input"
                elif "<a " in payload_lower or "<a>" in payload_lower:
                    result.trigger_element = "a"
                elif "<iframe" in payload_lower:
                    result.trigger_element = "iframe"
                elif "<video" in payload_lower:
                    result.trigger_element = "video"
                elif "<audio" in payload_lower:
                    result.trigger_element = "audio"

            # Build vector
            if result.trigger_element:
                result.trigger_vector = f"{result.trigger_element}.{handler_name}"
            else:
                result.trigger_vector = handler_name
            return

        # Check for script tags
        if self.PATTERNS["script_src"].search(payload):
            result.trigger_element = "script"
            result.trigger_attribute = "src"
            result.trigger_vector = "script.src"
            return

        if self.PATTERNS["script_open"].search(payload):
            result.trigger_element = "script"
            result.trigger_attribute = None
            result.trigger_vector = "script"
            return

        # Check for javascript: URI
        js_uri_match = self.PATTERNS["javascript_uri"].search(payload)
        if js_uri_match:
            # Find element using it
            payload_lower = payload.lower()
            if "<a " in payload_lower:
                result.trigger_element = "a"
                result.trigger_attribute = "href"
                result.trigger_vector = "a.href.javascript"
            elif "<iframe" in payload_lower:
                result.trigger_element = "iframe"
                result.trigger_attribute = "src"
                result.trigger_vector = "iframe.src.javascript"
            else:
                result.trigger_vector = "javascript_uri"
            return

        # Check for SVG
        if self.PATTERNS["svg_tag"].search(payload):
            result.trigger_element = "svg"
            result.trigger_vector = "svg"

    def _determine_execution(self, result: AnalyzedPayload):
        """Determine execution type based on trigger"""

        attr = result.trigger_attribute
        elem = result.trigger_element

        # Script tags - immediate execution
        if elem == "script":
            if result.trigger_attribute == "src":
                result.execution = ExecutionType.EXTERNAL_LOAD
                result.is_deterministic = True
                result.auto_executes = True
            else:
                result.execution = ExecutionType.AUTO_IMMEDIATE
                result.is_deterministic = True
                result.auto_executes = True
            return

        # Event handlers
        if attr:
            if attr in self.AUTO_HANDLERS:
                result.execution = self.AUTO_HANDLERS[attr]
                result.is_deterministic = True
                result.auto_executes = True
                result.requires_interaction = False
            elif attr in self.USER_HANDLERS:
                result.execution = self.USER_HANDLERS[attr]
                result.is_deterministic = False
                result.auto_executes = False
                result.requires_interaction = True
            else:
                # Unknown handler - assume user interaction
                result.execution = ExecutionType.USER_CLICK
                result.requires_interaction = True
            return

        # JavaScript URI - usually requires click
        if "javascript" in result.trigger_vector:
            result.execution = ExecutionType.USER_CLICK
            result.requires_interaction = True
            return

        # Default
        result.execution = ExecutionType.NONE

    def _classify_injection(self, payload: str, result: AnalyzedPayload):
        """Classify injection type"""

        # External script
        if self.PATTERNS["script_src"].search(payload):
            result.injection_class = InjectionClass.SCRIPT_EXTERNAL
            return

        # Inline script
        if self.PATTERNS["script_tag"].search(payload) or self.PATTERNS[
            "script_open"
        ].search(payload):
            result.injection_class = InjectionClass.SCRIPT_INLINE
            return

        # SVG injection
        if self.PATTERNS["svg_tag"].search(payload):
            result.injection_class = InjectionClass.SVG_INJECTION
            return

        # Event handler (with tag)
        if self.PATTERNS["tag_with_handler"].search(payload):
            result.injection_class = InjectionClass.HTML_ATTRIBUTE
            return

        # Event handler (standalone)
        if self.PATTERNS["event_handler"].search(payload):
            result.injection_class = InjectionClass.EVENT_HANDLER
            return

        # JavaScript URI
        if self.PATTERNS["javascript_uri"].search(payload):
            result.injection_class = InjectionClass.JAVASCRIPT_URI
            return

        # Data URI
        if self.PATTERNS["data_uri"].search(payload):
            result.injection_class = InjectionClass.DATA_URI
            return

        # Eval-based
        if self.PATTERNS["eval_call"].search(payload):
            result.injection_class = InjectionClass.EVAL_BASED
            return

        # DOM sinks
        if self.PATTERNS["innerHTML"].search(payload) or self.PATTERNS[
            "document_write"
        ].search(payload):
            result.injection_class = InjectionClass.DOM_SINK
            return

        result.injection_class = InjectionClass.UNKNOWN

    def _compute_xss_hint(
        self, payload: str, result: AnalyzedPayload, kb_hints: Dict[str, Any]
    ):
        """Compute XSS type hint"""

        # Inline/external script with deterministic execution
        if result.injection_class in {
            InjectionClass.SCRIPT_INLINE,
            InjectionClass.SCRIPT_EXTERNAL,
        }:
            result.xss_type_hint = XSSTypeHint.DOM_SCRIPT
            return

        # Event handler with auto-execute
        if result.trigger_attribute and result.is_deterministic:
            result.xss_type_hint = XSSTypeHint.DOM_EVENT_HANDLER
            return

        # DOM sinks
        if result.injection_class == InjectionClass.DOM_SINK:
            result.xss_type_hint = XSSTypeHint.DOM_INNERHTML
            return

        # User interaction required
        if result.requires_interaction:
            result.xss_type_hint = XSSTypeHint.REQUIRES_INTERACTION
            return

        # KB hints
        kb_contexts = kb_hints.get("contexts", [])
        if "dom" in str(kb_contexts).lower():
            result.xss_type_hint = XSSTypeHint.LIKELY_DOM
            return

        result.xss_type_hint = XSSTypeHint.UNKNOWN

    def _calculate_confidence_boost(self, result: AnalyzedPayload):
        """Calculate confidence boost based on characteristics"""

        boost = 0.0

        # Deterministic triggers get high boost
        if result.is_deterministic:
            boost += 0.15

        # Auto-execute handlers
        if result.execution in {
            ExecutionType.ERROR_TRIGGERED,
            ExecutionType.LOAD_TRIGGERED,
            ExecutionType.AUTO_IMMEDIATE,
        }:
            boost += 0.10

        # External script = definitive
        if result.injection_class == InjectionClass.SCRIPT_EXTERNAL:
            boost += 0.10

        # Inline script
        if result.injection_class == InjectionClass.SCRIPT_INLINE:
            boost += 0.05

        # User interaction required = lower confidence
        if result.requires_interaction:
            boost -= 0.10

        # Clamp
        result.confidence_boost = max(-0.2, min(0.3, boost))

    def _determine_severity_minimum(self, result: AnalyzedPayload):
        """Determine minimum severity"""

        # External script load = CRITICAL
        if result.injection_class == InjectionClass.SCRIPT_EXTERNAL:
            result.severity_minimum = "critical"
            return

        # Inline script = HIGH
        if result.injection_class == InjectionClass.SCRIPT_INLINE:
            result.severity_minimum = "high"
            return

        # Deterministic auto-execute = HIGH
        if result.is_deterministic and result.auto_executes:
            result.severity_minimum = "high"
            return

        # onerror specifically = HIGH (very reliable)
        if result.trigger_attribute == "onerror":
            result.severity_minimum = "high"
            return

        # User interaction required = can be MEDIUM
        if result.requires_interaction:
            result.severity_minimum = "medium"
            return

        result.severity_minimum = "medium"

    def _check_external_resources(self, payload: str, result: AnalyzedPayload):
        """Check for external resource loading"""

        url_match = self.PATTERNS["external_url"].search(payload)
        if url_match:
            result.contains_external_resource = True
            result.external_url = url_match.group(1)

        # Script src
        src_match = self.PATTERNS["script_src"].search(payload)
        if src_match:
            result.contains_external_resource = True
            result.external_url = src_match.group(1)

    def _analyze_complexity(self, payload: str, result: AnalyzedPayload):
        """Analyze payload complexity and obfuscation"""

        obfuscation = 0

        # Check for encoding functions
        if self.PATTERNS["encoding"].search(payload):
            obfuscation += 2

        # Unicode escapes
        unicode_count = len(self.PATTERNS["unicode_escape"].findall(payload))
        if unicode_count > 0:
            obfuscation += min(unicode_count, 2)

        # Hex escapes
        hex_count = len(self.PATTERNS["hex_escape"].findall(payload))
        if hex_count > 0:
            obfuscation += min(hex_count, 2)

        # HTML entities
        entity_count = len(self.PATTERNS["html_entity"].findall(payload))
        if entity_count > 0:
            obfuscation += 1

        result.obfuscation_level = min(obfuscation, 5)

        # Complexity based on length and structure
        if len(payload) > 200 or obfuscation >= 3:
            result.payload_complexity = "high"
        elif len(payload) > 80 or obfuscation >= 1:
            result.payload_complexity = "medium"
        else:
            result.payload_complexity = "low"

    def _generate_description(self, result: AnalyzedPayload):
        """Generate human-readable description"""

        # Payload class string
        parts = [result.injection_class.value.replace("_", " ").title()]

        if result.trigger_element and result.trigger_attribute:
            parts.append(f"via {result.trigger_element}.{result.trigger_attribute}")
        elif result.trigger_vector:
            parts.append(f"via {result.trigger_vector}")

        if result.is_deterministic:
            parts.append("(Auto-Execute)")
        elif result.requires_interaction:
            parts.append("(Requires User Action)")

        result.payload_class_string = " | ".join(parts)

        # Description
        descriptions = {
            InjectionClass.SCRIPT_EXTERNAL: "Loads attacker-controlled external JavaScript",
            InjectionClass.SCRIPT_INLINE: "Injects inline JavaScript for immediate execution",
            InjectionClass.HTML_ATTRIBUTE: "Injects via HTML element event handler attribute",
            InjectionClass.EVENT_HANDLER: "Injects JavaScript through event handler",
            InjectionClass.SVG_INJECTION: "Exploits SVG elements for script execution",
            InjectionClass.JAVASCRIPT_URI: "Uses javascript: URI scheme for code execution",
            InjectionClass.DATA_URI: "Uses data: URI to embed executable content",
            InjectionClass.EVAL_BASED: "Uses eval() or similar for dynamic code execution",
            InjectionClass.DOM_SINK: "Manipulates DOM to inject executable content",
        }

        base_desc = descriptions.get(result.injection_class, "XSS injection vector")

        if result.trigger_element:
            base_desc += f" using <{result.trigger_element}> element"

        if result.execution == ExecutionType.ERROR_TRIGGERED:
            base_desc += " (triggers on error)"
        elif result.execution == ExecutionType.LOAD_TRIGGERED:
            base_desc += " (triggers on load)"
        elif result.is_deterministic:
            base_desc += " (auto-executes)"
        elif result.requires_interaction:
            base_desc += " (requires user interaction)"

        result.description = base_desc


# Singleton instance
_analyzer: Optional[PayloadAnalyzer] = None


def get_payload_analyzer() -> PayloadAnalyzer:
    """Get singleton analyzer instance"""
    global _analyzer
    if _analyzer is None:
        _analyzer = PayloadAnalyzer()
    return _analyzer


def analyze_payload(
    payload: str, kb_hints: Optional[Dict[str, Any]] = None
) -> AnalyzedPayload:
    """Convenience function to analyze a payload"""
    return get_payload_analyzer().analyze(payload, kb_hints)
