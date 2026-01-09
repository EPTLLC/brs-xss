#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Created - XSS Type Classification
Telegram: https://t.me/EasyProTech

XSS Type Classifier - determines vulnerability type based on:
- Payload characteristics (event handlers, script tags, etc.)
- Source of injection (URL param, DOM API, storage)
- DOM confirmation from headless detector
"""

from enum import Enum
from typing import Optional, Dict, Any, Set
from dataclasses import dataclass
import re

from ..utils.logger import Logger

logger = Logger("core.xss_type_classifier")


class XSSType(Enum):
    """XSS vulnerability types"""

    REFLECTED = "Reflected XSS"
    DOM_BASED = "DOM-based XSS"
    STORED = "Stored XSS"
    MUTATION = "Mutation XSS"
    BLIND = "Blind XSS"
    SELF = "Self XSS"

    # Subtypes for detailed classification
    DOM_EVENT_HANDLER = "DOM XSS (Event Handler)"
    DOM_INNERHTML = "DOM XSS (innerHTML)"
    DOM_DOCUMENT_WRITE = "DOM XSS (document.write)"
    DOM_EVAL = "DOM XSS (eval)"
    DOM_LOCATION = "DOM XSS (location)"


class InjectionSource(Enum):
    """Source of user input for XSS"""

    URL_PARAMETER = "url_parameter"
    URL_FRAGMENT = "url_fragment"
    URL_PATH = "url_path"
    FORM_INPUT = "form_input"
    DOM_API = "dom_api"
    STORAGE = "storage"
    POSTMESSAGE = "postmessage"
    WEBSOCKET = "websocket"
    COOKIE = "cookie"
    HEADER = "header"
    UNKNOWN = "unknown"


class TriggerType(Enum):
    """How the XSS payload executes"""

    EVENT_HANDLER = "event_handler"  # onerror, onload, onclick
    SCRIPT_TAG = "script_tag"  # <script>
    SCRIPT_SRC = "script_src"  # <script src=>
    JAVASCRIPT_URI = "javascript_uri"  # href="javascript:"
    DATA_URI = "data_uri"  # src="data:text/html"
    CSS_EXPRESSION = "css_expression"  # style="x:expression()"
    SVG_SCRIPT = "svg_script"  # <svg onload=>
    TEMPLATE = "template"  # {{payload}}
    EVAL_FAMILY = "eval_family"  # eval(), setTimeout(), etc.
    DOM_SINK = "dom_sink"  # innerHTML, outerHTML
    AUTO_EXECUTE = "auto_execute"  # No user interaction
    USER_INTERACTION = "user_interaction"  # Requires click/hover
    UNKNOWN = "unknown"


@dataclass
class PayloadAnalysis:
    """Result of payload analysis"""

    has_event_handler: bool = False
    event_handler_name: Optional[str] = None
    has_script_tag: bool = False
    has_external_script: bool = False
    has_javascript_uri: bool = False
    has_dom_sink: bool = False
    dom_sink_name: Optional[str] = None
    has_eval_family: bool = False
    requires_user_interaction: bool = False
    trigger_type: TriggerType = TriggerType.UNKNOWN
    is_deterministic: bool = False  # Will always execute without user action


@dataclass
class ClassificationResult:
    """XSS classification result"""

    xss_type: XSSType
    trigger_type: TriggerType
    source: InjectionSource
    payload_class: str
    trigger_description: str
    confidence_modifier: float  # Affects confidence calculation
    severity_minimum: str  # Minimum severity for this type
    details: Dict[str, Any]


class XSSTypeClassifier:
    """
    Classifies XSS vulnerabilities by analyzing payload and context.

    Replaces hardcoded 'Reflected XSS' with dynamic classification.
    """

    # Event handlers that execute without user interaction (deterministic)
    AUTO_EVENT_HANDLERS: Set[str] = {
        "onerror",
        "onload",
        "onreadystatechange",
        "onpageshow",
        "onbeforeunload",
        "onunload",
        "onautocomplete",
        "onautocompleteerror",
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
        "ontransitionstart",
        "ontransitionrun",
    }

    # Event handlers requiring user interaction
    USER_EVENT_HANDLERS: Set[str] = {
        "onclick",
        "ondblclick",
        "onmousedown",
        "onmouseup",
        "onmouseover",
        "onmouseout",
        "onmousemove",
        "onmouseenter",
        "onmouseleave",
        "onkeydown",
        "onkeyup",
        "onkeypress",
        "onfocus",
        "onblur",
        "onchange",
        "onsubmit",
        "onreset",
        "onselect",
        "oninput",
        "oncontextmenu",
        "ondrag",
        "ondragend",
        "ondragenter",
        "ondragleave",
        "ondragover",
        "ondragstart",
        "ondrop",
        "onscroll",
        "onwheel",
        "ontouchstart",
        "ontouchend",
        "ontouchmove",
        "ontouchcancel",
        "onpointerdown",
        "onpointerup",
        "onpointermove",
        "onpointerenter",
        "onpointerleave",
        "onpointerover",
        "onpointerout",
        "onpointercancel",
    }

    # All event handlers combined
    ALL_EVENT_HANDLERS: Set[str] = AUTO_EVENT_HANDLERS | USER_EVENT_HANDLERS

    # DOM sinks that can lead to XSS
    DOM_SINKS: Set[str] = {
        "innerhtml",
        "outerhtml",
        "insertadjacenthtml",
        "write",
        "writeln",
        "createcontextualfragment",
        "srcdoc",
    }

    # Eval-family functions
    EVAL_FUNCTIONS: Set[str] = {
        "eval",
        "settimeout",
        "setinterval",
        "function",
        "execscript",
    }

    # DOM sources (indicate DOM-based XSS)
    DOM_SOURCES: Set[str] = {
        "location.hash",
        "location.href",
        "location.search",
        "location.pathname",
        "document.url",
        "document.documenturi",
        "document.referrer",
        "document.cookie",
        "window.name",
        "localstorage",
        "sessionstorage",
        "postmessage",
        "message.data",
    }

    # Regex patterns
    EVENT_HANDLER_PATTERN = re.compile(
        r"\bon(" + "|".join(h[2:] for h in ALL_EVENT_HANDLERS) + r")\s*=", re.IGNORECASE
    )

    SCRIPT_TAG_PATTERN = re.compile(r"<\s*script[^>]*>", re.IGNORECASE)
    SCRIPT_SRC_PATTERN = re.compile(r"<\s*script[^>]+src\s*=", re.IGNORECASE)
    JAVASCRIPT_URI_PATTERN = re.compile(r"javascript\s*:", re.IGNORECASE)
    DATA_URI_PATTERN = re.compile(r"data\s*:\s*text/html", re.IGNORECASE)
    SVG_PATTERN = re.compile(r"<\s*svg[^>]*on\w+\s*=", re.IGNORECASE)

    def __init__(self):
        logger.info("XSS Type Classifier initialized")

    def classify(
        self,
        payload: str,
        parameter: Optional[str] = None,
        source: Optional[InjectionSource] = None,
        dom_confirmed: bool = False,
        reflection_context: Optional[str] = None,
        additional_info: Optional[Dict[str, Any]] = None,
    ) -> ClassificationResult:
        """
        Classify XSS vulnerability type.

        Args:
            payload: The XSS payload that triggered
            parameter: URL/form parameter name (None if unknown)
            source: Detected injection source
            dom_confirmed: Whether headless browser confirmed execution
            reflection_context: Where payload was reflected
            additional_info: Additional context information

        Returns:
            ClassificationResult with type, trigger, and metadata
        """

        # 1. Analyze payload characteristics
        analysis = self._analyze_payload(payload)

        # 2. Determine source if not provided
        if source is None:
            source = self._infer_source(parameter, additional_info or {})

        # 3. Classify XSS type
        xss_type = self._determine_xss_type(analysis, source, dom_confirmed, parameter)

        # 4. Generate payload class description
        payload_class = self._generate_payload_class(analysis, reflection_context)

        # 5. Generate trigger description
        trigger_desc = self._generate_trigger_description(analysis)

        # 6. Calculate confidence modifier
        confidence_mod = self._calculate_confidence_modifier(analysis, dom_confirmed)

        # 7. Determine minimum severity
        severity_min = self._determine_minimum_severity(
            analysis, xss_type, dom_confirmed
        )

        result = ClassificationResult(
            xss_type=xss_type,
            trigger_type=analysis.trigger_type,
            source=source,
            payload_class=payload_class,
            trigger_description=trigger_desc,
            confidence_modifier=confidence_mod,
            severity_minimum=severity_min,
            details={
                "has_event_handler": analysis.has_event_handler,
                "event_handler": analysis.event_handler_name,
                "has_script_tag": analysis.has_script_tag,
                "has_external_script": analysis.has_external_script,
                "is_deterministic": analysis.is_deterministic,
                "requires_interaction": analysis.requires_user_interaction,
                "dom_confirmed": dom_confirmed,
            },
        )

        logger.info(
            f"Classified: {xss_type.value} | "
            f"Trigger: {analysis.trigger_type.value} | "
            f"Confidence mod: {confidence_mod:+.2f}"
        )

        return result

    def _analyze_payload(self, payload: str) -> PayloadAnalysis:
        """Analyze payload to determine characteristics"""

        payload_lower = payload.lower()
        analysis = PayloadAnalysis()

        # Check for event handlers
        event_match = self.EVENT_HANDLER_PATTERN.search(payload)
        if event_match:
            analysis.has_event_handler = True
            handler_name = "on" + event_match.group(1).lower()
            analysis.event_handler_name = handler_name

            if handler_name in self.AUTO_EVENT_HANDLERS:
                analysis.is_deterministic = True
                analysis.requires_user_interaction = False
                analysis.trigger_type = TriggerType.AUTO_EXECUTE
            else:
                analysis.is_deterministic = False
                analysis.requires_user_interaction = True
                analysis.trigger_type = TriggerType.USER_INTERACTION

        # Check for script tags
        if self.SCRIPT_TAG_PATTERN.search(payload):
            analysis.has_script_tag = True
            analysis.trigger_type = TriggerType.SCRIPT_TAG
            analysis.is_deterministic = True

            if self.SCRIPT_SRC_PATTERN.search(payload):
                analysis.has_external_script = True
                analysis.trigger_type = TriggerType.SCRIPT_SRC

        # Check for javascript: URI
        if self.JAVASCRIPT_URI_PATTERN.search(payload):
            analysis.has_javascript_uri = True
            analysis.trigger_type = TriggerType.JAVASCRIPT_URI
            # javascript: URIs often require user interaction (clicking link)
            analysis.requires_user_interaction = True

        # Check for DOM sinks in payload
        for sink in self.DOM_SINKS:
            if sink in payload_lower:
                analysis.has_dom_sink = True
                analysis.dom_sink_name = sink
                analysis.trigger_type = TriggerType.DOM_SINK
                break

        # Check for eval family
        for eval_func in self.EVAL_FUNCTIONS:
            if eval_func + "(" in payload_lower:
                analysis.has_eval_family = True
                analysis.trigger_type = TriggerType.EVAL_FAMILY
                break

        # Check for SVG with event handler
        if self.SVG_PATTERN.search(payload):
            analysis.has_event_handler = True
            analysis.trigger_type = TriggerType.EVENT_HANDLER

        # If no specific trigger found, default based on content
        if analysis.trigger_type == TriggerType.UNKNOWN:
            if analysis.has_event_handler:
                analysis.trigger_type = TriggerType.EVENT_HANDLER

        return analysis

    def _infer_source(
        self, parameter: Optional[str], info: Dict[str, Any]
    ) -> InjectionSource:
        """Infer injection source from available information"""

        if parameter:
            # Check if it's a URL fragment
            if parameter.startswith("#") or info.get("from_fragment"):
                return InjectionSource.URL_FRAGMENT

            # Check if from form
            if info.get("method", "").upper() == "POST":
                return InjectionSource.FORM_INPUT

            return InjectionSource.URL_PARAMETER

        # Check for DOM sources in info
        if info.get("dom_source"):
            source_str = str(info["dom_source"]).lower()
            for dom_src in self.DOM_SOURCES:
                if dom_src in source_str:
                    if "storage" in source_str:
                        return InjectionSource.STORAGE
                    if "postmessage" in source_str or "message" in source_str:
                        return InjectionSource.POSTMESSAGE
                    return InjectionSource.DOM_API

        return InjectionSource.UNKNOWN

    def _determine_xss_type(
        self,
        analysis: PayloadAnalysis,
        source: InjectionSource,
        dom_confirmed: bool,
        parameter: Optional[str],
    ) -> XSSType:
        """
        Determine the XSS type based on analysis and source.

        CRITICAL RULES:
        1. Reflected XSS REQUIRES known parameter (parameter != None/unknown)
        2. If parameter=unknown/None, it CANNOT be Reflected
        3. DOM confirmed + event handler = DOM XSS
        4. Fragment source (#hash) = always DOM XSS
        """

        # ========================================
        # RULE 1: Check for Reflected XSS
        # ========================================
        # Reflected XSS REQUIRES known parameter
        can_be_reflected = (
            parameter is not None
            and parameter != "unknown"
            and parameter != ""
            and source
            in {
                InjectionSource.URL_PARAMETER,
                InjectionSource.FORM_INPUT,
                InjectionSource.HEADER,
                InjectionSource.COOKIE,
            }
        )

        # ========================================
        # RULE 2: DOM-based indicators
        # ========================================
        is_dom_based = False
        dom_reason = None

        # 2a. Source-based: Fragment, DOM API, Storage, PostMessage = ALWAYS DOM
        if source in {
            InjectionSource.URL_FRAGMENT,
            InjectionSource.DOM_API,
            InjectionSource.STORAGE,
            InjectionSource.POSTMESSAGE,
        }:
            is_dom_based = True
            dom_reason = f"source={source.value}"

        # 2b. Parameter unknown = NOT Reflected, classify as DOM
        if parameter is None or parameter == "unknown" or parameter == "":
            # If parameter is unknown, it cannot be Reflected
            # Default to DOM-based classification
            is_dom_based = True
            dom_reason = "parameter_unknown"

        # 2c. DOM confirmed = DOM XSS (execution was confirmed in browser)
        # DOM confirmation is definitive - if browser executed it, it's DOM-based
        if dom_confirmed:
            is_dom_based = True
            if analysis.has_event_handler:
                dom_reason = "dom_confirmed_event_handler"
            elif analysis.has_script_tag:
                dom_reason = "dom_confirmed_script"
            else:
                dom_reason = "dom_confirmed"

        # 2d. DOM sinks (innerHTML, document.write) = DOM XSS
        if analysis.has_dom_sink:
            is_dom_based = True
            dom_reason = f"dom_sink={analysis.dom_sink_name}"

        # 2e. Payload contains DOM_XSS markers (from test payloads)
        # This is a heuristic for payloads like alert('DOM_XSS_FRAGMENT')
        # BUT: don't rely only on this, it's an auxiliary indicator

        # ========================================
        # RULE 3: Determine specific type
        # ========================================

        if is_dom_based:
            logger.debug(f"DOM-based XSS detected: reason={dom_reason}")

            # Subtype based on trigger mechanism
            if analysis.has_event_handler:
                return XSSType.DOM_EVENT_HANDLER
            if analysis.has_dom_sink:
                if analysis.dom_sink_name and "innerhtml" in analysis.dom_sink_name:
                    return XSSType.DOM_INNERHTML
                if analysis.dom_sink_name and "write" in analysis.dom_sink_name:
                    return XSSType.DOM_DOCUMENT_WRITE
            if analysis.has_eval_family:
                return XSSType.DOM_EVAL
            return XSSType.DOM_BASED

        # ========================================
        # RULE 4: Stored XSS check
        # ========================================
        if source == InjectionSource.STORAGE:
            return XSSType.STORED

        # ========================================
        # RULE 5: Reflected XSS (only if can_be_reflected)
        # ========================================
        if can_be_reflected:
            return XSSType.REFLECTED

        # ========================================
        # Fallback: if nothing matched, DOM-based
        # (conservative approach - better DOM than incorrect Reflected)
        # ========================================
        logger.warning(
            f"Fallback to DOM-based: parameter={parameter}, source={source.value}"
        )
        return XSSType.DOM_BASED

    def _generate_payload_class(
        self, analysis: PayloadAnalysis, context: Optional[str]
    ) -> str:
        """Generate human-readable payload class"""

        parts = []

        # Base class
        if analysis.has_script_tag:
            if analysis.has_external_script:
                parts.append("External Script Injection")
            else:
                parts.append("Inline Script Injection")
        elif analysis.has_event_handler:
            parts.append("HTML Attribute Injection")
        elif analysis.has_javascript_uri:
            parts.append("JavaScript URI Injection")
        elif analysis.has_dom_sink:
            parts.append("DOM Sink Injection")
        elif analysis.has_eval_family:
            parts.append("Eval-based Injection")
        else:
            parts.append("XSS Injection")

        return " | ".join(parts)

    def _generate_trigger_description(self, analysis: PayloadAnalysis) -> str:
        """Generate trigger description for report"""

        parts = []

        if analysis.event_handler_name:
            # Format: img.onerror, svg.onload, etc.
            parts.append(f"Trigger: {analysis.event_handler_name}")

        if analysis.has_script_tag:
            if analysis.has_external_script:
                parts.append("External script load")
            else:
                parts.append("Inline script execution")

        if analysis.is_deterministic:
            parts.append("Auto-execute")
        elif analysis.requires_user_interaction:
            parts.append("Requires interaction")

        return " | ".join(parts) if parts else "Unknown trigger"

    def _calculate_confidence_modifier(
        self, analysis: PayloadAnalysis, dom_confirmed: bool
    ) -> float:
        """
        Calculate confidence modifier based on payload characteristics.

        Returns value between -0.2 and +0.2 to adjust base confidence.
        """

        modifier = 0.0

        # Deterministic triggers = higher confidence
        if analysis.is_deterministic:
            modifier += 0.15

        # DOM confirmed = boost
        if dom_confirmed:
            modifier += 0.10

        # Auto-executing event handlers
        if analysis.event_handler_name in self.AUTO_EVENT_HANDLERS:
            modifier += 0.05

        # External script = definitive
        if analysis.has_external_script:
            modifier += 0.10

        # User interaction required = lower confidence
        if analysis.requires_user_interaction:
            modifier -= 0.10

        # Cap modifier
        return max(-0.2, min(0.2, modifier))

    def _determine_minimum_severity(
        self, analysis: PayloadAnalysis, xss_type: XSSType, dom_confirmed: bool
    ) -> str:
        """Determine minimum severity for this vulnerability"""

        # External script load = always HIGH
        if analysis.has_external_script:
            return "high"

        # DOM confirmed with auto-execute = HIGH
        if dom_confirmed and analysis.is_deterministic:
            return "high"

        # Inline script = HIGH
        if analysis.has_script_tag:
            return "high"

        # Auto-executing event handler = HIGH
        if analysis.event_handler_name in self.AUTO_EVENT_HANDLERS:
            return "high"

        # Stored XSS = HIGH
        if xss_type == XSSType.STORED:
            return "high"

        # User interaction required = can be MEDIUM
        if analysis.requires_user_interaction:
            return "medium"

        return "medium"


# Singleton instance
_classifier: Optional[XSSTypeClassifier] = None


def get_xss_classifier() -> XSSTypeClassifier:
    """Get singleton classifier instance"""
    global _classifier
    if _classifier is None:
        _classifier = XSSTypeClassifier()
    return _classifier
