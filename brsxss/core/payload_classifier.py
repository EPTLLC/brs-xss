#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Created - PAYLOAD CLASS generation
Telegram: https://t.me/EasyProTech

Payload Classifier - generates consistent PAYLOAD CLASS information:
- Injection type (HTML Attribute, Script, URI, etc.)
- Trigger mechanism (onerror, onload, etc.)
- Vector description
- Execution requirements
"""

from typing import Optional, Any
from dataclasses import dataclass
from enum import Enum
import re

from ..utils.logger import Logger

logger = Logger("core.payload_classifier")


class InjectionType(Enum):
    """Primary injection classification"""

    SCRIPT_INLINE = "Inline Script Injection"
    SCRIPT_EXTERNAL = "External Script Injection"
    HTML_ATTRIBUTE = "HTML Attribute Injection"
    EVENT_HANDLER = "Event Handler Injection"
    JAVASCRIPT_URI = "JavaScript URI Injection"
    DATA_URI = "Data URI Injection"
    SVG_INJECTION = "SVG-based XSS"
    CSS_INJECTION = "CSS Expression Injection"
    TEMPLATE_INJECTION = "Template Injection"
    DOM_MANIPULATION = "DOM Manipulation"
    EVAL_BASED = "Eval-based Injection"
    PROTOTYPE_POLLUTION = "Prototype Pollution XSS"
    MUTATION_XSS = "Mutation XSS (mXSS)"
    UNKNOWN = "XSS Injection"


class TriggerMechanism(Enum):
    """How the payload triggers execution"""

    AUTO_IMMEDIATE = "auto_immediate"  # Executes immediately
    AUTO_DELAYED = "auto_delayed"  # Executes after delay/event
    USER_CLICK = "user_click"  # Requires click
    USER_HOVER = "user_hover"  # Requires mouse hover
    USER_FOCUS = "user_focus"  # Requires focus
    USER_INPUT = "user_input"  # Requires input
    USER_SCROLL = "user_scroll"  # Requires scroll
    EXTERNAL_LOAD = "external_load"  # Loads external resource
    ERROR_TRIGGERED = "error_triggered"  # Triggers on error
    LOAD_TRIGGERED = "load_triggered"  # Triggers on load
    NONE = "none"


@dataclass
class PayloadClassification:
    """Complete payload classification result"""

    injection_type: InjectionType
    trigger: TriggerMechanism
    trigger_element: Optional[str]  # e.g., "img", "svg", "script"
    trigger_attribute: Optional[str]  # e.g., "onerror", "onload"
    vector: str  # e.g., "img.onerror", "script.src"
    execution_requirements: list[str]  # What's needed to execute
    complexity: str  # "low", "medium", "high"
    description: str  # Human-readable description
    is_deterministic: bool  # Will definitely execute
    requires_interaction: bool  # Needs user action

    def to_payload_class_string(self) -> str:
        """Generate PAYLOAD CLASS string for reports"""
        parts = [self.injection_type.value]

        if self.trigger_element and self.trigger_attribute:
            parts.append(f"Trigger: {self.trigger_element}.{self.trigger_attribute}")
        elif self.trigger_attribute:
            parts.append(f"Trigger: {self.trigger_attribute}")
        elif self.vector:
            parts.append(f"Vector: {self.vector}")

        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for reports"""
        return {
            "injection_type": self.injection_type.value,
            "trigger_mechanism": self.trigger.value,
            "trigger_element": self.trigger_element,
            "trigger_attribute": self.trigger_attribute,
            "vector": self.vector,
            "execution_requirements": self.execution_requirements,
            "complexity": self.complexity,
            "description": self.description,
            "is_deterministic": self.is_deterministic,
            "requires_interaction": self.requires_interaction,
            "payload_class": self.to_payload_class_string(),
        }


class PayloadClassifier:
    """
    Classifies XSS payloads for consistent PAYLOAD CLASS generation.

    Ensures all scan findings have proper:
    - PAYLOAD CLASS
    - Trigger information
    - Vector description
    """

    # Event handlers grouped by trigger type
    AUTO_EXECUTE_HANDLERS = {
        "error": ["onerror"],
        "load": ["onload", "onloadeddata", "onloadedmetadata", "onloadstart"],
        "ready": ["onreadystatechange", "onpageshow"],
        "animation": ["onanimationstart", "onanimationend", "onanimationiteration"],
        "transition": ["ontransitionend", "ontransitionstart", "ontransitionrun"],
        "media": [
            "oncanplay",
            "oncanplaythrough",
            "ondurationchange",
            "onemptied",
            "onended",
            "onprogress",
            "onstalled",
            "onsuspend",
            "ontimeupdate",
        ],
        "misc": ["onbeforeunload", "onautocomplete", "onautocompleteerror"],
    }

    USER_INTERACTION_HANDLERS = {
        "click": ["onclick", "ondblclick", "oncontextmenu"],
        "mouse": [
            "onmousedown",
            "onmouseup",
            "onmouseover",
            "onmouseout",
            "onmousemove",
            "onmouseenter",
            "onmouseleave",
        ],
        "keyboard": ["onkeydown", "onkeyup", "onkeypress"],
        "focus": ["onfocus", "onblur", "onfocusin", "onfocusout"],
        "input": ["onchange", "oninput", "onselect"],
        "form": ["onsubmit", "onreset"],
        "scroll": ["onscroll", "onwheel"],
        "drag": [
            "ondrag",
            "ondragend",
            "ondragenter",
            "ondragleave",
            "ondragover",
            "ondragstart",
            "ondrop",
        ],
        "touch": ["ontouchstart", "ontouchend", "ontouchmove", "ontouchcancel"],
        "pointer": [
            "onpointerdown",
            "onpointerup",
            "onpointermove",
            "onpointerenter",
            "onpointerleave",
        ],
    }

    # Elements commonly used in XSS
    XSS_ELEMENTS = {
        "script": {"type": "script", "dangerous": True},
        "img": {"type": "media", "dangerous": True},
        "svg": {"type": "svg", "dangerous": True},
        "iframe": {"type": "frame", "dangerous": True},
        "body": {"type": "structural", "dangerous": True},
        "input": {"type": "form", "dangerous": False},
        "a": {"type": "link", "dangerous": True},
        "object": {"type": "plugin", "dangerous": True},
        "embed": {"type": "plugin", "dangerous": True},
        "video": {"type": "media", "dangerous": True},
        "audio": {"type": "media", "dangerous": True},
        "source": {"type": "media", "dangerous": True},
        "link": {"type": "resource", "dangerous": True},
        "style": {"type": "style", "dangerous": True},
        "base": {"type": "structural", "dangerous": True},
        "form": {"type": "form", "dangerous": True},
        "button": {"type": "form", "dangerous": False},
        "details": {"type": "interactive", "dangerous": True},
        "marquee": {"type": "deprecated", "dangerous": True},
        "math": {"type": "mathml", "dangerous": True},
    }

    # Regex patterns
    PATTERNS = {
        "script_tag": re.compile(
            r"<\s*script[^>]*>(.*?)<\s*/\s*script\s*>", re.I | re.S
        ),
        "script_src": re.compile(r'<\s*script[^>]+src\s*=\s*["\']?([^"\'>\s]+)', re.I),
        "event_handler": re.compile(r'on(\w+)\s*=\s*["\']?([^"\'>\s]+)', re.I),
        "javascript_uri": re.compile(r"javascript\s*:", re.I),
        "data_uri": re.compile(r"data\s*:\s*([^;,]+)", re.I),
        "tag_extract": re.compile(r"<\s*(\w+)[^>]*>", re.I),
        "svg_tag": re.compile(r"<\s*svg[^>]*>", re.I),
        "img_tag": re.compile(r"<\s*img[^>]*>", re.I),
        "eval_call": re.compile(r"\b(eval|setTimeout|setInterval|Function)\s*\(", re.I),
        "innerhtml": re.compile(
            r"\.(innerHTML|outerHTML|insertAdjacentHTML)\s*=", re.I
        ),
        "document_write": re.compile(r"document\.(write|writeln)\s*\(", re.I),
    }

    def __init__(self):
        # Flatten handler lists for quick lookup
        self.all_auto_handlers = set()
        for handlers in self.AUTO_EXECUTE_HANDLERS.values():
            self.all_auto_handlers.update(handlers)

        self.all_user_handlers = set()
        for handlers in self.USER_INTERACTION_HANDLERS.values():
            self.all_user_handlers.update(handlers)

        logger.info("Payload Classifier initialized")

    def classify(self, payload: str) -> PayloadClassification:
        """
        Classify a payload and generate PAYLOAD CLASS information.

        Args:
            payload: XSS payload string

        Returns:
            PayloadClassification with complete classification
        """
        payload.lower()

        # Extract components
        injection_type = self._determine_injection_type(payload)
        trigger, trigger_element, trigger_attr = self._extract_trigger(payload)
        vector = self._build_vector_string(
            trigger_element, trigger_attr, injection_type
        )
        requirements = self._determine_requirements(trigger, injection_type)
        complexity = self._assess_complexity(payload, injection_type)
        description = self._generate_description(
            injection_type, trigger, trigger_element
        )

        is_deterministic = trigger in [
            TriggerMechanism.AUTO_IMMEDIATE,
            TriggerMechanism.ERROR_TRIGGERED,
            TriggerMechanism.LOAD_TRIGGERED,
            TriggerMechanism.EXTERNAL_LOAD,
        ]

        requires_interaction = trigger in [
            TriggerMechanism.USER_CLICK,
            TriggerMechanism.USER_HOVER,
            TriggerMechanism.USER_FOCUS,
            TriggerMechanism.USER_INPUT,
            TriggerMechanism.USER_SCROLL,
        ]

        result = PayloadClassification(
            injection_type=injection_type,
            trigger=trigger,
            trigger_element=trigger_element,
            trigger_attribute=trigger_attr,
            vector=vector,
            execution_requirements=requirements,
            complexity=complexity,
            description=description,
            is_deterministic=is_deterministic,
            requires_interaction=requires_interaction,
        )

        logger.debug(f"Classified payload: {result.to_payload_class_string()}")
        return result

    def _determine_injection_type(self, payload: str) -> InjectionType:
        """Determine the primary injection type"""

        # External script
        if self.PATTERNS["script_src"].search(payload):
            return InjectionType.SCRIPT_EXTERNAL

        # Inline script
        if self.PATTERNS["script_tag"].search(payload):
            return InjectionType.SCRIPT_INLINE

        # SVG-based
        if self.PATTERNS["svg_tag"].search(payload):
            return InjectionType.SVG_INJECTION

        # JavaScript URI
        if self.PATTERNS["javascript_uri"].search(payload):
            return InjectionType.JAVASCRIPT_URI

        # Data URI
        if self.PATTERNS["data_uri"].search(payload):
            return InjectionType.DATA_URI

        # Event handler
        if self.PATTERNS["event_handler"].search(payload):
            # Check if it's just an attribute or full HTML injection
            if self.PATTERNS["tag_extract"].search(payload):
                return InjectionType.HTML_ATTRIBUTE
            return InjectionType.EVENT_HANDLER

        # Eval-based
        if self.PATTERNS["eval_call"].search(payload):
            return InjectionType.EVAL_BASED

        # DOM manipulation
        if self.PATTERNS["innerhtml"].search(payload) or self.PATTERNS[
            "document_write"
        ].search(payload):
            return InjectionType.DOM_MANIPULATION

        return InjectionType.UNKNOWN

    def _extract_trigger(
        self, payload: str
    ) -> tuple[TriggerMechanism, Optional[str], Optional[str]]:
        """Extract trigger mechanism, element, and attribute"""

        # Find event handler
        handler_match = self.PATTERNS["event_handler"].search(payload)
        if handler_match:
            handler_name = "on" + handler_match.group(1).lower()

            # Find associated element
            tag_match = self.PATTERNS["tag_extract"].search(payload)
            element = tag_match.group(1).lower() if tag_match else None

            # Determine trigger type
            if handler_name in self.all_auto_handlers:
                if handler_name == "onerror":
                    return TriggerMechanism.ERROR_TRIGGERED, element, handler_name
                elif handler_name in ["onload", "onloadeddata", "onloadedmetadata"]:
                    return TriggerMechanism.LOAD_TRIGGERED, element, handler_name
                else:
                    return TriggerMechanism.AUTO_DELAYED, element, handler_name

            if handler_name in self.all_user_handlers:
                # Map to specific user trigger
                for group, handlers in self.USER_INTERACTION_HANDLERS.items():
                    if handler_name in handlers:
                        trigger_map = {
                            "click": TriggerMechanism.USER_CLICK,
                            "mouse": TriggerMechanism.USER_HOVER,
                            "keyboard": TriggerMechanism.USER_INPUT,
                            "focus": TriggerMechanism.USER_FOCUS,
                            "input": TriggerMechanism.USER_INPUT,
                            "form": TriggerMechanism.USER_CLICK,
                            "scroll": TriggerMechanism.USER_SCROLL,
                            "drag": TriggerMechanism.USER_CLICK,
                            "touch": TriggerMechanism.USER_CLICK,
                            "pointer": TriggerMechanism.USER_CLICK,
                        }
                        return (
                            trigger_map.get(group, TriggerMechanism.USER_CLICK),
                            element,
                            handler_name,
                        )

            return TriggerMechanism.AUTO_IMMEDIATE, element, handler_name

        # External script
        if self.PATTERNS["script_src"].search(payload):
            return TriggerMechanism.EXTERNAL_LOAD, "script", "src"

        # Inline script
        if self.PATTERNS["script_tag"].search(payload):
            return TriggerMechanism.AUTO_IMMEDIATE, "script", None

        # JavaScript URI
        if self.PATTERNS["javascript_uri"].search(payload):
            # Find the element using it
            for tag in ["a", "iframe", "form", "object"]:
                if f"<{tag}" in payload.lower():
                    return (
                        TriggerMechanism.USER_CLICK,
                        tag,
                        "href" if tag == "a" else "src",
                    )
            return TriggerMechanism.USER_CLICK, None, "javascript:"

        return TriggerMechanism.NONE, None, None

    def _build_vector_string(
        self,
        element: Optional[str],
        attribute: Optional[str],
        injection_type: InjectionType,
    ) -> str:
        """Build vector string like 'img.onerror'"""

        if element and attribute:
            return f"{element}.{attribute}"
        elif element:
            return element
        elif attribute:
            return attribute
        else:
            return injection_type.value.lower().replace(" ", "_")

    def _determine_requirements(
        self, trigger: TriggerMechanism, injection_type: InjectionType
    ) -> list[str]:
        """Determine execution requirements"""

        requirements = []

        if trigger == TriggerMechanism.USER_CLICK:
            requirements.append("User must click the element")
        elif trigger == TriggerMechanism.USER_HOVER:
            requirements.append("User must hover over the element")
        elif trigger == TriggerMechanism.USER_FOCUS:
            requirements.append("Element must receive focus")
        elif trigger == TriggerMechanism.USER_INPUT:
            requirements.append("User must interact with input")
        elif trigger == TriggerMechanism.ERROR_TRIGGERED:
            requirements.append("Resource load must fail (auto-trigger)")
        elif trigger == TriggerMechanism.LOAD_TRIGGERED:
            requirements.append("Resource must load (auto-trigger)")
        elif trigger == TriggerMechanism.EXTERNAL_LOAD:
            requirements.append("External script must be accessible")
        elif trigger == TriggerMechanism.AUTO_IMMEDIATE:
            requirements.append("Executes automatically on page load")

        if injection_type == InjectionType.SCRIPT_EXTERNAL:
            requirements.append("External script server must be online")

        if not requirements:
            requirements.append("Standard DOM insertion")

        return requirements

    def _assess_complexity(self, payload: str, injection_type: InjectionType) -> str:
        """Assess payload complexity"""

        # Simple payloads
        if len(payload) < 50:
            if injection_type in [
                InjectionType.SCRIPT_INLINE,
                InjectionType.EVENT_HANDLER,
            ]:
                return "low"

        # Complex obfuscation patterns
        obfuscation_indicators = [
            "fromcharcode",
            "charcodeat",
            "atob",
            "btoa",
            "unescape",
            "decodeuri",
            "encodeduri",
            "\\x",
            "\\u",
            "&#",
        ]

        payload_lower = payload.lower()
        obfuscation_count = sum(
            1 for ind in obfuscation_indicators if ind in payload_lower
        )

        if obfuscation_count >= 3:
            return "high"
        elif obfuscation_count >= 1:
            return "medium"

        # Nested elements increase complexity
        tag_count = len(self.PATTERNS["tag_extract"].findall(payload))
        if tag_count >= 3:
            return "medium"

        return "low"

    def _generate_description(
        self,
        injection_type: InjectionType,
        trigger: TriggerMechanism,
        element: Optional[str],
    ) -> str:
        """Generate human-readable description"""

        descriptions = {
            InjectionType.SCRIPT_EXTERNAL: "Loads external JavaScript from attacker-controlled server",
            InjectionType.SCRIPT_INLINE: "Injects inline JavaScript for immediate execution",
            InjectionType.HTML_ATTRIBUTE: "Injects via HTML element attributes",
            InjectionType.EVENT_HANDLER: "Injects JavaScript through event handler attribute",
            InjectionType.JAVASCRIPT_URI: "Uses javascript: URI scheme for code execution",
            InjectionType.DATA_URI: "Uses data: URI to embed executable content",
            InjectionType.SVG_INJECTION: "Exploits SVG elements for script execution",
            InjectionType.CSS_INJECTION: "Injects via CSS expression or behavior",
            InjectionType.EVAL_BASED: "Uses eval() or similar for dynamic code execution",
            InjectionType.DOM_MANIPULATION: "Manipulates DOM to inject executable content",
        }

        base_desc = descriptions.get(injection_type, "XSS injection vector")

        if element:
            base_desc = f"{base_desc} using <{element}> element"

        trigger_descs = {
            TriggerMechanism.ERROR_TRIGGERED: " (triggers on error)",
            TriggerMechanism.LOAD_TRIGGERED: " (triggers on load)",
            TriggerMechanism.AUTO_IMMEDIATE: " (auto-executes)",
            TriggerMechanism.USER_CLICK: " (requires user click)",
            TriggerMechanism.USER_HOVER: " (requires mouse hover)",
        }

        base_desc += trigger_descs.get(trigger, "")

        return base_desc


# Singleton instance
_classifier: Optional[PayloadClassifier] = None


def get_payload_classifier() -> PayloadClassifier:
    """Get singleton classifier instance"""
    global _classifier
    if _classifier is None:
        _classifier = PayloadClassifier()
    return _classifier
