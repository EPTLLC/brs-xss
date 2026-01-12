#!/usr/bin/env python3

"""
BRS-XSS Context Types

Data types for context analysis system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from dataclasses import dataclass, field
from enum import Enum


class ContextType(Enum):
    """Context types for XSS injections"""

    # HTML contexts
    HTML_CONTENT = "html_content"  # Between HTML tags
    HTML_ATTRIBUTE = "html_attribute"  # Inside HTML attributes
    HTML_COMMENT = "html_comment"  # Inside HTML comments

    # JavaScript contexts
    JAVASCRIPT = "javascript"  # Inside <script> tags
    JS_STRING = "js_string"  # Inside JavaScript strings
    JS_OBJECT = "js_object"  # Inside JavaScript objects
    JS_TEMPLATE_LITERAL = "js_template_literal"  # Inside template literals

    # CSS context
    CSS_STYLE = "css_style"  # Inside CSS styles

    # URL/JSON contexts
    URL_PARAMETER = "url_parameter"  # URL parameter context
    JSON_VALUE = "json_value"  # JSON value context

    # XML/SVG contexts
    XML_CONTENT = "xml_content"  # XML content
    SVG_CONTENT = "svg_content"  # SVG content
    MATHML_CONTENT = "mathml_content"  # MathML content

    # v3.0.0: Advanced contexts
    WEBSOCKET_MESSAGE = "websocket_message"  # WebSocket message handler
    WEBSOCKET_URL = "websocket_url"  # WebSocket URL construction
    GRAPHQL_QUERY = "graphql_query"  # GraphQL query/mutation
    GRAPHQL_VARIABLE = "graphql_variable"  # GraphQL variable
    SSE_DATA = "sse_data"  # Server-Sent Events data
    SSE_EVENT = "sse_event"  # Server-Sent Events event name
    SHADOW_DOM = "shadow_dom"  # Shadow DOM content
    CUSTOM_ELEMENT = "custom_element"  # Custom element attribute
    SLOT_CONTENT = "slot_content"  # Slot content
    POSTMESSAGE_DATA = "postmessage_data"  # postMessage data
    POSTMESSAGE_ORIGIN = "postmessage_origin"  # postMessage origin check

    # Framework-specific contexts
    ANGULAR_TEMPLATE = "angular_template"  # Angular template expression
    VUE_TEMPLATE = "vue_template"  # Vue template expression
    REACT_JSX = "react_jsx"  # React JSX context

    UNKNOWN = "unknown"  # Unknown context


class FilterType(Enum):
    """Types of detected filters"""

    CONTENT_FILTERING = "content_filtering"
    HTML_ENTITY_ENCODING = "html_entity_encoding"
    URL_ENCODING = "url_encoding"
    BACKSLASH_ESCAPING = "backslash_escaping"
    UNICODE_ESCAPING = "unicode_escaping"
    WAF_FILTERING = "waf_filtering"


class EncodingType(Enum):
    """Types of detected encoding"""

    NONE = "none"
    HTML_ENTITIES = "html_entities"
    URL_ENCODING = "url_encoding"
    UNICODE_ESCAPING = "unicode_escaping"
    BACKSLASH_ESCAPING = "backslash_escaping"
    UNKNOWN = "unknown"


@dataclass
class InjectionPoint:
    """XSS injection point analysis result"""

    parameter_name: str
    parameter_value: str
    context_type: ContextType
    surrounding_code: str = ""
    tag_name: str = ""
    attribute_name: str = ""
    quote_char: str = ""

    # Analysis results
    filters_detected: list[str] = field(default_factory=list)
    encoding_detected: str = ""
    escape_sequences: list[str] = field(default_factory=list)

    # Position information
    position: int = -1
    line_number: int = -1
    column_number: int = -1

    # Confidence metrics
    detection_confidence: float = 1.0


@dataclass
class ContextAnalysisResult:
    """Result of context analysis"""

    parameter_name: str
    parameter_value: str
    injection_points: list[InjectionPoint]
    primary_context: ContextType

    # Summary information
    total_injections: int = 0
    unique_contexts: list[ContextType] = field(default_factory=list)
    risk_level: str = "unknown"

    # Recommendations
    payload_recommendations: list[str] = field(default_factory=list)
    bypass_recommendations: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Initialize computed values"""
        if not self.unique_contexts:
            self.unique_contexts = list(
                set(ip.context_type for ip in self.injection_points)
            )

        self.total_injections = len(self.injection_points)

        # Determine risk level
        if any(
            ip.context_type in [ContextType.JAVASCRIPT, ContextType.HTML_CONTENT]
            for ip in self.injection_points
        ):
            self.risk_level = "high"
        elif any(
            ip.context_type in [ContextType.HTML_ATTRIBUTE, ContextType.JS_STRING]
            for ip in self.injection_points
        ):
            self.risk_level = "medium"
        else:
            self.risk_level = "low"
