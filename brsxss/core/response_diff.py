#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 26 Dec 2025 20:35:00 UTC
Status: Created

Response Diff Engine - Compare baseline vs payload responses
to accurately detect XSS vulnerabilities and filter behavior.
"""

import re
import html
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from difflib import SequenceMatcher

from ..utils.logger import Logger

logger = Logger("core.response_diff")


class ReflectionStatus(Enum):
    """Status of payload reflection"""

    REFLECTED_RAW = "reflected_raw"  # Payload reflected as-is (vulnerable)
    REFLECTED_ENCODED = "reflected_encoded"  # Payload HTML-encoded (safe)
    REFLECTED_PARTIAL = "reflected_partial"  # Payload partially reflected
    FILTERED = "filtered"  # Payload completely removed
    MODIFIED = "modified"  # Payload modified/sanitized
    NOT_FOUND = "not_found"  # Payload not in response
    ERROR = "error"  # Request failed


class FilterType(Enum):
    """Type of filter detected"""

    NONE = "none"
    HTML_ENCODE = "html_encode"
    URL_ENCODE = "url_encode"
    STRIP_TAGS = "strip_tags"
    STRIP_EVENTS = "strip_events"
    STRIP_SCRIPT = "strip_script"
    BLACKLIST = "blacklist"
    WHITELIST = "whitelist"
    WAF = "waf"
    CUSTOM = "custom"


@dataclass
class DiffResult:
    """Result of response diff analysis"""

    parameter: str
    payload: str
    baseline_value: str

    # Reflection analysis
    reflection_status: ReflectionStatus = ReflectionStatus.NOT_FOUND
    reflected_value: Optional[str] = None
    reflection_position: int = -1
    reflection_context: str = ""

    # Filter analysis
    filter_detected: bool = False
    filter_type: FilterType = FilterType.NONE
    filter_pattern: str = ""

    # Encoding analysis
    encoding_applied: List[str] = field(default_factory=list)

    # Vulnerability assessment
    is_vulnerable: bool = False
    confidence: float = 0.0
    bypass_suggestions: List[str] = field(default_factory=list)

    # Response metadata
    baseline_length: int = 0
    payload_length: int = 0
    length_diff: int = 0
    similarity_ratio: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parameter": self.parameter,
            "payload": self.payload,
            "reflection_status": self.reflection_status.value,
            "reflected_value": self.reflected_value,
            "filter_detected": self.filter_detected,
            "filter_type": self.filter_type.value,
            "is_vulnerable": self.is_vulnerable,
            "confidence": self.confidence,
            "bypass_suggestions": self.bypass_suggestions,
            "encoding_applied": self.encoding_applied,
        }


class ResponseDiffEngine:
    """
    Compare baseline and payload responses to detect XSS.

    Key capabilities:
    - Exact reflection detection
    - Encoding detection (HTML, URL, etc.)
    - Filter fingerprinting
    - Bypass suggestion generation
    """

    # Characters that indicate raw reflection (dangerous)
    DANGEROUS_CHARS = ["<", ">", '"', "'", "`", "/", "\\"]

    # Common encoding patterns
    ENCODING_PATTERNS = {
        "html_entity": {
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;",
            "&": "&amp;",
        },
        "url_encode": {
            "<": "%3C",
            ">": "%3E",
            '"': "%22",
            "'": "%27",
            " ": "%20",
        },
        "unicode_escape": {
            "<": "\\u003c",
            ">": "\\u003e",
            '"': "\\u0022",
        },
    }

    # Event handler patterns
    EVENT_HANDLERS = [
        "onclick",
        "onerror",
        "onload",
        "onmouseover",
        "onfocus",
        "onblur",
        "oninput",
        "onchange",
        "onsubmit",
        "onkeydown",
        "onkeyup",
        "onkeypress",
        "ondblclick",
        "onmousedown",
        "onmouseup",
        "onmousemove",
        "onmouseout",
        "onmouseenter",
        "onmouseleave",
        "oncontextmenu",
        "onwheel",
        "ondrag",
        "ondragstart",
        "ondragend",
        "ondragenter",
        "ondragleave",
        "ondragover",
        "ondrop",
        "onscroll",
        "oncopy",
        "oncut",
        "onpaste",
        "onanimationstart",
        "onanimationend",
        "ontoggle",
    ]

    def __init__(self):
        """Initialize diff engine"""
        self.analysis_count = 0
        logger.info("Response Diff Engine initialized")

    def analyze(
        self,
        parameter: str,
        baseline_value: str,
        baseline_response: str,
        payload: str,
        payload_response: str,
    ) -> DiffResult:
        """
        Analyze difference between baseline and payload responses.

        Args:
            parameter: Parameter name being tested
            baseline_value: Safe baseline value (e.g., 'test123')
            baseline_response: Response with baseline value
            payload: XSS payload being tested
            payload_response: Response with payload

        Returns:
            DiffResult with analysis
        """
        self.analysis_count += 1

        result = DiffResult(
            parameter=parameter,
            payload=payload,
            baseline_value=baseline_value,
            baseline_length=len(baseline_response),
            payload_length=len(payload_response),
            length_diff=len(payload_response) - len(baseline_response),
        )

        # Calculate overall similarity
        result.similarity_ratio = self._calculate_similarity(
            baseline_response, payload_response
        )

        # Check for raw reflection (vulnerable)
        raw_reflection = self._find_raw_reflection(payload, payload_response)
        if raw_reflection:
            result.reflection_status = ReflectionStatus.REFLECTED_RAW
            result.reflected_value = raw_reflection["value"]
            result.reflection_position = raw_reflection["position"]
            result.reflection_context = raw_reflection["context"]
            result.is_vulnerable = True
            result.confidence = self._calculate_confidence(raw_reflection)
            logger.info(f"Raw reflection detected for {parameter}")
            return result

        # Check for encoded reflection
        encoded_reflection = self._find_encoded_reflection(payload, payload_response)
        if encoded_reflection:
            result.reflection_status = ReflectionStatus.REFLECTED_ENCODED
            result.reflected_value = encoded_reflection["value"]
            result.reflection_position = encoded_reflection["position"]
            result.encoding_applied = encoded_reflection["encodings"]
            result.filter_detected = True
            result.filter_type = FilterType.HTML_ENCODE
            result.is_vulnerable = False
            result.confidence = 0.1
            result.bypass_suggestions = self._suggest_encoding_bypass(
                encoded_reflection["encodings"]
            )
            logger.debug(f"Encoded reflection for {parameter}")
            return result

        # Check for partial reflection
        partial = self._find_partial_reflection(payload, payload_response)
        if partial:
            result.reflection_status = ReflectionStatus.REFLECTED_PARTIAL
            result.reflected_value = partial["value"]
            result.filter_detected = True
            result.filter_type = partial["filter_type"]
            result.filter_pattern = partial["pattern"]
            result.is_vulnerable = partial["potentially_exploitable"]
            result.confidence = 0.3 if partial["potentially_exploitable"] else 0.1
            result.bypass_suggestions = partial["bypass_suggestions"]
            logger.debug(f"Partial reflection for {parameter}")
            return result

        # Check if payload was completely filtered
        if self._is_filtered(
            baseline_value, baseline_response, payload, payload_response
        ):
            result.reflection_status = ReflectionStatus.FILTERED
            result.filter_detected = True
            result.filter_type = self._identify_filter_type(payload, payload_response)
            result.is_vulnerable = False
            result.bypass_suggestions = self._suggest_filter_bypass(result.filter_type)
            logger.debug(f"Payload filtered for {parameter}")
            return result

        # Payload not found in response
        result.reflection_status = ReflectionStatus.NOT_FOUND
        return result

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity ratio between two texts"""
        if not text1 or not text2:
            return 0.0
        return SequenceMatcher(None, text1, text2).ratio()

    def _find_raw_reflection(
        self, payload: str, response: str
    ) -> Optional[Dict[str, Any]]:
        """Find exact payload reflection in response"""

        # Direct match
        pos = response.find(payload)
        if pos != -1:
            context = self._extract_context(response, pos, len(payload))
            return {
                "value": payload,
                "position": pos,
                "context": context,
                "type": "exact",
            }

        # Case-insensitive match (some apps lowercase)
        pos_lower = response.lower().find(payload.lower())
        if pos_lower != -1:
            actual_value = response[pos_lower : pos_lower + len(payload)]
            context = self._extract_context(response, pos_lower, len(payload))
            return {
                "value": actual_value,
                "position": pos_lower,
                "context": context,
                "type": "case_modified",
            }

        return None

    def _find_encoded_reflection(
        self, payload: str, response: str
    ) -> Optional[Dict[str, Any]]:
        """Find HTML/URL encoded payload in response"""

        encodings_found = []

        # Check HTML entity encoding
        html_encoded = html.escape(payload)
        pos = response.find(html_encoded)
        if pos != -1:
            encodings_found.append("html_entity")
            return {
                "value": html_encoded,
                "position": pos,
                "encodings": encodings_found,
                "context": self._extract_context(response, pos, len(html_encoded)),
            }

        # Check double HTML encoding
        double_encoded = html.escape(html.escape(payload))
        pos = response.find(double_encoded)
        if pos != -1:
            encodings_found.append("double_html_entity")
            return {
                "value": double_encoded,
                "position": pos,
                "encodings": encodings_found,
                "context": self._extract_context(response, pos, len(double_encoded)),
            }

        # Check URL encoding
        try:
            from urllib.parse import quote

            url_encoded = quote(payload, safe="")
            pos = response.find(url_encoded)
            if pos != -1:
                encodings_found.append("url_encode")
                return {
                    "value": url_encoded,
                    "position": pos,
                    "encodings": encodings_found,
                    "context": self._extract_context(response, pos, len(url_encoded)),
                }
        except Exception:
            pass

        # Check Unicode escape
        unicode_escaped = payload.encode("unicode_escape").decode("ascii")
        pos = response.find(unicode_escaped)
        if pos != -1:
            encodings_found.append("unicode_escape")
            return {
                "value": unicode_escaped,
                "position": pos,
                "encodings": encodings_found,
                "context": self._extract_context(response, pos, len(unicode_escaped)),
            }

        return None

    def _find_partial_reflection(
        self, payload: str, response: str
    ) -> Optional[Dict[str, Any]]:
        """Find partially filtered payload"""

        # Extract key parts of payload
        # For <script>alert(1)</script>, parts are: script, alert, 1

        result = {
            "value": "",
            "filter_type": FilterType.CUSTOM,
            "pattern": "",
            "potentially_exploitable": False,
            "bypass_suggestions": [],
        }

        # Check if tags are stripped but content remains
        # e.g., <script>alert(1)</script> -> alert(1)
        inner_content = re.sub(r"<[^>]+>", "", payload)
        if inner_content and inner_content in response:
            result["value"] = inner_content
            result["filter_type"] = FilterType.STRIP_TAGS
            result["pattern"] = "Tags stripped, content preserved"
            result["bypass_suggestions"] = [
                "Use tag-less payloads: javascript:alert(1)",
                "Use event handlers in existing elements",
                "Try SVG/MathML tags",
            ]
            return result

        # Check if script tag stripped but others allowed
        if "<script" in payload.lower():
            no_script = re.sub(r"</?script[^>]*>", "", payload, flags=re.IGNORECASE)
            if no_script != payload and no_script in response:
                result["value"] = no_script
                result["filter_type"] = FilterType.STRIP_SCRIPT
                result["pattern"] = "Script tags stripped"
                result["potentially_exploitable"] = True
                result["bypass_suggestions"] = [
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "<body onload=alert(1)>",
                ]
                return result

        # Check if event handlers stripped
        for handler in self.EVENT_HANDLERS:
            if handler in payload.lower():
                no_events = re.sub(
                    r'\s*on\w+\s*=\s*["\'][^"\']*["\']',
                    "",
                    payload,
                    flags=re.IGNORECASE,
                )
                if no_events != payload and no_events in response:
                    result["value"] = no_events
                    result["filter_type"] = FilterType.STRIP_EVENTS
                    result["pattern"] = f"Event handler {handler} stripped"
                    result["bypass_suggestions"] = [
                        "Use javascript: protocol",
                        "Use data: protocol with base64",
                        "Try less common events: ontoggle, onanimationend",
                    ]
                    return result

        # Check for significant substring match (at least 50% of payload)
        min_match_len = len(payload) // 2
        for i in range(len(payload) - min_match_len + 1):
            substring = payload[i : i + min_match_len]
            if substring in response:
                result["value"] = substring
                result["filter_type"] = FilterType.CUSTOM
                result["pattern"] = f"Partial match: {substring[:30]}..."
                return result

        return None

    def _is_filtered(
        self,
        baseline_value: str,
        baseline_response: str,
        payload: str,
        payload_response: str,
    ) -> bool:
        """Check if payload was completely filtered"""

        # If baseline value appears in its response but payload doesn't
        baseline_reflected = baseline_value in baseline_response
        payload_reflected = payload in payload_response

        if baseline_reflected and not payload_reflected:
            return True

        # Check if response dramatically shorter (content removed)
        if len(payload_response) < len(baseline_response) * 0.5:
            return True

        # Check if key dangerous characters are missing
        dangerous_in_payload = any(c in payload for c in self.DANGEROUS_CHARS)
        dangerous_in_response = any(c in payload_response for c in self.DANGEROUS_CHARS)

        if dangerous_in_payload and not dangerous_in_response:
            # Dangerous chars were in payload but not in response
            return True

        return False

    def _identify_filter_type(self, payload: str, response: str) -> FilterType:
        """Identify the type of filter applied"""

        # Check for HTML encoding
        if html.escape(payload) in response:
            return FilterType.HTML_ENCODE

        # Check for URL encoding
        try:
            from urllib.parse import quote

            if quote(payload, safe="") in response:
                return FilterType.URL_ENCODE
        except Exception:
            pass

        # Check if all tags removed
        if re.sub(r"<[^>]+>", "", payload) in response:
            return FilterType.STRIP_TAGS

        # Check if just script removed
        if re.sub(r"</?script[^>]*>", "", payload, flags=re.IGNORECASE) in response:
            return FilterType.STRIP_SCRIPT

        # Check if events removed
        if re.sub(r"\s*on\w+\s*=", "", payload, flags=re.IGNORECASE) in response:
            return FilterType.STRIP_EVENTS

        # Default to blacklist if something was removed
        return FilterType.BLACKLIST

    def _calculate_confidence(self, reflection: Dict[str, Any]) -> float:
        """Calculate vulnerability confidence based on reflection"""

        confidence = 0.5  # Base confidence for any reflection

        context = reflection.get("context", "").lower()

        # Higher confidence if in script context
        if "<script" in context or "javascript" in context:
            confidence += 0.3

        # Higher confidence if in event handler
        if any(handler in context for handler in self.EVENT_HANDLERS):
            confidence += 0.25

        # Higher confidence for exact match
        if reflection.get("type") == "exact":
            confidence += 0.15

        # Lower confidence if in attribute (needs breakout)
        if "value=" in context or "href=" in context:
            confidence -= 0.1

        return min(confidence, 0.99)

    def _extract_context(
        self, response: str, position: int, length: int, context_size: int = 100
    ) -> str:
        """Extract surrounding context for analysis"""
        start = max(0, position - context_size)
        end = min(len(response), position + length + context_size)
        return response[start:end]

    def _suggest_encoding_bypass(self, encodings: List[str]) -> List[str]:
        """Suggest bypasses for encoding filters"""
        suggestions = []

        if "html_entity" in encodings:
            suggestions.extend(
                [
                    "Use SVG with foreignObject",
                    "Try UTF-7 encoding if supported",
                    "Use numeric character references",
                    "Try double URL encoding",
                ]
            )

        if "url_encode" in encodings:
            suggestions.extend(
                [
                    "Try double URL encoding",
                    "Use mixed case (%3c vs %3C)",
                    "Try overlong UTF-8 sequences",
                ]
            )

        if "double_html_entity" in encodings:
            suggestions.extend(
                [
                    "Application double-encodes - may need context escape",
                    "Try alternative tags/attributes",
                ]
            )

        return suggestions

    def _suggest_filter_bypass(self, filter_type: FilterType) -> List[str]:
        """Suggest bypasses based on filter type"""

        bypass_map = {
            FilterType.STRIP_TAGS: [
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                '"><img src=x onerror=alert(1)>',
                "javascript:alert(1)",
            ],
            FilterType.STRIP_SCRIPT: [
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
            ],
            FilterType.STRIP_EVENTS: [
                '<a href="javascript:alert(1)">click</a>',
                '<form action="javascript:alert(1)"><input type=submit>',
                '<object data="javascript:alert(1)">',
            ],
            FilterType.HTML_ENCODE: [
                "Try breaking out of attribute context first",
                "Use unquoted attributes",
                "Try JavaScript template literals",
            ],
            FilterType.BLACKLIST: [
                "Use case variations: <ScRiPt>",
                "Use null bytes: <scr\\x00ipt>",
                "Use encoding: <script/src=data:,alert(1)>",
                "Try lesser-known tags: <details ontoggle=alert(1) open>",
            ],
            FilterType.WAF: [
                "Try obfuscation techniques",
                "Use HTTP parameter pollution",
                "Try chunked encoding",
                "Use alternative protocols",
            ],
        }

        return bypass_map.get(filter_type, [])

    def get_statistics(self) -> Dict[str, int]:
        """Get engine statistics"""
        return {"total_analyses": self.analysis_count}
