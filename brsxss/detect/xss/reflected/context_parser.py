#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Created - Hierarchical Context Detection
Telegram: https://t.me/EasyProTech

Context Parser - provides granular context detection for XSS payloads.

Instead of coarse 'html' or 'javascript', provides hierarchical path:
- html > body > div > img > onerror
- html > script > inline
- html > a > href > javascript_uri
"""

from enum import Enum
from typing import Optional, Any, Union
from dataclasses import dataclass, field
import re
from html.parser import HTMLParser

from brsxss.utils.logger import Logger

logger = Logger("core.context_parser")


class ContextType(Enum):
    """Base context types"""

    HTML = "html"
    JAVASCRIPT = "javascript"
    CSS = "css"
    URL = "url"
    SVG = "svg"
    XML = "xml"
    JSON = "json"
    TEMPLATE = "template"
    UNKNOWN = "unknown"


class HTMLSubContext(Enum):
    """HTML sub-contexts"""

    TAG_CONTENT = "tag_content"  # Between tags: <div>HERE</div>
    TAG_NAME = "tag_name"  # <HERE ...>
    ATTRIBUTE_NAME = "attribute_name"  # <tag HERE=value>
    ATTRIBUTE_VALUE = "attribute_value"  # <tag attr="HERE">
    ATTRIBUTE_UNQUOTED = "attribute_unquoted"  # <tag attr=HERE>
    COMMENT = "comment"  # <!-- HERE -->
    DOCTYPE = "doctype"
    CDATA = "cdata"


class JSSubContext(Enum):
    """JavaScript sub-contexts"""

    STRING_SINGLE = "string_single"  # 'HERE'
    STRING_DOUBLE = "string_double"  # "HERE"
    STRING_TEMPLATE = "string_template"  # `HERE`
    EXPRESSION = "expression"  # var x = HERE
    STATEMENT = "statement"  # HERE;
    COMMENT_LINE = "comment_line"  # // HERE
    COMMENT_BLOCK = "comment_block"  # /* HERE */
    REGEX = "regex"  # /HERE/


class AttributeType(Enum):
    """Attribute context types"""

    EVENT_HANDLER = "event_handler"  # onclick, onerror, etc.
    SRC = "src"  # img src, script src
    HREF = "href"  # a href
    DATA = "data"  # data-* attributes
    STYLE = "style"  # style attribute (CSS context)
    CLASS = "class"
    ID = "id"
    ACTION = "action"  # form action
    FORMACTION = "formaction"
    SRCDOC = "srcdoc"  # iframe srcdoc (HTML context)
    REGULAR = "regular"  # Other attributes


@dataclass
class ContextPath:
    """Hierarchical context path"""

    base: ContextType
    hierarchy: list[str] = field(default_factory=list)
    subcontext: Optional[Enum] = None
    attribute_type: Optional[AttributeType] = None
    tag_name: Optional[str] = None
    attribute_name: Optional[str] = None
    is_quoted: bool = True
    quote_char: Optional[str] = None
    depth: int = 0

    def to_string(self) -> str:
        """Convert to string representation like: html > img > onerror"""
        parts = [self.base.value]
        parts.extend(self.hierarchy)
        if self.subcontext:
            parts.append(self.subcontext.value)
        return " > ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for reports"""
        return {
            "base": self.base.value,
            "hierarchy": self.hierarchy,
            "path": self.to_string(),
            "subcontext": self.subcontext.value if self.subcontext else None,
            "attribute_type": (
                self.attribute_type.value if self.attribute_type else None
            ),
            "tag_name": self.tag_name,
            "attribute_name": self.attribute_name,
            "is_quoted": self.is_quoted,
            "quote_char": self.quote_char,
            "depth": self.depth,
        }


@dataclass
class ContextAnalysis:
    """Complete context analysis result"""

    primary_context: ContextPath
    secondary_contexts: list[ContextPath] = field(default_factory=list)
    risk_level: str = "medium"  # low, medium, high, critical
    can_execute_js: bool = False
    requires_breakout: bool = False
    breakout_needed: Optional[str] = None
    encoding_detected: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


class PayloadLocationFinder(HTMLParser):
    """Find exact location of payload in HTML"""

    def __init__(self, payload: str):
        super().__init__()
        self.payload = payload
        self.payload_lower = payload.lower()
        self.locations: list[dict[str, Any]] = []
        self.current_tag: Optional[str] = None
        self.tag_stack: list[str] = []
        self.current_attrs: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]):
        self.tag_stack.append(tag)
        self.current_tag = tag

        for name, value in attrs:
            if value and self.payload_lower in value.lower():
                self.locations.append(
                    {
                        "type": "attribute_value",
                        "tag": tag,
                        "attribute": name,
                        "tag_stack": list(self.tag_stack),
                        "value": value,
                    }
                )

    def handle_endtag(self, tag: str):
        if self.tag_stack and self.tag_stack[-1] == tag:
            self.tag_stack.pop()
        self.current_tag = self.tag_stack[-1] if self.tag_stack else None

    def handle_data(self, data: str):
        if self.payload_lower in data.lower():
            self.locations.append(
                {
                    "type": "content",
                    "tag": self.current_tag,
                    "tag_stack": list(self.tag_stack),
                    "data": data,
                }
            )

    def handle_comment(self, data: str):
        if self.payload_lower in data.lower():
            self.locations.append(
                {
                    "type": "comment",
                    "tag_stack": list(self.tag_stack),
                    "data": data,
                }
            )


class ContextParser:
    """
    Parses response content to determine granular injection context.

    Provides hierarchical context detection for more accurate
    severity and confidence scoring.
    """

    # Event handler attributes
    EVENT_HANDLERS = {
        "onabort",
        "onafterprint",
        "onbeforeprint",
        "onbeforeunload",
        "onblur",
        "oncanplay",
        "oncanplaythrough",
        "onchange",
        "onclick",
        "oncontextmenu",
        "oncopy",
        "oncuechange",
        "oncut",
        "ondblclick",
        "ondrag",
        "ondragend",
        "ondragenter",
        "ondragleave",
        "ondragover",
        "ondragstart",
        "ondrop",
        "ondurationchange",
        "onemptied",
        "onended",
        "onerror",
        "onfocus",
        "onhashchange",
        "oninput",
        "oninvalid",
        "onkeydown",
        "onkeypress",
        "onkeyup",
        "onload",
        "onloadeddata",
        "onloadedmetadata",
        "onloadstart",
        "onmessage",
        "onmousedown",
        "onmousemove",
        "onmouseout",
        "onmouseover",
        "onmouseup",
        "onmousewheel",
        "onoffline",
        "ononline",
        "onpagehide",
        "onpageshow",
        "onpaste",
        "onpause",
        "onplay",
        "onplaying",
        "onpopstate",
        "onprogress",
        "onratechange",
        "onreset",
        "onresize",
        "onscroll",
        "onsearch",
        "onseeked",
        "onseeking",
        "onselect",
        "onstalled",
        "onstorage",
        "onsubmit",
        "onsuspend",
        "ontimeupdate",
        "ontoggle",
        "onunload",
        "onvolumechange",
        "onwaiting",
        "onwheel",
    }

    # URL-expecting attributes
    URL_ATTRIBUTES = {
        "href",
        "src",
        "action",
        "formaction",
        "data",
        "poster",
        "codebase",
        "cite",
        "background",
        "longdesc",
        "usemap",
        "profile",
        "manifest",
    }

    # Dangerous tags
    SCRIPT_TAGS = {"script"}
    STYLE_TAGS = {"style"}

    # JavaScript patterns
    JS_STRING_PATTERNS = [
        (r"'[^'\\]*(?:\\.[^'\\]*)*'", "single"),
        (r'"[^"\\]*(?:\\.[^"\\]*)*"', "double"),
        (r"`[^`\\]*(?:\\.[^`\\]*)*`", "template"),
    ]

    def __init__(self):
        logger.info("Context Parser initialized")

    def parse(
        self, content: str, payload: str, content_type: Optional[str] = None
    ) -> ContextAnalysis:
        """
        Parse content and determine context for payload.

        Args:
            content: Full response content
            payload: The payload to find
            content_type: Content-Type header value

        Returns:
            ContextAnalysis with detailed context information
        """

        # 1. Determine base content type
        base_type = self._determine_base_type(content, content_type)

        # 2. Find payload location(s)
        locations = self._find_payload_locations(content, payload, base_type)

        if not locations:
            return ContextAnalysis(
                primary_context=ContextPath(base=ContextType.UNKNOWN),
                risk_level="low",
                can_execute_js=False,
            )

        # 3. Analyze each location
        contexts = []
        for loc in locations:
            ctx = self._analyze_location(loc, base_type)
            contexts.append(ctx)

        # 4. Determine primary context (highest risk)
        primary = max(contexts, key=lambda c: self._context_risk_score(c))
        secondary = [c for c in contexts if c != primary]

        # 5. Calculate overall risk
        risk = self._calculate_risk_level(primary)
        can_execute = self._can_execute_javascript(primary)

        # 6. Determine breakout requirements
        breakout_needed, breakout_str = self._determine_breakout(primary)

        # 7. Generate suggestions
        suggestions = self._generate_suggestions(primary)

        return ContextAnalysis(
            primary_context=primary,
            secondary_contexts=secondary,
            risk_level=risk,
            can_execute_js=can_execute,
            requires_breakout=breakout_needed,
            breakout_needed=breakout_str,
            suggestions=suggestions,
        )

    def _determine_base_type(
        self, content: str, content_type: Optional[str]
    ) -> ContextType:
        """Determine base content type from headers or content"""

        if content_type:
            ct_lower = content_type.lower()
            if "html" in ct_lower:
                return ContextType.HTML
            if "javascript" in ct_lower or "ecmascript" in ct_lower:
                return ContextType.JAVASCRIPT
            if "json" in ct_lower:
                return ContextType.JSON
            if "css" in ct_lower:
                return ContextType.CSS
            if "xml" in ct_lower or "svg" in ct_lower:
                return ContextType.XML

        # Heuristic detection
        content_stripped = content.strip()
        if content_stripped.startswith("<!DOCTYPE") or content_stripped.startswith(
            "<html"
        ):
            return ContextType.HTML
        if content_stripped.startswith("{") or content_stripped.startswith("["):
            return ContextType.JSON
        if content_stripped.startswith("<?xml") or content_stripped.startswith("<svg"):
            return ContextType.XML
        if "<" in content and ">" in content:
            return ContextType.HTML

        return ContextType.UNKNOWN

    def _find_payload_locations(
        self, content: str, payload: str, base_type: ContextType
    ) -> list[dict[str, Any]]:
        """Find all locations where payload appears"""

        locations: list[dict[str, Any]] = []
        payload_lower = payload.lower()
        content_lower = content.lower()

        # Quick check
        if payload_lower not in content_lower:
            return locations

        if base_type == ContextType.HTML:
            # Use HTML parser
            try:
                parser = PayloadLocationFinder(payload)
                parser.feed(content)
                locations.extend(parser.locations)
            except Exception as e:
                logger.debug(f"HTML parse error: {e}")

        # Also do raw text search for positions
        pos = 0
        while True:
            idx = content_lower.find(payload_lower, pos)
            if idx == -1:
                break

            locations.append(
                {
                    "type": "raw",
                    "position": idx,
                    "before": content[max(0, idx - 100) : idx],
                    "after": content[idx + len(payload) : idx + len(payload) + 100],
                }
            )
            pos = idx + 1

        return locations

    def _analyze_location(
        self, location: dict[str, Any], base_type: ContextType
    ) -> ContextPath:
        """Analyze a specific payload location"""

        loc_type = location.get("type", "raw")

        if loc_type == "attribute_value":
            return self._analyze_attribute_location(location, base_type)
        elif loc_type == "content":
            return self._analyze_content_location(location, base_type)
        elif loc_type == "comment":
            return self._analyze_comment_location(location, base_type)
        else:
            return self._analyze_raw_location(location, base_type)

    def _analyze_attribute_location(
        self, location: dict[str, Any], base_type: ContextType
    ) -> ContextPath:
        """Analyze payload in attribute value"""

        tag = location.get("tag", "unknown").lower()
        attr = location.get("attribute", "unknown").lower()
        tag_stack = location.get("tag_stack", [])

        hierarchy = list(tag_stack) if tag_stack else [tag]
        hierarchy.append(attr)

        # Determine attribute type
        attr_type = self._classify_attribute(attr)

        # Determine subcontext
        subcontext: Optional[Union[JSSubContext, HTMLSubContext]] = None
        if attr_type == AttributeType.EVENT_HANDLER:
            subcontext = JSSubContext.STATEMENT
        elif attr_type == AttributeType.STYLE:
            subcontext = None  # CSS context
        elif attr_type in {AttributeType.SRC, AttributeType.HREF, AttributeType.ACTION}:
            subcontext = None  # URL context potentially
        else:
            subcontext = HTMLSubContext.ATTRIBUTE_VALUE

        return ContextPath(
            base=base_type,
            hierarchy=hierarchy,
            subcontext=subcontext,
            attribute_type=attr_type,
            tag_name=tag,
            attribute_name=attr,
            is_quoted=True,  # Assume quoted for parser-found
            depth=len(tag_stack),
        )

    def _analyze_content_location(
        self, location: dict[str, Any], base_type: ContextType
    ) -> ContextPath:
        """Analyze payload in tag content"""

        tag = location.get("tag", "body").lower()
        tag_stack = location.get("tag_stack", [])

        hierarchy = list(tag_stack) if tag_stack else [tag]

        # Special handling for script/style tags
        if tag == "script":
            return ContextPath(
                base=ContextType.JAVASCRIPT,
                hierarchy=hierarchy,
                subcontext=JSSubContext.STATEMENT,
                tag_name=tag,
                depth=len(tag_stack),
            )
        elif tag == "style":
            return ContextPath(
                base=ContextType.CSS,
                hierarchy=hierarchy,
                tag_name=tag,
                depth=len(tag_stack),
            )

        return ContextPath(
            base=base_type,
            hierarchy=hierarchy,
            subcontext=HTMLSubContext.TAG_CONTENT,
            tag_name=tag,
            depth=len(tag_stack),
        )

    def _analyze_comment_location(
        self, location: dict[str, Any], base_type: ContextType
    ) -> ContextPath:
        """Analyze payload in HTML comment"""

        return ContextPath(
            base=base_type,
            hierarchy=["comment"],
            subcontext=HTMLSubContext.COMMENT,
        )

    def _analyze_raw_location(
        self, location: dict[str, Any], base_type: ContextType
    ) -> ContextPath:
        """Analyze payload from raw position"""

        before = location.get("before", "")
        after = location.get("after", "")

        # Check if inside quotes
        before.count("'")
        before.count('"')
        before.count("`")

        # Check for script context
        if re.search(r"<\s*script[^>]*>\s*$", before, re.IGNORECASE):
            return ContextPath(
                base=ContextType.JAVASCRIPT,
                hierarchy=["script"],
                subcontext=JSSubContext.STATEMENT,
            )

        # Check for attribute context
        attr_match = re.search(r'(\w+)\s*=\s*["\']?\s*$', before)
        if attr_match:
            attr_name = attr_match.group(1).lower()
            attr_type = self._classify_attribute(attr_name)

            # Find tag name
            tag_match = re.search(r"<\s*(\w+)[^>]*$", before)
            tag_name = tag_match.group(1) if tag_match else "unknown"

            return ContextPath(
                base=base_type,
                hierarchy=[tag_name, attr_name],
                subcontext=HTMLSubContext.ATTRIBUTE_VALUE,
                attribute_type=attr_type,
                tag_name=tag_name,
                attribute_name=attr_name,
            )

        # Check for between tags
        if re.search(r">\s*$", before) and re.search(r"^\s*<", after):
            return ContextPath(
                base=base_type,
                hierarchy=["text_content"],
                subcontext=HTMLSubContext.TAG_CONTENT,
            )

        return ContextPath(
            base=base_type,
            subcontext=HTMLSubContext.TAG_CONTENT,
        )

    def _classify_attribute(self, attr_name: str) -> AttributeType:
        """Classify attribute by its security relevance"""

        attr_lower = attr_name.lower()

        if attr_lower in self.EVENT_HANDLERS:
            return AttributeType.EVENT_HANDLER
        if attr_lower == "href":
            return AttributeType.HREF
        if attr_lower == "src":
            return AttributeType.SRC
        if attr_lower == "style":
            return AttributeType.STYLE
        if attr_lower == "action":
            return AttributeType.ACTION
        if attr_lower == "formaction":
            return AttributeType.FORMACTION
        if attr_lower == "srcdoc":
            return AttributeType.SRCDOC
        if attr_lower.startswith("data-"):
            return AttributeType.DATA
        if attr_lower == "class":
            return AttributeType.CLASS
        if attr_lower == "id":
            return AttributeType.ID

        return AttributeType.REGULAR

    def _context_risk_score(self, context: ContextPath) -> int:
        """Score context by risk level"""

        score = 0

        # Base type scores
        if context.base == ContextType.JAVASCRIPT:
            score += 100
        elif context.base == ContextType.HTML:
            score += 50
        elif context.base == ContextType.CSS:
            score += 30

        # Attribute type bonuses
        if context.attribute_type == AttributeType.EVENT_HANDLER:
            score += 80
        elif context.attribute_type == AttributeType.SRCDOC:
            score += 70
        elif context.attribute_type in {AttributeType.SRC, AttributeType.HREF}:
            score += 60

        # Subcontext bonuses
        if context.subcontext == JSSubContext.STATEMENT:
            score += 40
        elif context.subcontext == JSSubContext.EXPRESSION:
            score += 30

        return score

    def _calculate_risk_level(self, context: ContextPath) -> str:
        """Calculate overall risk level"""

        score = self._context_risk_score(context)

        if score >= 150:
            return "critical"
        elif score >= 100:
            return "high"
        elif score >= 50:
            return "medium"
        return "low"

    def _can_execute_javascript(self, context: ContextPath) -> bool:
        """Determine if context allows JavaScript execution"""

        # Direct JS context
        if context.base == ContextType.JAVASCRIPT:
            return True

        # Event handler attributes
        if context.attribute_type == AttributeType.EVENT_HANDLER:
            return True

        # javascript: URIs in href/src
        if context.attribute_type in {AttributeType.HREF, AttributeType.SRC}:
            return True  # Could be javascript: URI

        # srcdoc allows HTML which can contain scripts
        if context.attribute_type == AttributeType.SRCDOC:
            return True

        # HTML content between tags
        if context.subcontext == HTMLSubContext.TAG_CONTENT:
            return True  # Can inject script tags

        return False

    def _determine_breakout(self, context: ContextPath) -> tuple[bool, Optional[str]]:
        """Determine what breakout is needed"""

        if context.base == ContextType.JAVASCRIPT:
            if context.subcontext in {
                JSSubContext.STRING_SINGLE,
                JSSubContext.STRING_DOUBLE,
                JSSubContext.STRING_TEMPLATE,
            }:
                return True, "String escape required"

        if context.subcontext == HTMLSubContext.ATTRIBUTE_VALUE:
            if context.is_quoted:
                return True, f"Quote breakout ({context.quote_char or 'quote'})"

        if context.subcontext == HTMLSubContext.COMMENT:
            return True, "Comment breakout (-->)"

        return False, None

    def _generate_suggestions(self, context: ContextPath) -> list[str]:
        """Generate exploitation suggestions"""

        suggestions = []

        if context.attribute_type == AttributeType.EVENT_HANDLER:
            suggestions.append("Event handler context - direct JS execution possible")
            suggestions.append(f"Trigger: {context.attribute_name}")

        if context.subcontext == HTMLSubContext.TAG_CONTENT:
            suggestions.append(
                "HTML content context - script/img/svg injection possible"
            )

        if context.base == ContextType.JAVASCRIPT:
            suggestions.append("JavaScript context - direct code injection")

        return suggestions


# Singleton instance
_parser: Optional[ContextParser] = None


def get_context_parser() -> ContextParser:
    """Get singleton parser instance"""
    global _parser
    if _parser is None:
        _parser = ContextParser()
    return _parser
