#!/usr/bin/env python3

"""
BRS-XSS HTML Context Detector

Specialized detector for HTML contexts.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from .context_types import ContextType
from brsxss.utils.logger import Logger

logger = Logger("core.html_context_detector")


class HTMLContextDetector:
    """Detects and analyzes HTML contexts for XSS injections"""

    def __init__(self):
        """Initialize HTML context detector"""
        self.html_patterns = {
            "html_content": r">\s*{}\s*<",
            "html_attribute": r'(\w+)\s*=\s*["\']?[^"\']*{}[^"\']*["\']?',
            "html_comment": r"<!--[^>]*{}[^>]*-->",
            "tag_name": r"<\s*{}\s*[^>]*>",
            "style_attr": r'style\s*=\s*["\'][^"\']*{}[^"\']*["\']',
        }

    def detect_html_context(
        self, html_content: str, marker_pos: int, marker: str
    ) -> ContextType:
        """
        Detect HTML context type at marker position.

        Args:
            html_content: HTML content
            marker_pos: Position of marker in content
            marker: Marker string

        Returns:
            Detected context type
        """
        # Check for HTML comment
        if self._is_in_html_comment(html_content, marker_pos):
            return ContextType.HTML_COMMENT

        # Check for HTML attribute
        if self._is_in_html_attribute(html_content, marker_pos, marker):
            # Check if this is an event handler attribute (onload, onclick, etc.)
            # Event handlers contain JavaScript code, so context is JS_STRING
            attr_name = self.extract_attribute_name(html_content, marker_pos, marker)
            if attr_name and attr_name.startswith("on"):
                # This is an event handler - the value is JavaScript code
                # If marker is inside a JS string within the handler, it's JS_STRING
                return ContextType.JS_STRING
            return ContextType.HTML_ATTRIBUTE

        # Default to HTML content
        return ContextType.HTML_CONTENT

    def extract_tag_name(self, html_content: str, marker_pos: int) -> str:
        """Extract tag name containing the marker"""
        # Look backwards for opening tag
        search_start = max(0, marker_pos - 1000)
        before_marker = html_content[search_start:marker_pos]

        # Find last opening tag
        tag_match = re.search(r"<\s*(\w+)[^>]*$", before_marker)
        if tag_match:
            return tag_match.group(1).lower()

        # Look forward for closing tag
        search_end = min(len(html_content), marker_pos + 1000)
        after_marker = html_content[marker_pos:search_end]

        closing_tag_match = re.search(r"</\s*(\w+)\s*>", after_marker)
        if closing_tag_match:
            return closing_tag_match.group(1).lower()

        return ""

    def extract_attribute_name(
        self, html_content: str, marker_pos: int, marker: str
    ) -> str:
        """Extract attribute name containing the marker"""
        attr_name, _quote = self._extract_attribute_context(html_content, marker_pos)
        return attr_name

    def detect_quote_character(
        self, html_content: str, marker_pos: int, marker: str
    ) -> str:
        """Detect quote character used around marker"""
        _attr_name, quote_char = self._extract_attribute_context(html_content, marker_pos)
        return quote_char

    def _is_in_html_comment(self, html_content: str, pos: int) -> bool:
        """Check if position is inside HTML comment"""
        # Find nearest comment start before position
        comment_start = html_content.rfind("<!--", 0, pos)
        if comment_start == -1:
            return False

        # Find comment end after start
        comment_end = html_content.find("-->", comment_start)

        # Check if position is between start and end
        return comment_end == -1 or pos < comment_end

    def _is_in_html_attribute(self, html_content: str, pos: int, marker: str) -> bool:
        """Check if position is inside HTML attribute"""
        attr_name, _quote = self._extract_attribute_context(html_content, pos)
        return bool(attr_name)

    def _find_tag_end(self, html_content: str, tag_start: int, max_scan: int = 5000) -> int:
        """
        Find the end '>' for a tag starting at tag_start, ignoring any '>' inside
        QUOTED attribute values.

        Quote state is only entered when a quote starts immediately after '=' (optionally
        preceded by whitespace). This avoids treating quotes inside unquoted values (e.g.
        onload=alert('x')) as tag-delimiting quotes.
        """
        if tag_start < 0 or tag_start >= len(html_content):
            return -1

        i = tag_start + 1
        in_quote: str | None = None
        after_equal = False

        scan_limit = min(len(html_content), tag_start + max_scan)
        while i < scan_limit:
            c = html_content[i]

            if in_quote:
                if c == in_quote:
                    in_quote = None
                i += 1
                continue

            if c == ">":
                return i

            if after_equal:
                if c.isspace():
                    i += 1
                    continue
                if c in ("'", '"'):
                    in_quote = c
                after_equal = False
                i += 1
                continue

            if c == "=":
                after_equal = True

            i += 1

        return -1

    def _find_enclosing_tag_bounds(
        self, html_content: str, pos: int, max_scan: int = 5000
    ) -> tuple[int, int] | None:
        """Find (tag_start, tag_end) for the tag whose markup contains pos."""
        if pos < 0 or pos >= len(html_content):
            return None

        search_pos = pos + 1
        while True:
            tag_start = html_content.rfind("<", 0, search_pos)
            if tag_start == -1:
                return None

            # Skip HTML comments (handled separately, but avoid false positives here)
            if html_content.startswith("<!--", tag_start):
                search_pos = tag_start
                continue

            tag_end = self._find_tag_end(html_content, tag_start, max_scan=max_scan)
            if tag_end == -1:
                search_pos = tag_start
                continue

            if tag_end >= pos:
                return tag_start, tag_end

            search_pos = tag_start

    def _extract_attribute_context(
        self, html_content: str, marker_pos: int
    ) -> tuple[str, str]:
        """
        Extract (attribute_name, attribute_quote_char) for the attribute value
        that contains marker_pos.

        Returns ("", "") if marker_pos is not inside an attribute value.
        """
        bounds = self._find_enclosing_tag_bounds(html_content, marker_pos)
        if not bounds:
            return "", ""

        tag_start, tag_end = bounds
        i = tag_start + 1

        # Reject closing tags
        if i < len(html_content) and html_content[i] == "/":
            return "", ""

        # Skip leading whitespace
        while i <= tag_end and html_content[i].isspace():
            i += 1

        # Skip tag name
        while (
            i <= tag_end
            and not html_content[i].isspace()
            and html_content[i] not in (">", "/")
        ):
            i += 1

        # Parse attributes
        while i <= tag_end:
            # Skip whitespace
            while i <= tag_end and html_content[i].isspace():
                i += 1
            if i > tag_end:
                break

            if html_content[i] in (">", "/"):
                break

            # Parse attribute name
            name_start = i
            while (
                i <= tag_end
                and not html_content[i].isspace()
                and html_content[i] not in ("=", ">", "/")
            ):
                i += 1
            attr_name = html_content[name_start:i].strip()
            if not attr_name:
                break

            # Skip whitespace
            while i <= tag_end and html_content[i].isspace():
                i += 1

            # Boolean attribute (no value)
            if i > tag_end or html_content[i] != "=":
                continue

            # Consume '=' and whitespace
            i += 1
            while i <= tag_end and html_content[i].isspace():
                i += 1
            if i > tag_end:
                break

            # Parse attribute value
            quote_char = ""
            if html_content[i] in ("'", '"'):
                quote_char = html_content[i]
                i += 1
                value_start = i
                while i <= tag_end and html_content[i] != quote_char:
                    i += 1
                value_end = i

                if value_start <= marker_pos < value_end:
                    return attr_name.lower(), quote_char

                # Consume closing quote if present
                if i <= tag_end and html_content[i] == quote_char:
                    i += 1
            else:
                value_start = i
                while (
                    i <= tag_end
                    and not html_content[i].isspace()
                    and html_content[i] not in (">", "/")
                ):
                    i += 1
                value_end = i

                if value_start <= marker_pos < value_end:
                    return attr_name.lower(), quote_char

        return "", ""

    def get_surrounding_content(
        self, html_content: str, marker_pos: int, marker: str, radius: int = 200
    ) -> str:
        """Get surrounding content around marker"""
        start = max(0, marker_pos - radius)
        end = min(len(html_content), marker_pos + len(marker) + radius)

        return html_content[start:end]

    def analyze_tag_context(self, html_content: str, marker_pos: int) -> dict:
        """Analyze tag context around marker"""
        tag_name = self.extract_tag_name(html_content, marker_pos)

        context_info = {
            "tag_name": tag_name,
            "is_void_element": tag_name
            in [
                "area",
                "base",
                "br",
                "col",
                "embed",
                "hr",
                "img",
                "input",
                "link",
                "meta",
                "param",
                "source",
                "track",
                "wbr",
            ],
            "is_script_tag": tag_name == "script",
            "is_style_tag": tag_name == "style",
            "is_form_element": tag_name
            in ["form", "input", "textarea", "select", "button"],
            "is_media_element": tag_name
            in ["img", "video", "audio", "embed", "object"],
        }

        # Check for dangerous attributes
        if tag_name:
            dangerous_attrs = self._find_dangerous_attributes(html_content, marker_pos)
            context_info["dangerous_attributes"] = dangerous_attrs

        return context_info

    def _find_dangerous_attributes(self, html_content: str, marker_pos: int) -> list:
        """Find dangerous attributes in the current tag"""
        dangerous_attrs: list = []

        # Get tag content
        tag_start = html_content.rfind("<", 0, marker_pos)
        if tag_start == -1:
            return dangerous_attrs

        tag_end = html_content.find(">", tag_start)
        if tag_end == -1:
            return dangerous_attrs

        tag_content = html_content[tag_start : tag_end + 1]

        # Check for dangerous attributes
        dangerous_patterns = [
            r"\bon\w+\s*=",  # Event handlers
            r"\bsrc\s*=",  # Source attributes
            r"\bhref\s*=",  # Links
            r"\baction\s*=",  # Form actions
            r"\bstyle\s*=",  # Inline styles
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, tag_content, re.IGNORECASE):
                match = re.search(pattern, tag_content, re.IGNORECASE)
                if match:
                    attr_name = match.group().split("=")[0].strip()
                    dangerous_attrs.append(attr_name)

        return dangerous_attrs
