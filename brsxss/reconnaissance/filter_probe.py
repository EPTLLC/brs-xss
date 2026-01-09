#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 14:37:26 MSK
Status: Created
Telegram: https://t.me/EasyProTech

Filter probe system.
Active testing of input filtering and sanitization.
"""

import asyncio
import random
import string
from typing import Dict, List, Optional
from urllib.parse import urlencode, urlparse, parse_qs

from .recon_types import (
    FilterProfile,
    FilterStatus,
    ProtectionStrength,
    ParameterProfile,
    ReflectionPoint,
)
from ..utils.logger import Logger

logger = Logger("recon.filter_probe")


class FilterProbe:
    """
    Active filter probing system.
    Tests what characters, tags, events, and encodings are filtered/allowed.
    """

    # Test payloads for character filtering
    CHAR_TESTS = {
        "less_than": "<",
        "greater_than": ">",
        "double_quote": '"',
        "single_quote": "'",
        "backtick": "`",
        "slash": "/",
        "backslash": "\\",
        "parenthesis_open": "(",
        "parenthesis_close": ")",
        "curly_open": "{",
        "curly_close": "}",
    }

    # Test payloads for tag filtering
    TAG_TESTS = {
        "script": "<script>",
        "img": "<img>",
        "svg": "<svg>",
        "iframe": "<iframe>",
        "object": "<object>",
        "embed": "<embed>",
        "form": "<form>",
        "input": "<input>",
        "body": "<body>",
        "style": "<style>",
        "link": "<link>",
        "meta": "<meta>",
        "base": "<base>",
        "math": "<math>",
        "video": "<video>",
        "audio": "<audio>",
        "details": "<details>",
        "marquee": "<marquee>",
    }

    # Test payloads for event handler filtering
    EVENT_TESTS = {
        "onerror": "onerror=",
        "onload": "onload=",
        "onclick": "onclick=",
        "onmouseover": "onmouseover=",
        "onfocus": "onfocus=",
        "onblur": "onblur=",
        "oninput": "oninput=",
        "onchange": "onchange=",
        "onsubmit": "onsubmit=",
        "onanimationend": "onanimationend=",
        "ontoggle": "ontoggle=",
        "onpointerover": "onpointerover=",
    }

    # Test payloads for keyword filtering
    KEYWORD_TESTS = {
        "alert": "alert",
        "prompt": "prompt",
        "confirm": "confirm",
        "eval": "eval",
        "document": "document",
        "window": "window",
        "location": "location",
        "cookie": "cookie",
        "innerhtml": "innerHTML",
        "script": "script",
        "javascript": "javascript",
        "expression": "expression",
    }

    # Test payloads for protocol filtering
    PROTOCOL_TESTS = {
        "javascript": "javascript:",
        "data": "data:",
        "vbscript": "vbscript:",
    }

    # Encoding test payloads
    ENCODING_TESTS = {
        "url": ("%3C", "<"),  # URL encoded <
        "double_url": ("%253C", "<"),  # Double URL encoded <
        "html_entity": ("&lt;", "<"),  # HTML entity <
        "hex_entity": ("&#x3c;", "<"),  # Hex entity <
        "unicode": ("\\u003c", "<"),  # Unicode <
        "mixed_case": ("<ScRiPt>", "<script>"),  # Case variation
    }

    def __init__(self, http_client=None, timeout: float = 5.0):
        self.http_client = http_client
        self.timeout = timeout
        self._marker_base = self._generate_marker()

    def _generate_marker(self) -> str:
        """Generate unique marker for reflection detection"""
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"BRS_PROBE_{suffix}"

    async def probe_filters(
        self, url: str, parameters: Dict[str, str], http_client=None
    ) -> FilterProfile:
        """
        Probe target for input filtering.

        Args:
            url: Target URL
            parameters: Parameters to test
            http_client: HTTP client to use

        Returns:
            FilterProfile with detected filters
        """
        client = http_client or self.http_client
        if not client:
            logger.error("No HTTP client provided for filter probing")
            return FilterProfile()

        profile = FilterProfile()

        logger.info(f"Starting filter probe for {url}")

        # Find a reflectable parameter first
        test_param = await self._find_reflectable_parameter(url, parameters, client)
        if not test_param:
            logger.warning("No reflectable parameter found for filter probing")
            profile.filter_type = "unknown"
            profile.filter_strength = ProtectionStrength.MEDIUM
            return profile

        logger.debug(f"Using parameter '{test_param}' for filter probing")

        # Test characters
        char_results = await self._probe_characters(url, test_param, parameters, client)
        self._apply_char_results(profile, char_results)

        # Test tags
        tag_results = await self._probe_tags(url, test_param, parameters, client)
        self._apply_tag_results(profile, tag_results)

        # Test event handlers
        event_results = await self._probe_events(url, test_param, parameters, client)
        self._apply_event_results(profile, event_results)

        # Test keywords
        keyword_results = await self._probe_keywords(
            url, test_param, parameters, client
        )
        self._apply_keyword_results(profile, keyword_results)

        # Test protocols
        protocol_results = await self._probe_protocols(
            url, test_param, parameters, client
        )
        self._apply_protocol_results(profile, protocol_results)

        # Test encodings
        encoding_results = await self._probe_encodings(
            url, test_param, parameters, client
        )
        self._apply_encoding_results(profile, encoding_results)

        # Analyze and summarize
        self._analyze_profile(profile)

        logger.info(
            f"Filter probe complete: {profile.filter_type}, strength: {profile.filter_strength.value}"
        )

        return profile

    async def probe_reflection(
        self, url: str, parameters: Dict[str, str], http_client=None
    ) -> List[ParameterProfile]:
        """
        Probe parameters for reflection points.

        Args:
            url: Target URL
            parameters: Parameters to test
            http_client: HTTP client to use

        Returns:
            List of ParameterProfile with reflection info
        """
        client = http_client or self.http_client
        if not client:
            return []

        profiles = []

        for param_name, param_value in parameters.items():
            marker = f"{self._marker_base}_{param_name}"
            profile = await self._probe_single_parameter(
                url, param_name, marker, parameters, client
            )
            profiles.append(profile)

        return profiles

    async def _find_reflectable_parameter(
        self, url: str, parameters: Dict[str, str], client
    ) -> Optional[str]:
        """Find a parameter that reflects in response"""
        for param_name in parameters:
            marker = f"{self._marker_base}_test"
            test_params = parameters.copy()
            test_params[param_name] = marker

            try:
                response = await self._make_request(url, test_params, client)
                if response and marker in response:
                    return param_name
            except Exception as e:
                logger.debug(f"Error testing parameter {param_name}: {e}")

        # If no existing params reflect, try common ones
        common_params = ["q", "search", "query", "id", "name", "input", "text", "value"]
        for param_name in common_params:
            if param_name in parameters:
                continue

            marker = f"{self._marker_base}_test"
            test_params = parameters.copy()
            test_params[param_name] = marker

            try:
                response = await self._make_request(url, test_params, client)
                if response and marker in response:
                    return param_name
            except Exception:
                pass

        return None

    async def _probe_characters(
        self, url: str, param_name: str, base_params: Dict[str, str], client
    ) -> Dict[str, FilterStatus]:
        """Probe character filtering"""
        results = {}

        for char_name, char in self.CHAR_TESTS.items():
            marker = f"{self._marker_base}{char}END"
            test_params = base_params.copy()
            test_params[param_name] = marker

            try:
                response = await self._make_request(url, test_params, client)
                status = self._analyze_response(marker, char, response)
                results[char_name] = status
            except Exception as e:
                logger.debug(f"Error probing character {char_name}: {e}")
                results[char_name] = FilterStatus.ALLOWED  # Assume allowed on error

        return results

    async def _probe_tags(
        self, url: str, param_name: str, base_params: Dict[str, str], client
    ) -> Dict[str, FilterStatus]:
        """Probe tag filtering"""
        results = {}

        for tag_name, tag in self.TAG_TESTS.items():
            marker = f"{self._marker_base}{tag}END"
            test_params = base_params.copy()
            test_params[param_name] = marker

            try:
                response = await self._make_request(url, test_params, client)
                status = self._analyze_response(marker, tag, response)
                results[tag_name] = status
            except Exception:
                results[tag_name] = FilterStatus.ALLOWED

        return results

    async def _probe_events(
        self, url: str, param_name: str, base_params: Dict[str, str], client
    ) -> Dict[str, FilterStatus]:
        """Probe event handler filtering"""
        results = {}

        for event_name, event in self.EVENT_TESTS.items():
            marker = f"{self._marker_base} {event}x END"
            test_params = base_params.copy()
            test_params[param_name] = marker

            try:
                response = await self._make_request(url, test_params, client)
                status = self._analyze_response(marker, event, response)
                results[event_name] = status
            except Exception:
                results[event_name] = FilterStatus.ALLOWED

        return results

    async def _probe_keywords(
        self, url: str, param_name: str, base_params: Dict[str, str], client
    ) -> Dict[str, FilterStatus]:
        """Probe keyword filtering"""
        results = {}

        for keyword_name, keyword in self.KEYWORD_TESTS.items():
            marker = f"{self._marker_base}{keyword}END"
            test_params = base_params.copy()
            test_params[param_name] = marker

            try:
                response = await self._make_request(url, test_params, client)
                status = self._analyze_response(marker, keyword, response)
                results[keyword_name] = status
            except Exception:
                results[keyword_name] = FilterStatus.ALLOWED

        return results

    async def _probe_protocols(
        self, url: str, param_name: str, base_params: Dict[str, str], client
    ) -> Dict[str, FilterStatus]:
        """Probe protocol filtering"""
        results = {}

        for protocol_name, protocol in self.PROTOCOL_TESTS.items():
            marker = f"{self._marker_base}{protocol}x END"
            test_params = base_params.copy()
            test_params[param_name] = marker

            try:
                response = await self._make_request(url, test_params, client)
                status = self._analyze_response(marker, protocol, response)
                results[protocol_name] = status
            except Exception:
                results[protocol_name] = FilterStatus.ALLOWED

        return results

    async def _probe_encodings(
        self, url: str, param_name: str, base_params: Dict[str, str], client
    ) -> Dict[str, bool]:
        """Probe encoding acceptance"""
        results = {}

        for encoding_name, (encoded, decoded) in self.ENCODING_TESTS.items():
            marker = f"{self._marker_base}{encoded}END"
            test_params = base_params.copy()
            test_params[param_name] = marker

            try:
                response = await self._make_request(url, test_params, client)

                # Check if encoded version was decoded
                if response:
                    decoded_marker = f"{self._marker_base}{decoded}END"
                    if decoded_marker in response:
                        results[encoding_name] = True  # Decoded
                    elif marker in response:
                        results[encoding_name] = False  # Not decoded (kept encoded)
                    else:
                        results[encoding_name] = False  # Blocked or modified
                else:
                    results[encoding_name] = False
            except Exception:
                results[encoding_name] = False

        return results

    async def _probe_single_parameter(
        self,
        url: str,
        param_name: str,
        marker: str,
        base_params: Dict[str, str],
        client,
    ) -> ParameterProfile:
        """Probe single parameter for reflection"""
        profile = ParameterProfile(name=param_name)

        test_params = base_params.copy()
        test_params[param_name] = marker

        try:
            response = await self._make_request(url, test_params, client)

            if response and marker in response:
                profile.reflected = True
                profile.reflection_points = self._find_reflection_contexts(
                    response, marker
                )

                if profile.reflection_points:
                    # Determine best context
                    contexts = [rp.context for rp in profile.reflection_points]
                    if "javascript" in contexts:
                        profile.best_context = "javascript"
                    elif "html_attribute" in contexts:
                        profile.best_context = "html_attribute"
                    elif "html_content" in contexts:
                        profile.best_context = "html_content"
                    else:
                        profile.best_context = contexts[0] if contexts else "unknown"
        except Exception as e:
            logger.debug(f"Error probing parameter {param_name}: {e}")

        return profile

    async def _make_request(
        self, url: str, params: Dict[str, str], client
    ) -> Optional[str]:
        """Make HTTP request with parameters"""
        try:
            # Build URL with params
            parsed = urlparse(url)
            existing_params = parse_qs(parsed.query)

            # Merge params
            for key, value in params.items():
                existing_params[key] = [value]

            query_string = urlencode(existing_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if query_string:
                test_url += f"?{query_string}"

            response = await asyncio.wait_for(
                client.get(test_url), timeout=self.timeout
            )

            return response.text if response else None
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None

    def _analyze_response(
        self, original_marker: str, test_payload: str, response: Optional[str]
    ) -> FilterStatus:
        """Analyze response to determine filter status"""
        if not response:
            return FilterStatus.BLOCKED

        # Check if original marker is in response
        if original_marker in response:
            return FilterStatus.ALLOWED

        # Check for the marker base (payload might be modified)
        marker_base = self._marker_base
        if marker_base not in response:
            return FilterStatus.BLOCKED

        # Check if payload was encoded
        encoded_variants = {
            "<": ["&lt;", "&#60;", "&#x3c;", "%3C", "%3c"],
            ">": ["&gt;", "&#62;", "&#x3e;", "%3E", "%3e"],
            '"': ["&quot;", "&#34;", "&#x22;", "%22"],
            "'": ["&#39;", "&#x27;", "%27"],
            "&": ["&amp;", "&#38;", "&#x26;", "%26"],
        }

        for char, variants in encoded_variants.items():
            if char in test_payload:
                for variant in variants:
                    if variant in response:
                        return FilterStatus.ENCODED

        # Check if payload was stripped
        if marker_base in response and test_payload not in response:
            # The marker is there but the payload part is missing
            return FilterStatus.STRIPPED

        return FilterStatus.MODIFIED

    def _find_reflection_contexts(
        self, response: str, marker: str
    ) -> List[ReflectionPoint]:
        """Find all reflection contexts for marker"""
        points = []

        start = 0
        while True:
            pos = response.find(marker, start)
            if pos == -1:
                break

            # Get surrounding context
            context_start = max(0, pos - 100)
            context_end = min(len(response), pos + len(marker) + 100)
            surrounding = response[context_start:context_end]

            # Determine context type
            context = self._determine_context(response, pos, marker)

            # Calculate line number
            line_number = response[:pos].count("\n") + 1

            point = ReflectionPoint(
                context=context,
                position=pos,
                line_number=line_number,
                surrounding_code=surrounding,
                is_encoded=False,
            )

            # Check for encoding in surrounding
            if "&lt;" in surrounding or "&gt;" in surrounding or "&#" in surrounding:
                point.is_encoded = True
                point.encoding_type = "html_entities"

            points.append(point)
            start = pos + 1

        return points

    def _determine_context(self, response: str, pos: int, marker: str) -> str:
        """Determine the context of reflection"""
        # Get preceding content
        before = response[max(0, pos - 500) : pos]
        response[pos + len(marker) : min(len(response), pos + len(marker) + 500)]

        # Check for script context
        if "<script" in before.lower():
            # Find last script tag
            script_start = before.lower().rfind("<script")
            # Check if there's a closing script tag after that
            after_script = before[script_start:]
            if "</script>" not in after_script.lower():
                return "javascript"

        # Check for attribute context
        # Look for pattern like: attribute="...MARKER..."
        import re

        attr_pattern = r'[\w-]+\s*=\s*["\'][^"\']*$'
        if re.search(attr_pattern, before):
            # Determine quote character
            if before.rstrip().endswith('"'):
                return "html_attribute_double"
            elif before.rstrip().endswith("'"):
                return "html_attribute_single"
            return "html_attribute"

        # Check for style context
        if "<style" in before.lower():
            style_start = before.lower().rfind("<style")
            after_style = before[style_start:]
            if "</style>" not in after_style.lower():
                return "css"

        # Check for comment context
        if "<!--" in before:
            comment_start = before.rfind("<!--")
            if "-->" not in before[comment_start:]:
                return "html_comment"

        # Check for URL context
        if "href=" in before[-50:].lower() or "src=" in before[-50:].lower():
            return "url"

        # Default to HTML content
        return "html_content"

    def _apply_char_results(
        self, profile: FilterProfile, results: Dict[str, FilterStatus]
    ):
        """Apply character test results to profile"""
        profile.char_less_than = results.get("less_than", FilterStatus.ALLOWED)
        profile.char_greater_than = results.get("greater_than", FilterStatus.ALLOWED)
        profile.char_double_quote = results.get("double_quote", FilterStatus.ALLOWED)
        profile.char_single_quote = results.get("single_quote", FilterStatus.ALLOWED)
        profile.char_backtick = results.get("backtick", FilterStatus.ALLOWED)
        profile.char_slash = results.get("slash", FilterStatus.ALLOWED)
        profile.char_backslash = results.get("backslash", FilterStatus.ALLOWED)
        profile.char_parenthesis_open = results.get(
            "parenthesis_open", FilterStatus.ALLOWED
        )
        profile.char_parenthesis_close = results.get(
            "parenthesis_close", FilterStatus.ALLOWED
        )
        profile.char_curly_open = results.get("curly_open", FilterStatus.ALLOWED)
        profile.char_curly_close = results.get("curly_close", FilterStatus.ALLOWED)

    def _apply_tag_results(
        self, profile: FilterProfile, results: Dict[str, FilterStatus]
    ):
        """Apply tag test results to profile"""
        profile.tag_script = results.get("script", FilterStatus.ALLOWED)
        profile.tag_img = results.get("img", FilterStatus.ALLOWED)
        profile.tag_svg = results.get("svg", FilterStatus.ALLOWED)
        profile.tag_iframe = results.get("iframe", FilterStatus.ALLOWED)
        profile.tag_object = results.get("object", FilterStatus.ALLOWED)
        profile.tag_embed = results.get("embed", FilterStatus.ALLOWED)
        profile.tag_form = results.get("form", FilterStatus.ALLOWED)
        profile.tag_input = results.get("input", FilterStatus.ALLOWED)
        profile.tag_body = results.get("body", FilterStatus.ALLOWED)
        profile.tag_style = results.get("style", FilterStatus.ALLOWED)
        profile.tag_link = results.get("link", FilterStatus.ALLOWED)
        profile.tag_meta = results.get("meta", FilterStatus.ALLOWED)
        profile.tag_base = results.get("base", FilterStatus.ALLOWED)
        profile.tag_math = results.get("math", FilterStatus.ALLOWED)
        profile.tag_video = results.get("video", FilterStatus.ALLOWED)
        profile.tag_audio = results.get("audio", FilterStatus.ALLOWED)
        profile.tag_details = results.get("details", FilterStatus.ALLOWED)
        profile.tag_marquee = results.get("marquee", FilterStatus.ALLOWED)

    def _apply_event_results(
        self, profile: FilterProfile, results: Dict[str, FilterStatus]
    ):
        """Apply event handler test results to profile"""
        profile.event_onerror = results.get("onerror", FilterStatus.ALLOWED)
        profile.event_onload = results.get("onload", FilterStatus.ALLOWED)
        profile.event_onclick = results.get("onclick", FilterStatus.ALLOWED)
        profile.event_onmouseover = results.get("onmouseover", FilterStatus.ALLOWED)
        profile.event_onfocus = results.get("onfocus", FilterStatus.ALLOWED)
        profile.event_onblur = results.get("onblur", FilterStatus.ALLOWED)
        profile.event_oninput = results.get("oninput", FilterStatus.ALLOWED)
        profile.event_onchange = results.get("onchange", FilterStatus.ALLOWED)
        profile.event_onsubmit = results.get("onsubmit", FilterStatus.ALLOWED)
        profile.event_onanimationend = results.get(
            "onanimationend", FilterStatus.ALLOWED
        )
        profile.event_ontoggle = results.get("ontoggle", FilterStatus.ALLOWED)
        profile.event_onpointerover = results.get("onpointerover", FilterStatus.ALLOWED)

    def _apply_keyword_results(
        self, profile: FilterProfile, results: Dict[str, FilterStatus]
    ):
        """Apply keyword test results to profile"""
        profile.keyword_alert = results.get("alert", FilterStatus.ALLOWED)
        profile.keyword_prompt = results.get("prompt", FilterStatus.ALLOWED)
        profile.keyword_confirm = results.get("confirm", FilterStatus.ALLOWED)
        profile.keyword_eval = results.get("eval", FilterStatus.ALLOWED)
        profile.keyword_document = results.get("document", FilterStatus.ALLOWED)
        profile.keyword_window = results.get("window", FilterStatus.ALLOWED)
        profile.keyword_location = results.get("location", FilterStatus.ALLOWED)
        profile.keyword_cookie = results.get("cookie", FilterStatus.ALLOWED)
        profile.keyword_innerhtml = results.get("innerhtml", FilterStatus.ALLOWED)
        profile.keyword_script = results.get("script", FilterStatus.ALLOWED)
        profile.keyword_javascript = results.get("javascript", FilterStatus.ALLOWED)
        profile.keyword_expression = results.get("expression", FilterStatus.ALLOWED)

    def _apply_protocol_results(
        self, profile: FilterProfile, results: Dict[str, FilterStatus]
    ):
        """Apply protocol test results to profile"""
        profile.protocol_javascript = results.get("javascript", FilterStatus.ALLOWED)
        profile.protocol_data = results.get("data", FilterStatus.ALLOWED)
        profile.protocol_vbscript = results.get("vbscript", FilterStatus.ALLOWED)

    def _apply_encoding_results(self, profile: FilterProfile, results: Dict[str, bool]):
        """Apply encoding test results to profile"""
        profile.encoding_url_decoded = results.get("url", True)
        profile.encoding_double_url_decoded = results.get("double_url", False)
        profile.encoding_html_entities_decoded = results.get("html_entity", True)
        profile.encoding_hex_entities_decoded = results.get("hex_entity", True)
        profile.encoding_unicode_decoded = results.get("unicode", False)
        profile.encoding_case_sensitive = not results.get("mixed_case", False)

    def _analyze_profile(self, profile: FilterProfile):
        """Analyze filter profile and generate summary"""
        blocked_count = 0
        encoded_count = 0
        allowed_count = 0

        # Count status of key elements
        key_elements = [
            profile.char_less_than,
            profile.char_greater_than,
            profile.tag_script,
            profile.tag_img,
            profile.tag_svg,
            profile.event_onerror,
            profile.event_onload,
            profile.keyword_alert,
            profile.keyword_javascript,
            profile.protocol_javascript,
        ]

        for status in key_elements:
            if status == FilterStatus.BLOCKED or status == FilterStatus.STRIPPED:
                blocked_count += 1
            elif status == FilterStatus.ENCODED:
                encoded_count += 1
            else:
                allowed_count += 1

        total = len(key_elements)

        # Determine filter type
        if blocked_count > total * 0.7:
            profile.filter_type = "blacklist_strict"
            profile.filter_strength = ProtectionStrength.STRONG
        elif blocked_count > total * 0.5:
            profile.filter_type = "blacklist_moderate"
            profile.filter_strength = ProtectionStrength.MEDIUM
        elif encoded_count > total * 0.5:
            profile.filter_type = "encoding_based"
            profile.filter_strength = ProtectionStrength.MEDIUM
        elif blocked_count > 0 or encoded_count > 0:
            profile.filter_type = "blacklist_weak"
            profile.filter_strength = ProtectionStrength.WEAK
        else:
            profile.filter_type = "none"
            profile.filter_strength = ProtectionStrength.NONE

        # Determine bypassability
        profile.is_bypassable = (
            profile.filter_strength != ProtectionStrength.VERY_STRONG
        )

        # Generate bypass techniques
        bypass_techniques = []

        if profile.encoding_double_url_decoded:
            bypass_techniques.append("Double URL encoding")
        if profile.encoding_unicode_decoded:
            bypass_techniques.append("Unicode encoding")
        if not profile.encoding_case_sensitive:
            bypass_techniques.append("Case variation")

        # Check for allowed vectors
        if profile.tag_svg == FilterStatus.ALLOWED:
            bypass_techniques.append("SVG-based payloads")
        if profile.tag_img == FilterStatus.ALLOWED:
            bypass_techniques.append("IMG tag with event handlers")
        if profile.tag_details == FilterStatus.ALLOWED:
            bypass_techniques.append("Details/Summary with ontoggle")
        if profile.event_onload == FilterStatus.ALLOWED:
            bypass_techniques.append("onload event handler")
        if profile.event_onfocus == FilterStatus.ALLOWED:
            bypass_techniques.append("onfocus event handler with autofocus")
        if (
            profile.keyword_prompt == FilterStatus.ALLOWED
            and profile.keyword_alert == FilterStatus.BLOCKED
        ):
            bypass_techniques.append("prompt() instead of alert()")

        profile.bypass_techniques = bypass_techniques

        # Determine best vector
        if (
            profile.tag_svg == FilterStatus.ALLOWED
            and profile.event_onload == FilterStatus.ALLOWED
        ):
            profile.best_vector = "<svg onload=...>"
        elif (
            profile.tag_img == FilterStatus.ALLOWED
            and profile.event_onerror == FilterStatus.ALLOWED
        ):
            profile.best_vector = "<img src=x onerror=...>"
        elif profile.tag_details == FilterStatus.ALLOWED:
            profile.best_vector = "<details ontoggle=...>"
        elif (
            profile.tag_body == FilterStatus.ALLOWED
            and profile.event_onload == FilterStatus.ALLOWED
        ):
            profile.best_vector = "<body onload=...>"
        else:
            profile.best_vector = "Encoding-based bypass required"

        # Determine best encoding
        if profile.encoding_double_url_decoded:
            profile.best_encoding = "Double URL encoding"
        elif profile.encoding_unicode_decoded:
            profile.best_encoding = "Unicode"
        elif not profile.encoding_case_sensitive:
            profile.best_encoding = "Mixed case"
        else:
            profile.best_encoding = "Standard"
