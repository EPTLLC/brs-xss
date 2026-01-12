#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Updated - Remote API support
Telegram: https://t.me/EasyProTech

Payload Manager - Central manager for XSS payloads.
Uses BRS-KB (BRS XSS Knowledge Base) as the ONLY source of payloads.
Supports both remote API and local library modes.
"""

from typing import Optional, Any
import random

from .kb_adapter import get_kb_adapter, KBAdapter


class PayloadManager:
    """
    Central payload manager using BRS-KB as the only source.

    All payloads are stored in BRS-KB (BRS XSS Knowledge Base).
    This manager provides convenient access methods.

    Configuration is loaded from:
    1. config/default.yaml (kb section)
    2. Environment variables (BRSXSS_KB_*)
    """

    def __init__(self, config_data: Optional[dict] = None):
        """
        Initialize PayloadManager with BRS-KB connection.

        Args:
            config_data: Optional configuration dictionary with 'kb' section
        """
        self._kb: KBAdapter = get_kb_adapter(config_data)
        self.using_kb: bool = self._kb.is_available
        self.kb_adapter: KBAdapter = self._kb  # Alias for compatibility

        if not self.using_kb:
            print(
                "[PayloadManager] WARNING: BRS-KB not available. Limited functionality."
            )

    @property
    def kb(self) -> KBAdapter:
        """Get KB adapter"""
        return self._kb

    @property
    def mode(self) -> str:
        """Get current KB mode (remote/local/none)"""
        return self._kb.mode

    def get_all_payloads(self) -> list[str]:
        """Get all payloads from BRS-KB"""
        return self._kb.get_all_payloads()

    def get_random_payloads(self, count: int = 50) -> list[str]:
        """Get random payloads"""
        payloads = self.get_all_payloads()
        if count >= len(payloads):
            return payloads
        return random.sample(payloads, count)

    def get_context_payloads(self, context: str) -> list[str]:
        """Get payloads suitable for a specific context"""
        return self._kb.get_payloads_by_context(context)

    def get_waf_bypass_payloads(self, waf_type: Optional[str] = None) -> list[str]:
        """Get WAF bypass payloads, optionally filtered by WAF name"""
        return self._kb.get_waf_bypass_payloads(waf_type)

    def get_websocket_payloads(self) -> list[str]:
        """Get WebSocket-specific payloads"""
        return self._kb.get_websocket_payloads()

    def get_graphql_payloads(self) -> list[str]:
        """Get GraphQL-specific payloads"""
        return self._kb.get_graphql_payloads()

    def get_sse_payloads(self) -> list[str]:
        """Get Server-Sent Events payloads"""
        return self._kb.get_sse_payloads()

    def get_modern_browser_payloads(self) -> list[str]:
        """Get modern browser payloads (ES6+, WebAssembly, etc.)"""
        return self._kb.get_modern_browser_payloads()

    def get_exotic_payloads(self) -> list[str]:
        """Get exotic payloads (mXSS, DOM clobbering, etc.)"""
        return self._kb.get_exotic_payloads()

    def get_payloads_by_tag(self, tag: str) -> list[str]:
        """Get payloads with a specific tag"""
        return self._kb.get_payloads_by_tag(tag)

    def get_payloads_by_severity(self, severity: str) -> list[str]:
        """Get payloads by severity level"""
        return self._kb.get_payloads_by_severity(severity)

    def search_payloads(self, term: str, case_sensitive: bool = False) -> list[str]:
        """Search payloads by term"""
        return self._kb.search(term, case_sensitive)

    def get_payload_statistics(self) -> dict[str, Any]:
        """Get statistics about the payload database"""
        return self._kb.get_statistics()

    def get_top_payloads(self, count: int = 20) -> list[str]:
        """Get most effective XSS payloads"""
        top_payloads = []
        seen = set()

        # Get high severity first (most effective)
        high_sev = self._kb.get_payloads_by_severity("critical")
        for p in high_sev[: count // 2]:
            if p not in seen:
                seen.add(p)
                top_payloads.append(p)

        # Add high severity
        high = self._kb.get_payloads_by_severity("high")
        for p in high[: count // 4]:
            if p not in seen:
                seen.add(p)
                top_payloads.append(p)

        # Fill remaining with polyglots
        polyglots = self._kb.get_payloads_by_tag("polyglot")
        for p in polyglots:
            if p not in seen and len(top_payloads) < count:
                seen.add(p)
                top_payloads.append(p)

        return top_payloads[:count]

    def validate_payload(self, payload: str) -> dict[str, bool]:
        """Basic validation of a payload"""
        payload_lower = payload.lower()
        return {
            "has_script_tag": "<script" in payload_lower,
            "has_event_handler": any(
                event in payload_lower
                for event in [
                    "onclick",
                    "onload",
                    "onerror",
                    "onmouseover",
                    "onfocus",
                    "onblur",
                    "onchange",
                ]
            ),
            "has_javascript_protocol": "javascript:" in payload_lower,
            "has_data_uri": "data:" in payload_lower,
            "has_eval": "eval(" in payload_lower,
            "has_alert": "alert(" in payload_lower,
            "potentially_dangerous": any(
                danger in payload_lower
                for danger in [
                    "document.cookie",
                    "document.domain",
                    "location.href",
                    "window.location",
                ]
            ),
        }

    def get_context_details(self, context_id: str) -> Optional[dict[str, Any]]:
        """Get detailed context information (remote API only)"""
        return self._kb.get_context_details(context_id)

    def get_defenses(self, context_id: str) -> Optional[dict[str, Any]]:
        """Get defense recommendations for a context (remote API only)"""
        return self._kb.get_defenses(context_id)

    def analyze_payload(self, payload: str) -> Optional[dict[str, Any]]:
        """Analyze a payload using BRS-KB API (remote API only)"""
        return self._kb.analyze_payload(payload)
