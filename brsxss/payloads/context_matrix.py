#!/usr/bin/env python3

"""
Project: BRS-XSS v3.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 25 Dec 2025 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Context Matrix - Context-aware payload selection using BRS-KB.
"""

from enum import Enum
from typing import List
from .kb_adapter import get_kb_adapter


class Context(Enum):
    """XSS injection context types"""

    HTML = "html"
    ATTRIBUTE = "attribute"
    JAVASCRIPT = "javascript"
    CSS = "css"
    URI = "uri"
    SVG = "svg"


class ContextMatrix:
    """Context-aware payload matrix using BRS-KB as source."""

    def __init__(self):
        self._kb = get_kb_adapter()

    def get_context_payloads(self, context: Context) -> List[str]:
        """Get payloads for a specific context"""
        context_mapping = {
            Context.HTML: "HTML_CONTENT",
            Context.ATTRIBUTE: "HTML_ATTRIBUTE",
            Context.JAVASCRIPT: "JS_STRING",
            Context.CSS: "CSS",
            Context.URI: "URL",
            Context.SVG: "SVG",
        }
        kb_context = context_mapping.get(context, "HTML_CONTENT")
        return self._kb.get_payloads_by_context(kb_context)

    def get_polyglot_payloads(self) -> List[str]:
        """Get polyglot payloads (work across multiple contexts)"""
        return self._kb.get_payloads_by_tag("polyglot")

    def get_aggr_payloads(self) -> List[str]:
        """Get aggressive payloads"""
        return self._kb.get_payloads_by_severity("high")

    def get_all_contexts(self) -> List[Context]:
        """Get all available contexts"""
        return list(Context)

    def get_payload_count(self, context: Context) -> int:
        """Get payload count for a specific context"""
        return len(self.get_context_payloads(context))

    def get_total_payload_count(self) -> dict:
        """Get total payload counts by category"""
        context_specific = sum(len(self.get_context_payloads(ctx)) for ctx in Context)
        polyglot = len(self.get_polyglot_payloads())
        aggressive = len(self.get_aggr_payloads())
        return {
            "context_specific": context_specific,
            "polyglot": polyglot,
            "aggressive": aggressive,
        }
