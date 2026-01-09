#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Updated - Uses KBAdapter for remote API
Telegram: https://t.me/EasyProTech

Knowledge Base routes.
"""

from typing import Optional
from fastapi import FastAPI, Query


def register(app: FastAPI):
    """Register KB routes"""

    @app.get("/api/kb/stats")
    async def get_kb_stats():
        """Get BRS-KB statistics - data from remote API via KBAdapter"""
        try:
            from brsxss.payloads.kb_adapter import get_kb_adapter

            # Get statistics from KB API
            kb = get_kb_adapter()
            stats = kb.get_statistics()

            if not stats.get("available", False):
                raise Exception("KB API not available")

            # Get KB info from /info endpoint
            kb_info = kb.get_kb_info() if hasattr(kb, "get_kb_info") else {}

            return {
                "name": "BRS-KB",
                "full_name": "BRS XSS Knowledge Base",
                "version": kb_info.get("version", kb.get_kb_version()),
                "build": kb_info.get("build", "unknown"),
                "revision": kb_info.get("revision", "stable"),
                "author": kb_info.get("author", "Brabus"),
                "company": kb_info.get("company", "EasyProTech LLC"),
                "website": kb_info.get("website", "https://www.easypro.tech"),
                "license": kb_info.get("license", "MIT"),
                "repo_url": kb_info.get("repo_url", "https://github.com/EPTLLC/BRS-KB"),
                "telegram": kb_info.get("telegram", "https://t.me/EasyProTech"),
                "total_payloads": stats.get("total_payloads", 0),
                "contexts": stats.get("total_contexts", 0),
                "waf_bypass_count": stats.get("waf_bypass_count", 0),
                "available_contexts": list(stats.get("context_coverage", {}).keys()),
                "severity_distribution": stats.get("severity_distribution", {}),
                "mode": stats.get("mode", "remote"),
                "api_url": stats.get("api_url", "https://brs-kb.easypro.tech/api/v1"),
            }
        except Exception as e:
            # Return error status instead of fake data
            return {
                "error": True,
                "error_message": f"Connection to Knowledge Base failed: {str(e)}",
                "name": "BRS-KB",
                "full_name": "BRS XSS Knowledge Base",
                "version": None,
                "total_payloads": None,
                "contexts": None,
                "waf_bypass_count": None,
                "available": False,
            }

    @app.get("/api/kb/payloads")
    async def get_kb_payloads(
        category: Optional[str] = None,
        limit: int = Query(50, le=500),
        offset: int = Query(0, ge=0),
    ):
        """Get payloads from BRS-KB"""
        from brsxss.payloads import PayloadManager

        pm = PayloadManager()

        if category == "waf_bypass":
            payloads = pm.get_waf_bypass_payloads()
        elif category == "websocket":
            payloads = pm.get_websocket_payloads()
        elif category == "graphql":
            payloads = pm.get_graphql_payloads()
        elif category == "sse":
            payloads = pm.get_sse_payloads()
        elif category == "modern_browser":
            payloads = pm.get_modern_browser_payloads()
        elif category == "exotic":
            payloads = pm.get_exotic_payloads()
        else:
            payloads = pm.get_all_payloads()

        total = len(payloads)
        payloads = payloads[offset : offset + limit]

        return {"payloads": payloads, "total": total, "offset": offset, "limit": limit}
