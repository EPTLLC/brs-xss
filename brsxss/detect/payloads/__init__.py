#!/usr/bin/env python3

"""
Project: BRS-XSS v3.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 25 Dec 2025 UTC
Status: Updated
Telegram: https://t.me/EasyProTech

BRS-XSS Payload Module
All payloads are stored in BRS-KB (BRS XSS Knowledge Base).
This module provides the PayloadManager interface.
"""

from .payload_manager import PayloadManager
from .kb_adapter import KBAdapter, get_kb_adapter, kb_available
from .context_matrix import ContextMatrix, Context

__all__ = [
    "PayloadManager",
    "KBAdapter",
    "get_kb_adapter",
    "kb_available",
    "ContextMatrix",
    "Context",
]
