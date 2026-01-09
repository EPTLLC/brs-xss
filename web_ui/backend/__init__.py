#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 25 Dec 2025 13:30:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

FastAPI backend for BRS-XSS Web UI.
Single-user mode (no auth required).
"""

from .app import create_app
from .models import ScanRequest, ScanResult, ScanStatus

__all__ = [
    "create_app",
    "ScanRequest",
    "ScanResult",
    "ScanStatus",
]
