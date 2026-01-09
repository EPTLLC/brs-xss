#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 23:10:02 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Routes module initialization.
"""

from fastapi import FastAPI
from . import dashboard, scans, settings, proxy, telegram, system, kb, static, websocket


def register_routes(
    app: FastAPI, storage, scanner_service, ws_manager, static_dir=None
):
    """Register all route modules"""
    dashboard.register(app, storage)
    scans.register(app, storage, scanner_service)
    settings.register(app, storage)
    proxy.register(app, storage)
    telegram.register(app, storage)
    system.register(app, scanner_service)
    kb.register(app)
    websocket.register(app, ws_manager)
    static.register(app, static_dir)
