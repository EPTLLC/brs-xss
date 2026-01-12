#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 UTC
Status: Updated - Added auth routes
Telegram: https://t.me/EasyProTech

Routes module initialization.
"""

from fastapi import FastAPI
from . import dashboard, scans, settings, proxy, telegram, system, kb, static, websocket
from .auth import router as auth_router
from .payloads import router as payloads_router
from .domains import router as domains_router
from .workflows import router as workflows_router
from .strategy import router as strategy_router


def register_routes(
    app: FastAPI, storage, scanner_service, ws_manager, static_dir=None
):
    """Register all route modules"""
    # Auth routes (no storage injection - uses get_storage())
    app.include_router(auth_router, prefix="/api")
    # Payloads routes
    app.include_router(payloads_router, prefix="/api")
    # Domains routes (domain profiles)
    app.include_router(domains_router)
    # Workflows routes
    app.include_router(workflows_router)
    # Strategy routes (PTT)
    app.include_router(strategy_router)
    
    dashboard.register(app, storage)
    scans.register(app, storage, scanner_service)
    settings.register(app, storage)
    proxy.register(app, storage)
    telegram.register(app, storage)
    system.register(app, scanner_service)
    kb.register(app)
    websocket.register(app, ws_manager)
    static.register(app, static_dir)
