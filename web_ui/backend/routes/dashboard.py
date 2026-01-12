#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 23:10:02 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Dashboard routes.
"""

from typing import Optional
from fastapi import FastAPI, Header
from ..models import DashboardStats
from .auth import get_current_user


def register(app: FastAPI, storage):
    """Register dashboard routes"""

    def _get_user_id(authorization: Optional[str]) -> Optional[str]:
        """Extract user_id from auth header if auth is enabled"""
        config = storage.get_auth_config()
        if not config.auth_enabled:
            return None
        user = get_current_user(authorization)
        return user.id if user else None

    @app.get("/api/dashboard", response_model=DashboardStats)
    async def get_dashboard(authorization: Optional[str] = Header(None)):
        """Get dashboard statistics (user-specific if auth enabled)"""
        user_id = _get_user_id(authorization)
        return storage.get_dashboard_stats(user_id=user_id)
