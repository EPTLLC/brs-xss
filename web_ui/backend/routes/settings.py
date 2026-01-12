#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 23:10:02 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Settings routes.
"""

from typing import Optional
from fastapi import FastAPI, Header
from ..models import SettingsModel
from .auth import get_current_user


def register(app: FastAPI, storage):
    """Register settings routes"""

    def _get_user_id(authorization: Optional[str]) -> Optional[str]:
        """Extract user_id from auth header if auth is enabled"""
        config = storage.get_auth_config()
        if not config.auth_enabled:
            return None
        user = get_current_user(authorization)
        return user.id if user else None

    @app.get("/api/settings", response_model=SettingsModel)
    async def get_settings(authorization: Optional[str] = Header(None)):
        """Get application settings (user-specific if auth enabled)"""
        user_id = _get_user_id(authorization)
        return storage.get_settings(user_id=user_id)

    @app.put("/api/settings", response_model=SettingsModel)
    async def update_settings(settings: SettingsModel, authorization: Optional[str] = Header(None)):
        """Update application settings (user-specific if auth enabled)"""
        user_id = _get_user_id(authorization)
        storage.save_settings(settings, user_id=user_id)
        return settings
