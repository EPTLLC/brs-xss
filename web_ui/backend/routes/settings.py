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

from fastapi import FastAPI
from ..models import SettingsModel


def register(app: FastAPI, storage):
    """Register settings routes"""

    @app.get("/api/settings", response_model=SettingsModel)
    async def get_settings():
        """Get application settings"""
        return storage.get_settings()

    @app.put("/api/settings", response_model=SettingsModel)
    async def update_settings(settings: SettingsModel):
        """Update application settings"""
        storage.save_settings(settings)
        return settings
