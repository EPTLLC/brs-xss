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

from fastapi import FastAPI
from ..models import DashboardStats


def register(app: FastAPI, storage):
    """Register dashboard routes"""

    @app.get("/api/dashboard", response_model=DashboardStats)
    async def get_dashboard():
        """Get dashboard statistics"""
        return storage.get_dashboard_stats()
