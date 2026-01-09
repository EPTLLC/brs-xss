#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 23:10:02 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Static files serving routes.
"""

from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse


def register(app: FastAPI, static_dir: Optional[str] = None):
    """Register static file routes"""

    if not static_dir:
        return

    app.mount(
        "/assets",
        StaticFiles(directory=str(Path(static_dir) / "assets")),
        name="assets",
    )

    @app.get("/shield.svg")
    async def serve_favicon():
        return FileResponse(str(Path(static_dir) / "shield.svg"))

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        """Serve SPA for all non-API routes"""
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")

        index_path = Path(static_dir) / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
        raise HTTPException(status_code=404, detail="index.html not found")
