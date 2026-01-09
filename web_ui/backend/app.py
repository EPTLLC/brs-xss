#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 23:10:02 UTC
Status: Modified
Telegram: https://t.me/EasyProTech

FastAPI application for BRS-XSS Web UI.
Single-user mode - no authentication required.
"""

from typing import Optional
from pathlib import Path
import shutil

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .models import ScanProgress, VulnerabilityInfo
from .storage import ScanStorage
from .scanner_service import ScannerService
from .websocket_manager import ConnectionManager
from .routes import register_routes


def _resolve_db_path(db_path: Optional[str]) -> Path:
    """
    Resolve database path to an absolute location inside the project.

    Strategy:
    - Prefer <project_root>/brsxss_ui.db (shared between launch methods)
    - If legacy file exists under web_ui/backend/, migrate/copy it
    - Always create parent directories to keep path valid
    """
    module_dir = Path(__file__).resolve().parent
    project_root = module_dir.parent.parent

    candidate_name = Path(db_path) if db_path else Path("brsxss_ui.db")
    preferred = (
        candidate_name
        if candidate_name.is_absolute()
        else project_root / candidate_name
    )

    if preferred.exists():
        return preferred

    legacy = module_dir / candidate_name.name
    if legacy.exists() and not preferred.exists():
        try:
            preferred.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(legacy, preferred)
            return preferred
        except Exception:
            return legacy

    preferred.parent.mkdir(parents=True, exist_ok=True)
    return preferred


def create_app(
    db_path: Optional[str] = None, static_dir: Optional[str] = None
) -> FastAPI:
    """Create and configure FastAPI application"""

    app = FastAPI(
        title="BRS-XSS Web UI",
        description="Web interface for BRS-XSS vulnerability scanner",
        version="3.0.0",
    )

    # CORS for development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    resolved_db_path = _resolve_db_path(db_path or "brsxss_ui.db")

    # Initialize components
    storage = ScanStorage(str(resolved_db_path))
    ws_manager = ConnectionManager()

    # Progress callback for WebSocket
    async def on_progress(progress: ScanProgress):
        await ws_manager.broadcast({"type": "progress", "data": progress.model_dump()})

    # Vulnerability callback for WebSocket
    async def on_vulnerability(scan_id: str, vuln: VulnerabilityInfo):
        await ws_manager.broadcast(
            {"type": "vulnerability", "scan_id": scan_id, "data": vuln.model_dump()}
        )

    # Reconnaissance callback for WebSocket
    async def on_recon(scan_id: str, data: dict):
        await ws_manager.broadcast(
            {"type": "reconnaissance", "scan_id": scan_id, "data": data}
        )

    scanner_service = ScannerService(
        storage=storage,
        progress_callback=on_progress,
        vulnerability_callback=on_vulnerability,
        recon_callback=on_recon,
    )

    # Initialize Telegram from saved settings
    async def init_telegram():
        """Load Telegram configuration from saved settings"""
        try:
            settings = storage.get_settings()
            if (
                settings.telegram_enabled
                and settings.telegram_bot_token
                and settings.telegram_channel_id
            ):
                from brsxss.integrations.telegram_service import telegram_service

                await telegram_service.configure(
                    bot_token=settings.telegram_bot_token,
                    channel_id=settings.telegram_channel_id,
                )
        except Exception as e:
            print(f"[WARN] Failed to initialize Telegram: {e}")

    @app.on_event("startup")
    async def startup_event():
        await init_telegram()

    # Register all routes
    register_routes(
        app=app,
        storage=storage,
        scanner_service=scanner_service,
        ws_manager=ws_manager,
        static_dir=static_dir,
    )

    return app


# For uvicorn
# Auto-detect static directory
_backend_dir = Path(__file__).parent
_static_dir = _backend_dir.parent / "frontend" / "dist"

app = create_app(static_dir=str(_static_dir) if _static_dir.exists() else None)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
