#!/usr/bin/env python3

"""
Project: BRS-XSS Blind XSS Callback Server
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 25 Dec 2025 12:30:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Data models for Blind XSS callback server.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import uuid


class PayloadInfo(BaseModel):
    """Information about a tracked Blind XSS payload"""

    payload_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    payload: str
    target_url: str
    parameter: str
    context_type: str = "unknown"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    notes: Optional[str] = None


class CallbackCreate(BaseModel):
    """Incoming callback data"""

    payload_id: str
    # Client-side collected data
    url: Optional[str] = None
    referrer: Optional[str] = None
    cookies: Optional[str] = None
    local_storage: Optional[str] = None
    session_storage: Optional[str] = None
    dom_snapshot: Optional[str] = None
    screenshot: Optional[str] = None  # Base64 encoded
    user_agent: Optional[str] = None
    custom_data: Optional[Dict[str, Any]] = None


class Callback(BaseModel):
    """Stored callback record"""

    id: int
    payload_id: str
    received_at: datetime

    # Request metadata
    source_ip: str
    user_agent: str
    referer: Optional[str] = None

    # Collected data
    url: Optional[str] = None
    cookies: Optional[str] = None
    local_storage: Optional[str] = None
    session_storage: Optional[str] = None
    dom_snapshot: Optional[str] = None
    screenshot_path: Optional[str] = None
    custom_data: Optional[Dict[str, Any]] = None

    # Linked payload info
    payload_info: Optional[PayloadInfo] = None


class CallbackStats(BaseModel):
    """Statistics about callbacks"""

    total_callbacks: int = 0
    unique_payloads: int = 0
    unique_ips: int = 0
    callbacks_today: int = 0
    last_callback_at: Optional[datetime] = None


class WebhookConfig(BaseModel):
    """Webhook notification configuration"""

    enabled: bool = False
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    custom_webhook_url: Optional[str] = None
    notify_on_new_callback: bool = True
    notify_on_new_payload: bool = False


class ServerConfig(BaseModel):
    """Server configuration"""

    host: str = "0.0.0.0"
    port: int = 8888
    database_path: str = "blind_xss.db"
    screenshots_dir: str = "screenshots"
    cors_origins: List[str] = ["*"]
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)
    retention_days: int = 30
    max_dom_snapshot_size: int = 1_000_000  # 1MB
    max_screenshot_size: int = 5_000_000  # 5MB
