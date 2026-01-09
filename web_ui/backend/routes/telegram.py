#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 23:10:02 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Telegram integration routes.
"""

import re
import aiohttp
from fastapi import FastAPI
from brsxss.integrations.telegram_service import telegram_service
from brsxss.integrations.telegram_bot import TelegramBot, TelegramConfig


async def resolve_channel_input(bot_token: str, channel_input: str) -> dict:
    """
    Resolve channel input to numeric ID.
    Supports:
    - Numeric ID: -1003325111853
    - Invite link: https://t.me/+g5wb4aKSgQs1NzJi
    - Username: @channel_name
    - Short link: t.me/+abc123
    """
    channel_input = channel_input.strip()

    if channel_input.lstrip("-").isdigit():
        return {"success": True, "channel_id": int(channel_input)}

    invite_patterns = [
        r"(?:https?://)?t\.me/\+([a-zA-Z0-9_-]+)",
        r"(?:https?://)?t\.me/joinchat/([a-zA-Z0-9_-]+)",
    ]

    invite_hash = None
    for pattern in invite_patterns:
        match = re.search(pattern, channel_input)
        if match:
            invite_hash = match.group(1)
            break

    username = None
    if channel_input.startswith("@"):
        username = channel_input[1:]
    elif re.match(r"(?:https?://)?t\.me/([a-zA-Z][a-zA-Z0-9_]{4,})", channel_input):
        match = re.search(r"t\.me/([a-zA-Z][a-zA-Z0-9_]{4,})", channel_input)
        if match and not match.group(1).startswith("+"):
            username = match.group(1)

    if username:
        try:
            url = f"https://api.telegram.org/bot{bot_token}/getChat"
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json={"chat_id": f"@{username}"}) as resp:
                    data = await resp.json()
                    if data.get("ok"):
                        return {
                            "success": True,
                            "channel_id": data["result"]["id"],
                            "title": data["result"].get("title"),
                            "type": data["result"].get("type"),
                        }
                    else:
                        return {
                            "success": False,
                            "error": f"Channel @{username} not found or bot not added",
                        }
        except Exception as e:
            return {"success": False, "error": str(e)}

    if invite_hash:
        try:
            url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json={"limit": 100}) as resp:
                    data = await resp.json()
                    if data.get("ok"):
                        for update in data.get("result", []):
                            if "channel_post" in update:
                                chat = update["channel_post"].get("chat", {})
                                if chat.get("type") == "channel":
                                    return {
                                        "success": True,
                                        "channel_id": chat["id"],
                                        "title": chat.get("title"),
                                        "type": "channel",
                                    }
                            if "my_chat_member" in update:
                                chat = update["my_chat_member"].get("chat", {})
                                if chat.get("type") == "channel":
                                    return {
                                        "success": True,
                                        "channel_id": chat["id"],
                                        "title": chat.get("title"),
                                        "type": "channel",
                                    }

                        return {
                            "success": False,
                            "error": "Channel not found in bot updates. Make sure bot is admin in the channel and post something.",
                            "hint": "Or use numeric ID: forward any message from channel to @userinfobot",
                        }
        except Exception as e:
            return {"success": False, "error": str(e)}

        return {
            "success": False,
            "error": "Could not resolve invite link. Use numeric Channel ID.",
            "hint": "Forward any message from channel to @userinfobot to get numeric ID",
        }

    return {"success": False, "error": "Invalid channel format"}


def register(app: FastAPI, storage):
    """Register Telegram routes"""

    @app.post("/api/telegram/resolve-channel")
    async def resolve_telegram_channel(bot_token: str, channel_input: str):
        """
        Resolve channel input (link, username, or ID) to numeric ID.
        User-friendly endpoint for channel resolution.
        """
        return await resolve_channel_input(bot_token, channel_input)

    @app.get("/api/telegram")
    async def get_telegram_status():
        """Get Telegram integration status"""
        return telegram_service.get_status()

    @app.post("/api/telegram/configure")
    async def configure_telegram(
        bot_token: str, channel_input: str = "", notify_level: str = "critical"
    ):
        """
        Configure Telegram bot integration.

        Required:
        1. bot_token - from @BotFather
        2. channel_input - channel ID, link, or @username

        Bot must be admin in the channel.
        """
        channel_id = None
        if channel_input:
            resolved = await resolve_channel_input(bot_token, channel_input)
            if not resolved.get("success"):
                return resolved
            channel_id = resolved.get("channel_id")

        result = await telegram_service.configure(
            bot_token=bot_token, channel_id=channel_id, notify_level=notify_level
        )

        if result.get("success"):
            settings = storage.get_settings()
            settings.telegram_bot_token = bot_token
            settings.telegram_channel_id = channel_id
            settings.telegram_channel_input = channel_input
            settings.telegram_enabled = True
            settings.telegram_notify_level = notify_level
            storage.save_settings(settings)

        return result

    @app.post("/api/telegram/channel")
    async def set_telegram_channel(channel_id: int):
        """set channel for scan posts"""
        result = await telegram_service.set_channel(channel_id)

        if result.get("success"):
            settings = storage.get_settings()
            settings.telegram_channel_id = channel_id
            storage.save_settings(settings)

        return result

    @app.post("/api/telegram/test")
    async def test_telegram(bot_token: str = "", channel_input: str = ""):
        """
        Test Telegram configuration and send welcome message.

        If bot_token and channel_input provided - configures and tests.
        Otherwise tests current configuration.
        """
        if bot_token and channel_input:
            resolved = await resolve_channel_input(bot_token, channel_input)
            if not resolved.get("success"):
                return resolved

            channel_id = resolved.get("channel_id")

            config = TelegramConfig(
                bot_token=bot_token, channel_id=channel_id, enabled=True
            )
            bot = TelegramBot(config)

            verify = await bot.verify()
            if not verify.get("success"):
                await bot.close()
                return verify

            welcome_sent = await bot.send_welcome()
            await bot.close()

            if welcome_sent:
                settings = storage.get_settings()
                settings.telegram_bot_token = bot_token
                settings.telegram_channel_id = channel_id
                settings.telegram_channel_input = channel_input
                settings.telegram_enabled = True
                storage.save_settings(settings)

                await telegram_service.configure(
                    bot_token=bot_token, channel_id=channel_id
                )

                return {
                    "success": True,
                    "bot_username": verify.get("bot_username"),
                    "channel_id": channel_id,
                    "channel_title": resolved.get("title"),
                    "message": "Welcome message sent",
                }
            else:
                return {"success": False, "error": "Failed to send welcome message"}

        return await telegram_service.test_connection()

    @app.delete("/api/telegram")
    async def disable_telegram():
        """Disable Telegram integration"""
        telegram_service.disable()

        settings = storage.get_settings()
        settings.telegram_enabled = False
        storage.save_settings(settings)

        return {"success": True, "message": "Telegram disabled"}
