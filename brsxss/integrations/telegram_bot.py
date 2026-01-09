"""
BRS-XSS Telegram Integration
Channel-only with legal compliance

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
"""

import asyncio
import aiohttp
import json
from dataclasses import dataclass
from typing import Optional, Dict, Any
from pathlib import Path


@dataclass
class TelegramConfig:
    """Telegram configuration"""

    bot_token: str = ""
    channel_id: Optional[int] = None
    enabled: bool = False


# Legal disclaimer for every post
LEGAL_DISCLAIMER = """
<i>Authorized testing only. Unauthorized use is illegal.</i>
<a href="https://easypro.tech">EasyProTech LLC</a>"""


class TelegramBot:
    """
    Telegram bot for BRS-XSS
    - Welcome message with ETHICS.md and LEGAL.md
    - Scan reports with legal disclaimer
    - Professional branding
    """

    API_URL = "https://api.telegram.org/bot"

    def __init__(self, config: TelegramConfig):
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self._welcome_sent = False
        self._send_lock = asyncio.Lock()  # Lock for atomic send

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self._session or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def _api(
        self, method: str, data: Optional[Dict[Any, Any]] = None
    ) -> Optional[Dict[Any, Any]]:
        """Call Telegram API with JSON"""
        if not self.config.bot_token:
            return None

        url = f"{self.API_URL}{self.config.bot_token}/{method}"
        session = await self._get_session()

        try:
            async with session.post(url, json=data or {}, timeout=30) as r:
                result = await r.json()
                if result.get("ok"):
                    return result.get("result")
        except Exception:
            pass
        return None

    async def _api_form(self, method: str, form: aiohttp.FormData) -> Optional[Dict]:
        """Call Telegram API with multipart form"""
        if not self.config.bot_token:
            return None

        url = f"{self.API_URL}{self.config.bot_token}/{method}"
        session = await self._get_session()

        try:
            async with session.post(url, data=form, timeout=120) as r:
                result = await r.json()
                if result.get("ok"):
                    return result.get("result")
        except Exception:
            pass
        return None

    async def verify(self) -> Dict[str, Any]:
        """Verify bot and channel access"""
        result: Dict[str, Any] = {"success": False}

        bot = await self._api("getMe")
        if not bot:
            result["error"] = "Invalid bot token"
            return result

        result["bot_username"] = bot.get("username")

        if self.config.channel_id:
            ch = await self._api("getChat", {"chat_id": self.config.channel_id})
            if ch:
                result["channel_title"] = ch.get("title")
                result["success"] = True
            else:
                result["error"] = "Cannot access channel"
        else:
            result["success"] = True

        return result

    async def send_welcome(self) -> bool:
        """
        Send welcome message with ETHICS.md and LEGAL.md
        Called once when bot starts
        """
        if not self.config.enabled or not self.config.channel_id:
            return False

        if self._welcome_sent:
            return True

        # Find legal PDF files
        integrations_path = Path(__file__).parent
        ethics_path = integrations_path / "ETHICS.pdf"
        legal_path = integrations_path / "LEGAL.pdf"

        if not ethics_path.exists() or not legal_path.exists():
            return False

        ethics_content = ethics_path.read_bytes()
        legal_content = legal_path.read_bytes()

        welcome_text = """<a href="https://github.com/EPTLLC/brs-xss"><b>BRS-XSS Scanner</b></a>
━━━━━━━━━━━━━━━━━━
<b>Brabus Recon Suite - XSS Module</b>
Enterprise-grade XSS vulnerability scanner

<b>IMPORTANT:</b> This tool is for <b>authorized security testing only</b>.

Before using BRS-XSS, you must read and agree to:
<b>ETHICS</b> - Ethical guidelines
<b>LEGAL</b> - Legal terms and conditions

<b>By using this scanner, you confirm:</b>
- You have written authorization to test target systems
- You comply with all applicable laws
- You accept full responsibility for your actions

━━━━━━━━━━━━━━━━━━
<a href="https://easypro.tech">EasyProTech LLC</a>"""

        # Step 1: Send welcome text message
        text_result = await self._api(
            "sendMessage",
            {
                "chat_id": self.config.channel_id,
                "text": welcome_text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
        )

        if not text_result:
            return False

        # Step 2: Send both PDFs as documents under the text
        media = [
            {"type": "document", "media": "attach://ethics"},
            {"type": "document", "media": "attach://legal"},
        ]

        form = aiohttp.FormData()
        form.add_field("chat_id", str(self.config.channel_id))
        form.add_field("media", json.dumps(media))
        form.add_field(
            "ethics",
            ethics_content,
            filename="ETHICS.pdf",
            content_type="application/pdf",
        )
        form.add_field(
            "legal", legal_content, filename="LEGAL.pdf", content_type="application/pdf"
        )

        result = await self._api_form("sendMediaGroup", form)
        if result:
            self._welcome_sent = True
            return True
        return False

    async def post_scan_result(
        self,
        scan_id: str,
        target: str,
        mode: str,
        duration: float,
        proxy: str,
        critical: int,
        high: int,
        medium: int,
        low: int,
        urls_scanned: int,
        payloads_sent: int,
        recon_pdf: bytes,
        report_pdf: bytes,
    ) -> bool:
        """
        Post completed scan: text message + two PDFs.
        Uses lock to prevent mixing reports from concurrent scans.
        """
        if not self.config.enabled or not self.config.channel_id:
            return False

        async with self._send_lock:
            total = critical + high + medium + low
            dur = (
                f"{int(duration//60)}m {int(duration%60)}s"
                if duration >= 60
                else f"{int(duration)}s"
            )
            proxy_text = proxy if proxy else "Direct IP"

            # Status indicator
            if total == 0:
                status = "[OK] No vulnerabilities found"
            elif critical > 0:
                status = f"[CRITICAL] {total} vulnerabilities found"
            elif high > 0:
                status = f"[HIGH] {total} vulnerabilities found"
            else:
                status = f"[!] {total} vulnerabilities found"

            # Step 1: Send text message with scan summary (pre block for monospace)
            text = f"""<b>BRS-XSS Scan Complete</b>
<pre>
Target: {self._esc(target)}
Scan ID: {scan_id}
Mode: {mode.upper()} | Duration: {dur}
Via: {proxy_text}

URLs: {urls_scanned} | Payloads: {payloads_sent}

Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}
</pre>
<b>{status}</b>
{LEGAL_DISCLAIMER}"""

            text_result = await self._api(
                "sendMessage",
                {
                    "chat_id": self.config.channel_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
            )

            if not text_result:
                return False

            # Step 2: Send two PDFs
            media = [
                {"type": "document", "media": "attach://recon"},
                {"type": "document", "media": "attach://report"},
            ]

            form = aiohttp.FormData()
            form.add_field("chat_id", str(self.config.channel_id))
            form.add_field("media", json.dumps(media))
            form.add_field(
                "recon",
                recon_pdf,
                filename=f"recon_{scan_id}.pdf",
                content_type="application/pdf",
            )
            form.add_field(
                "report",
                report_pdf,
                filename=f"report_{scan_id}.pdf",
                content_type="application/pdf",
            )

            result = await self._api_form("sendMediaGroup", form)
            return result is not None

    def _esc(self, text: str) -> str:
        if not text:
            return ""
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    async def on_scan_failed(self, scan_id: str, error: str) -> bool:
        """Send scan failed notification"""
        if not self.config.channel_id:
            return False

        msg = f"<b>Scan Failed</b>\n\nScan ID: <code>{self._esc(scan_id)}</code>\nError: {self._esc(error)}"
        result = await self._api(
            "sendMessage",
            {"chat_id": self.config.channel_id, "text": msg, "parse_mode": "HTML"},
        )
        return result is not None

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


# Singleton
_bot: Optional[TelegramBot] = None


def get_bot() -> Optional[TelegramBot]:
    return _bot


def init_bot(config: TelegramConfig) -> TelegramBot:
    global _bot
    _bot = TelegramBot(config)
    return _bot
