"""
Project: BRS-XSS Scanner
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Telegram Service - Singleton service for bot management
Requires: bot_token, channel_id, discussion_group_id
"""

from typing import Optional, Any
from .telegram_bot import TelegramBot, TelegramConfig


class TelegramService:
    """
    Singleton service for Telegram bot management.

    Configuration requires:
    - bot_token: From @BotFather
    - channel_id: Channel for scan posts
    - discussion_group_id: Linked group for comments
    """

    _instance: Optional["TelegramService"] = None
    _bot: Optional[TelegramBot] = None
    _config: Optional[TelegramConfig] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def get_instance(cls) -> "TelegramService":
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def bot(self) -> Optional[TelegramBot]:
        """Get current bot instance"""
        return self._bot

    @property
    def is_configured(self) -> bool:
        """Check if Telegram is fully configured"""
        return (
            self._config is not None
            and self._config.enabled
            and bool(self._config.bot_token)
            and self._config.channel_id is not None
        )

    async def configure(
        self,
        bot_token: str,
        channel_id: Optional[int] = None,
        discussion_group_id: Optional[int] = None,
        notify_level: str = "critical",
    ) -> dict[str, Any]:
        """
        Configure Telegram integration.

        Args:
            bot_token: Token from @BotFather
            channel_id: Channel ID for posts (-100...)
            discussion_group_id: Linked discussion group ID (-100...)
            notify_level: off, critical, high, all
        """

        # Create new config
        self._config = TelegramConfig(
            bot_token=bot_token, channel_id=channel_id, enabled=True
        )
        self._notify_level = notify_level

        # Create bot instance
        self._bot = TelegramBot(self._config)

        # Verify bot and channel access
        verify_result = await self._bot.verify()
        if not verify_result.get("success"):
            self._config.enabled = False
            return verify_result

        result = {
            "success": True,
            "bot_username": verify_result.get("bot_username"),
            "channel_title": verify_result.get("channel_title"),
            "channel_id": channel_id,
            "configured": True,
        }

        return result

    async def test_connection(self) -> dict[str, Any]:
        """Test bot connection by verifying access"""
        if not self._config or not self._config.bot_token:
            return {"success": False, "error": "Bot not configured"}

        if not self._config.channel_id:
            return {"success": False, "error": "Channel not configured"}

        try:
            # Verify bot and channel access
            if not self._bot:
                return {"success": False, "error": "Bot not initialized"}
            result = await self._bot.verify()

            if result.get("success"):
                return {
                    "success": True,
                    "bot_username": result.get("bot_username"),
                    "channel_title": result.get("channel_title"),
                    "message": "Connection verified",
                }
            else:
                return {
                    "success": False,
                    "error": result.get("error", "Verification failed"),
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def disable(self):
        """Disable Telegram integration"""
        if self._config:
            self._config.enabled = False

    def enable(self):
        """Enable Telegram integration"""
        if self._config and self._config.bot_token:
            self._config.enabled = True

    def get_status(self) -> dict[str, Any]:
        """Get current status"""
        if not self._config:
            return {"configured": False, "enabled": False}

        bot_username = None
        try:
            if self._bot and hasattr(self._bot, "_bot_info") and self._bot._bot_info:
                bot_username = self._bot._bot_info.get("username")
        except Exception:
            pass

        return {
            "configured": self.is_configured,
            "enabled": self._config.enabled,
            "channel_id": self._config.channel_id,
            "bot_username": bot_username,
        }

    # === Scanner Event Handlers ===
    # Only final report is sent to Telegram (no intermediate messages)

    async def on_scan_started(self, **kwargs):
        """Scan started - no Telegram notification (by design)"""
        pass

    async def on_vulnerability_found(self, **kwargs):
        """Vulnerability found - no Telegram notification (by design)"""
        pass

    async def on_scan_completed(
        self,
        scan_id: str,
        target: str,
        mode: str,
        duration_seconds: float,
        proxy: str,
        total_vulns: int,
        critical: int,
        high: int,
        medium: int,
        low: int,
        urls_scanned: int = 0,
        payloads_sent: int = 0,
        target_profile: Optional[dict[Any, Any]] = None,
        vulnerabilities: Optional[list[Any]] = None,
    ):
        """Handle scan completed event - generate PDFs and post to channel"""
        if not self.is_configured or not self._bot:
            print("[TG] Not configured, skipping notification")
            return

        try:
            from .pdf_report import PDFReportGenerator

            pdf_gen = PDFReportGenerator()

            # Generate recon PDF with full profile
            recon_pdf = pdf_gen.generate_recon_report(
                scan_id=scan_id, target=target, profile=target_profile or {}
            )

            # Generate scan report PDF with all vulns
            report_pdf = pdf_gen.generate_scan_report(
                scan_id=scan_id,
                target=target,
                mode=mode,
                duration=duration_seconds,
                proxy=proxy,
                vulns=vulnerabilities or [],
                recon=target_profile,
            )

            # Post to channel (locked - one at a time)
            result = await self._bot.post_scan_result(
                scan_id=scan_id,
                target=target,
                mode=mode,
                duration=duration_seconds,
                proxy=proxy,
                critical=critical,
                high=high,
                medium=medium,
                low=low,
                urls_scanned=urls_scanned,
                payloads_sent=payloads_sent,
                recon_pdf=recon_pdf,
                report_pdf=report_pdf,
            )

            if result:
                print(f"[TG] Scan report posted for {scan_id}")
            else:
                print(f"[TG] Failed to post scan report for {scan_id}")

        except Exception as e:
            print(f"[TG] Scan complete notify error: {e}")
            import traceback

            traceback.print_exc()

    async def on_scan_failed(self, scan_id: str, error: str):
        """Handle scan failed event"""
        if not self.is_configured or not self._bot:
            return

        try:
            await self._bot.on_scan_failed(scan_id=scan_id, error=error)
        except Exception as e:
            print(f"[TG] Scan failed notify error: {e}")

    async def close(self):
        """Cleanup resources"""
        if self._bot:
            await self._bot.close()


# Global instance
telegram_service = TelegramService.get_instance()
