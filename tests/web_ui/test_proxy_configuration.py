#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 08 Jan 2026 17:25:59 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from types import SimpleNamespace

import pytest

from web_ui.backend.scanner_service import ScannerService
from brsxss.core.proxy_manager import ProxyProtocol


def _make_settings(
    enabled: bool = True,
    host: str = "127.0.0.1",
    port: int = 9050,
    protocol: ProxyProtocol = ProxyProtocol.SOCKS5,
    username: str | None = "user",
    password: str | None = "pass",
):
    proxy = SimpleNamespace(
        enabled=enabled,
        host=host,
        port=port,
        protocol=protocol,
        username=username,
        password=password,
        country="",
        country_code="",
    )
    return SimpleNamespace(proxy=proxy)


def test_build_proxy_config_returns_config():
    storage = SimpleNamespace()
    service = ScannerService(
        storage=storage,
        progress_callback=None,
        vulnerability_callback=None,
        recon_callback=None,
    )
    settings = _make_settings()

    proxy_cfg = service._build_proxy_config(settings)

    assert proxy_cfg is not None
    assert proxy_cfg.enabled is True
    assert proxy_cfg.host == "127.0.0.1"
    assert proxy_cfg.port == 9050
    assert proxy_cfg.username == "user"
    assert proxy_cfg.password == "pass"
    assert proxy_cfg.protocol == ProxyProtocol.SOCKS5


@pytest.mark.asyncio
async def test_http_client_applies_proxy(monkeypatch):
    applied = {}

    class DummyHTTPClient:
        def __init__(
            self,
            timeout: int = 15,
            verify_ssl: bool = True,
            connector_limit: int = 64,
            connector_limit_per_host: int = 10,
        ):
            self.timeout = timeout
            self.verify_ssl = verify_ssl
            self.connector_limit = connector_limit
            self.connector_limit_per_host = connector_limit_per_host
            self.last_proxy = None

        def set_proxy(self, proxy_cfg):
            applied["cfg"] = proxy_cfg
            self.last_proxy = proxy_cfg

    monkeypatch.setattr(
        "brsxss.core.http_client.HTTPClient",
        DummyHTTPClient,
        raising=False,
    )

    settings = _make_settings()
    storage = SimpleNamespace(get_settings=lambda: settings)
    service = ScannerService(
        storage=storage,
        progress_callback=None,
        vulnerability_callback=None,
        recon_callback=None,
    )

    client = await service._get_http_client()

    assert isinstance(client, DummyHTTPClient)
    assert "cfg" in applied
    assert applied["cfg"] is not None
    assert applied["cfg"].host == settings.proxy.host
    assert applied["cfg"].port == settings.proxy.port
