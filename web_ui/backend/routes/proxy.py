#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 23:10:02 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Proxy management routes.
"""

import uuid
from fastapi import FastAPI, HTTPException
from brsxss.detect.xss.reflected.proxy_manager import (
    ProxyParser,
    ProxyManager,
    ProxyProtocol as CoreProxyProtocol,
)
from ..models import ProxyProtocolType, SavedProxy, ProxyTestResult


def register(app: FastAPI, storage):
    """Register proxy routes"""

    @app.get("/api/proxy")
    async def get_proxy_settings():
        """Get current proxy settings"""
        settings = storage.get_settings()
        return settings.proxy.model_dump(exclude_none=False)

    @app.post("/api/proxy")
    async def set_proxy(
        proxy_string: str = "",
        protocol: str = "socks5",
        enabled: bool = True,
        country: str = "",
        country_code: str = "",
        name: str = "",
        save: bool = True,
    ):
        """
        set proxy from string and optionally save to list.

        Format: host:port:user:pass
        """
        settings = storage.get_settings()

        if not proxy_string:
            settings.proxy.enabled = False
            settings.proxy.active_proxy_id = None
            storage.save_settings(settings)
            return {"success": True, "message": "Proxy disabled"}

        config = ProxyParser.parse(proxy_string)
        if not config:
            raise HTTPException(status_code=400, detail="Invalid proxy string format")

        try:
            proto = ProxyProtocolType(protocol.lower())
        except ValueError:
            proto = ProxyProtocolType.SOCKS5

        if not country or not country_code:
            manager = ProxyManager()
            try:
                core_proto = CoreProxyProtocol(protocol.lower())
            except ValueError:
                core_proto = CoreProxyProtocol.SOCKS5

            if manager.set_from_string(proxy_string, core_proto):
                success, info = await manager.test_connection(timeout=15.0)
                if success:
                    country = info.get("country", "")
                    country_code = info.get("country_code", "")

        proxy_id = str(uuid.uuid4())[:8]

        existing = next(
            (
                p
                for p in settings.proxy.saved_proxies
                if p.host == config.host and p.port == config.port
            ),
            None,
        )

        if existing:
            proxy_id = existing.id
            existing.username = config.username
            existing.password = config.password
            existing.protocol = proto
            existing.proxy_string = proxy_string
            existing.country = country if country else existing.country
            existing.country_code = (
                country_code if country_code else existing.country_code
            )
            if name:
                existing.name = name
        elif save:
            if len(settings.proxy.saved_proxies) >= 10:
                raise HTTPException(
                    status_code=400, detail="Maximum 10 proxies allowed in MIT version"
                )

            new_proxy = SavedProxy(
                id=proxy_id,
                name=name or f"{config.host}:{config.port}",
                host=config.host,
                port=config.port,
                username=config.username,
                password=config.password,
                protocol=proto,
                proxy_string=proxy_string,
                country=country if country else None,
                country_code=country_code if country_code else None,
            )
            settings.proxy.saved_proxies.append(new_proxy)

        settings.proxy.enabled = enabled
        settings.proxy.active_proxy_id = proxy_id
        settings.proxy.host = config.host
        settings.proxy.port = config.port
        settings.proxy.username = config.username
        settings.proxy.password = config.password
        settings.proxy.protocol = proto
        settings.proxy.proxy_string = proxy_string
        settings.proxy.country = country if country else None
        settings.proxy.country_code = country_code if country_code else None

        storage.save_settings(settings)

        return {"success": True, "proxy": settings.proxy.model_dump()}

    @app.post("/api/proxy/select/{proxy_id}")
    async def select_proxy(proxy_id: str):
        """Select a saved proxy as active"""
        settings = storage.get_settings()

        proxy = next(
            (p for p in settings.proxy.saved_proxies if p.id == proxy_id), None
        )
        if not proxy:
            raise HTTPException(status_code=404, detail="Proxy not found")

        settings.proxy.enabled = True
        settings.proxy.active_proxy_id = proxy_id
        settings.proxy.host = proxy.host
        settings.proxy.port = proxy.port
        settings.proxy.username = proxy.username
        settings.proxy.password = proxy.password
        settings.proxy.protocol = proxy.protocol
        settings.proxy.proxy_string = proxy.proxy_string
        settings.proxy.country = proxy.country
        settings.proxy.country_code = proxy.country_code

        storage.save_settings(settings)

        return {"success": True, "proxy": settings.proxy.model_dump()}

    @app.delete("/api/proxy/saved/{proxy_id}")
    async def delete_saved_proxy(proxy_id: str):
        """Delete a saved proxy from list"""
        settings = storage.get_settings()

        settings.proxy.saved_proxies = [
            p for p in settings.proxy.saved_proxies if p.id != proxy_id
        ]

        if settings.proxy.active_proxy_id == proxy_id:
            settings.proxy.enabled = False
            settings.proxy.active_proxy_id = None
            settings.proxy.host = ""
            settings.proxy.port = 0

        storage.save_settings(settings)

        return {"success": True, "remaining": len(settings.proxy.saved_proxies)}

    @app.post("/api/proxy/test")
    async def test_proxy(proxy_string: str = "", protocol: str = "socks5"):
        """
        Test proxy connection.

        Returns IP, country, and latency.
        """
        if not proxy_string:
            settings = storage.get_settings()
            if not settings.proxy.enabled or not settings.proxy.host:
                return ProxyTestResult(success=False, error="No proxy configured")

            proxy_string = f"{settings.proxy.host}:{settings.proxy.port}"
            if settings.proxy.username and settings.proxy.password:
                proxy_string += f":{settings.proxy.username}:{settings.proxy.password}"
            protocol = settings.proxy.protocol.value

        manager = ProxyManager()
        try:
            proto = CoreProxyProtocol(protocol.lower())
        except ValueError:
            proto = CoreProxyProtocol.SOCKS5

        if not manager.set_from_string(proxy_string, proto):
            return ProxyTestResult(success=False, error="Failed to parse proxy string")

        success, info = await manager.test_connection(timeout=20.0)

        if success:
            return ProxyTestResult(
                success=True,
                ip=info.get("ip"),
                country=info.get("country"),
                country_code=info.get("country_code"),
                latency_ms=info.get("latency_ms"),
            )
        else:
            return ProxyTestResult(
                success=False, error=info.get("error", "Unknown error")
            )

    @app.delete("/api/proxy")
    async def disable_proxy():
        """Disable proxy (keeps saved proxies)"""
        settings = storage.get_settings()

        settings.proxy.enabled = False
        settings.proxy.active_proxy_id = None
        settings.proxy.host = ""
        settings.proxy.port = 0
        settings.proxy.username = None
        settings.proxy.password = None
        settings.proxy.proxy_string = None
        settings.proxy.country = None
        settings.proxy.country_code = None

        storage.save_settings(settings)
        return {"success": True, "message": "Proxy disabled"}
