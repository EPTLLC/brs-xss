#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 12:27:23 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Proxy Manager - handles proxy configuration, parsing, and connection testing.
Supports HTTP/HTTPS and SOCKS5 proxies.
"""

import asyncio
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Any
from urllib.parse import urlparse

import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType


class ProxyProtocol(Enum):
    """Supported proxy protocols"""

    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


@dataclass
class ProxyConfig:
    """Proxy configuration"""

    enabled: bool = False
    host: str = ""
    port: int = 0
    username: Optional[str] = None
    password: Optional[str] = None
    protocol: ProxyProtocol = ProxyProtocol.SOCKS5

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return {
            "enabled": self.enabled,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "protocol": self.protocol.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProxyConfig":
        """Create from dictionary"""
        protocol = data.get("protocol", "socks5")
        if isinstance(protocol, str):
            protocol = ProxyProtocol(protocol)
        return cls(
            enabled=data.get("enabled", False),
            host=data.get("host", ""),
            port=data.get("port", 0),
            username=data.get("username"),
            password=data.get("password"),
            protocol=protocol,
        )

    def get_url(self) -> str:
        """Get proxy URL for aiohttp"""
        if not self.host or not self.port:
            return ""

        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"

        return f"{self.protocol.value}://{auth}{self.host}:{self.port}"

    def is_valid(self) -> bool:
        """Check if config is valid"""
        return bool(self.host and self.port > 0)


class ProxyParser:
    """Parse various proxy string formats"""

    # Common formats:
    # host:port:user:pass
    # user:pass@host:port
    # protocol://user:pass@host:port
    # host:port (no auth)

    @staticmethod
    def parse(proxy_string: str) -> Optional[ProxyConfig]:
        """
        Parse proxy string in various formats.

        Supported formats:
        - host:port:user:pass (most common for purchased proxies)
        - user:pass@host:port
        - protocol://user:pass@host:port
        - host:port (no auth)

        Returns ProxyConfig or None if parsing fails.
        """
        if not proxy_string or not proxy_string.strip():
            return None

        proxy_string = proxy_string.strip()

        # Try URL format first: protocol://user:pass@host:port
        if "://" in proxy_string:
            return ProxyParser._parse_url_format(proxy_string)

        # Try user:pass@host:port format
        if "@" in proxy_string:
            return ProxyParser._parse_at_format(proxy_string)

        # Try host:port:user:pass format (most common)
        parts = proxy_string.split(":")
        if len(parts) == 4:
            return ProxyParser._parse_colon_format(parts)
        elif len(parts) == 2:
            return ProxyParser._parse_host_port_only(parts)

        return None

    @staticmethod
    def _parse_url_format(proxy_string: str) -> Optional[ProxyConfig]:
        """Parse protocol://user:pass@host:port format"""
        try:
            parsed = urlparse(proxy_string)
            protocol = ProxyProtocol(parsed.scheme.lower())
            return ProxyConfig(
                enabled=True,
                host=parsed.hostname or "",
                port=parsed.port or 0,
                username=parsed.username,
                password=parsed.password,
                protocol=protocol,
            )
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _parse_at_format(proxy_string: str) -> Optional[ProxyConfig]:
        """Parse user:pass@host:port format"""
        try:
            auth_part, host_part = proxy_string.rsplit("@", 1)
            user, password = auth_part.split(":", 1)
            host, port_str = host_part.rsplit(":", 1)
            return ProxyConfig(
                enabled=True,
                host=host,
                port=int(port_str),
                username=user,
                password=password,
                protocol=ProxyProtocol.SOCKS5,
            )
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _parse_colon_format(parts: list) -> Optional[ProxyConfig]:
        """Parse host:port:user:pass format"""
        try:
            host, port_str, user, password = parts
            return ProxyConfig(
                enabled=True,
                host=host,
                port=int(port_str),
                username=user,
                password=password,
                protocol=ProxyProtocol.SOCKS5,
            )
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _parse_host_port_only(parts: list) -> Optional[ProxyConfig]:
        """Parse host:port format (no auth)"""
        try:
            host, port_str = parts
            return ProxyConfig(
                enabled=True,
                host=host,
                port=int(port_str),
                protocol=ProxyProtocol.SOCKS5,
            )
        except (ValueError, AttributeError):
            return None


class ProxyManager:
    """Manages proxy connections and testing"""

    def __init__(self, config: Optional[ProxyConfig] = None):
        self.config = config or ProxyConfig()
        self._test_urls = [
            "https://api.ipify.org?format=json",
            "https://httpbin.org/ip",
        ]

    def set_config(self, config: ProxyConfig):
        """Set proxy configuration"""
        self.config = config

    def set_from_string(
        self, proxy_string: str, protocol: Optional[ProxyProtocol] = None
    ) -> bool:
        """
        set proxy from string.

        Args:
            proxy_string: Proxy string in any supported format
            protocol: Override protocol (optional)

        Returns:
            True if parsing successful
        """
        config = ProxyParser.parse(proxy_string)
        if config:
            if protocol:
                config.protocol = protocol
            self.config = config
            return True
        return False

    def get_connector(self) -> Optional[ProxyConnector]:
        """Get aiohttp ProxyConnector for SOCKS proxies"""
        if not self.config.enabled or not self.config.is_valid():
            return None

        if self.config.protocol in [ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5]:
            proxy_type = (
                ProxyType.SOCKS5
                if self.config.protocol == ProxyProtocol.SOCKS5
                else ProxyType.SOCKS4
            )
            return ProxyConnector(
                proxy_type=proxy_type,
                host=self.config.host,
                port=self.config.port,
                username=self.config.username,
                password=self.config.password,
            )
        return None

    def get_proxy_url(self) -> Optional[str]:
        """Get proxy URL for HTTP/HTTPS proxies (aiohttp native)"""
        if not self.config.enabled or not self.config.is_valid():
            return None

        if self.config.protocol in [ProxyProtocol.HTTP, ProxyProtocol.HTTPS]:
            return self.config.get_url()
        return None

    async def test_connection(
        self, timeout: float = 15.0
    ) -> tuple[bool, dict[str, Any]]:
        """
        Test proxy connection.

        Returns:
            tuple of (success, info_dict)
            info_dict contains: ip, country, latency_ms, error
        """
        if not self.config.is_valid():
            return False, {"error": "Invalid proxy configuration"}

        import time

        start_time = time.time()

        try:
            connector = self.get_connector()
            proxy_url = self.get_proxy_url()

            timeout_obj = aiohttp.ClientTimeout(total=timeout)

            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout_obj
            ) as session:
                # Get IP info
                async with session.get(
                    self._test_urls[0], proxy=proxy_url if proxy_url else None
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        latency_ms = (time.time() - start_time) * 1000

                        # Try to get country info
                        country_info = await self._get_country_info(
                            session, data.get("ip", ""), proxy_url
                        )

                        return True, {
                            "ip": data.get("ip", "unknown"),
                            "country": country_info.get("country", "Unknown"),
                            "country_code": country_info.get("country_code", ""),
                            "latency_ms": round(latency_ms, 1),
                            "protocol": self.config.protocol.value,
                        }
                    else:
                        return False, {"error": f"HTTP {resp.status}"}

        except asyncio.TimeoutError:
            return False, {"error": "Connection timeout"}
        except Exception as e:
            return False, {"error": str(e)}

    async def _get_country_info(
        self, session: aiohttp.ClientSession, ip: str, proxy_url: Optional[str]
    ) -> dict[str, str]:
        """Get country from IP. Returns dict with country and country_code."""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=country,countryCode"
            async with session.get(url, proxy=proxy_url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", ""),
                    }
        except Exception:
            pass
        return {"country": "Unknown", "country_code": ""}

    async def test_target(
        self, target_url: str, timeout: float = 15.0
    ) -> tuple[bool, str]:
        """
        Test if target is reachable through proxy.

        Returns:
            tuple of (success, message)
        """
        try:
            connector = self.get_connector()
            proxy_url = self.get_proxy_url()

            timeout_obj = aiohttp.ClientTimeout(total=timeout)

            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout_obj
            ) as session:
                async with session.head(
                    target_url, proxy=proxy_url if proxy_url else None
                ) as resp:
                    return True, f"Status: {resp.status}"

        except asyncio.TimeoutError:
            return False, "Connection timeout"
        except Exception as e:
            return False, str(e)


# Convenience function for quick testing
async def test_proxy_string(
    proxy_string: str, protocol: ProxyProtocol = ProxyProtocol.SOCKS5
):
    """Quick test of a proxy string"""
    manager = ProxyManager()
    if not manager.set_from_string(proxy_string, protocol):
        return False, {"error": "Failed to parse proxy string"}
    return await manager.test_connection()
