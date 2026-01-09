#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 12:27:23 UTC
Status: Updated - Added proxy support
Telegram: https://t.me/EasyProTech
"""

import aiohttp
import asyncio
import time
from typing import Optional, Any, Union
from dataclasses import dataclass

from ..utils.logger import Logger
from .proxy_manager import ProxyManager, ProxyConfig, ProxyProtocol

logger = Logger("core.http_client")


@dataclass
class HTTPResponse:
    """HTTP response wrapper"""

    status_code: int
    text: str
    headers: dict[str, str]
    url: str
    response_time: float
    error: Optional[str] = None


class HTTPClient:
    """
    HTTP client for web requests.

    Features:
    - Async/sync request support
    - Automatic retry mechanism
    - Connection pooling
    - Request/response logging
    - Timeout management
    - Proxy support (HTTP/HTTPS/SOCKS5)
    """

    def __init__(
        self,
        timeout: int = 10,
        verify_ssl: bool = True,
        proxy_config: Optional[ProxyConfig] = None,
        connector_limit: int = 100,
        connector_limit_per_host: int = 10,
    ):
        """Initialize HTTP client"""
        self.session: Optional[aiohttp.ClientSession] = None
        self.request_count = 0
        self.error_count = 0

        # Default settings
        self.default_timeout = timeout
        self.verify_ssl = verify_ssl
        self.default_headers = {
            "User-Agent": "BRS-XSS Scanner",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

        # Proxy support
        self.proxy_manager = ProxyManager(proxy_config) if proxy_config else None
        self._proxy_connector = None
        self.connector_limit = connector_limit
        self.connector_limit_per_host = connector_limit_per_host

    def set_proxy(self, proxy_config: Optional[ProxyConfig] = None):
        """
        Set or update proxy configuration.
        Closes existing session to apply new proxy settings.
        """
        if proxy_config:
            self.proxy_manager = ProxyManager(proxy_config)
        else:
            self.proxy_manager = None
        self._proxy_connector = None

        # Close existing session to apply new settings
        if self.session and not self.session.closed:
            asyncio.create_task(self.close())

    def set_proxy_from_string(
        self, proxy_string: str, protocol: ProxyProtocol = ProxyProtocol.SOCKS5
    ) -> bool:
        """
        Set proxy from string.

        Args:
            proxy_string: Proxy in format host:port:user:pass
            protocol: Proxy protocol (default SOCKS5)

        Returns:
            True if parsing successful
        """
        self.proxy_manager = ProxyManager()
        if self.proxy_manager.set_from_string(proxy_string, protocol):
            self._proxy_connector = None
            if self.session and not self.session.closed:
                asyncio.create_task(self.close())
            return True
        self.proxy_manager = None
        return False

    def _get_connector(self):
        """Get connector (with proxy if configured)"""
        # If proxy is configured and uses SOCKS
        if self.proxy_manager and self.proxy_manager.config.enabled:
            socks_connector = self.proxy_manager.get_connector()
            if socks_connector:
                return socks_connector

        # Default TCP connector
        return aiohttp.TCPConnector(
            limit=self.connector_limit,
            limit_per_host=self.connector_limit_per_host,
            ssl=self.verify_ssl,
        )

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.default_timeout)
            connector = self._get_connector()
            self.session = aiohttp.ClientSession(
                timeout=timeout, headers=self.default_headers, connector=connector
            )
        return self.session

    async def close(self):
        """Close the HTTP session"""
        if self.session and not self.session.closed:
            await self.session.close()
            # Longer delay to ensure proper SSL cleanup
            await asyncio.sleep(0.3)
            logger.debug("HTTP session closed")
            # Clear session reference
            self.session = None

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    async def get(
        self, url: str, cookies: Optional[dict[str, str]] = None, **kwargs
    ) -> HTTPResponse:
        """Make GET request"""
        return await self.request("GET", url, cookies=cookies, **kwargs)

    async def post(
        self,
        url: str,
        data: Optional[Union[str, dict]] = None,
        json: Optional[dict] = None,
        cookies: Optional[dict[str, str]] = None,
        **kwargs,
    ) -> HTTPResponse:
        """Make POST request"""
        return await self.request(
            "POST", url, data=data, json=json, cookies=cookies, **kwargs
        )

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        data: Optional[Union[str, dict]] = None,
        json: Optional[dict] = None,
        cookies: Optional[dict[str, str]] = None,
        timeout: Optional[int] = None,
        retries: int = 3,
    ) -> HTTPResponse:
        """
        Make HTTP request with retry logic.

        Args:
            method: HTTP method
            url: Request URL
            headers: Additional headers
            data: Request data
            timeout: Request timeout
            retries: Number of retries

        Returns:
            HTTP response
        """
        start_time = time.time()
        self.request_count += 1

        # Merge headers
        request_headers = self.default_headers.copy()
        if headers:
            request_headers.update(headers)

        # Setup timeout
        if timeout is None:
            timeout = self.default_timeout

        last_error = None

        for attempt in range(retries + 1):
            try:
                session = await self._get_session()

                # Get HTTP proxy URL if configured (for non-SOCKS proxies)
                request_kwargs = {
                    "method": method,
                    "url": url,
                    "headers": request_headers,
                    "timeout": aiohttp.ClientTimeout(total=timeout),
                }

                # Add data or json
                if json is not None:
                    request_kwargs["json"] = json
                elif data is not None:
                    request_kwargs["data"] = data

                # Add cookies if provided
                if cookies:
                    request_kwargs["cookies"] = cookies

                # Add HTTP/HTTPS proxy if configured
                if self.proxy_manager:
                    proxy_url = self.proxy_manager.get_proxy_url()
                    if proxy_url:
                        request_kwargs["proxy"] = proxy_url

                async with session.request(
                    method=str(request_kwargs.pop("method")),
                    url=str(request_kwargs.pop("url")),
                    **request_kwargs,
                ) as response:

                    text = await response.text()
                    response_time = time.time() - start_time

                    http_response = HTTPResponse(
                        status_code=response.status,
                        text=text,
                        headers=dict(response.headers),
                        url=str(response.url),
                        response_time=response_time,
                    )

                    logger.debug(
                        f"{method} {url} -> {response.status} ({response_time:.2f}s)"
                    )
                    return http_response

            except asyncio.TimeoutError as e:
                last_error = f"Request timeout: {e}"
                if attempt < retries:
                    await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff
                    continue

            except aiohttp.ClientError as e:
                last_error = f"Client error: {e}"
                if attempt < retries:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue

            except Exception as e:
                last_error = f"Unexpected error: {e}"
                break

        # All retries failed
        self.error_count += 1
        response_time = time.time() - start_time

        logger.error(f"Request failed after {retries + 1} attempts: {last_error}")

        return HTTPResponse(
            status_code=0,
            text="",
            headers={},
            url=url,
            response_time=response_time,
            error=last_error,
        )

    def get_sync(self, url: str, **kwargs) -> HTTPResponse:
        """Synchronous GET request"""
        return asyncio.run(self.get(url, **kwargs))

    def post_sync(self, url: str, **kwargs) -> HTTPResponse:
        """Synchronous POST request"""
        return asyncio.run(self.post(url, **kwargs))

    async def test_proxy(self, timeout: float = 15.0) -> tuple:
        """
        Test current proxy configuration.

        Returns:
            Tuple of (success, info_dict)
        """
        if not self.proxy_manager:
            return False, {"error": "No proxy configured"}
        return await self.proxy_manager.test_connection(timeout)

    def get_proxy_info(self) -> Optional[dict[str, Any]]:
        """Get current proxy configuration"""
        if self.proxy_manager and self.proxy_manager.config.enabled:
            return self.proxy_manager.config.to_dict()
        return None

    def get_stats(self) -> dict[str, Any]:
        """Get client statistics"""
        stats: dict[str, Any] = {
            "request_count": self.request_count,
            "error_count": self.error_count,
            "error_rate": self.error_count / max(1, self.request_count),
            "session_active": self.session is not None and not self.session.closed,
        }

        # Add proxy info if configured
        if self.proxy_manager and self.proxy_manager.config.enabled:
            stats["proxy_enabled"] = True
            stats["proxy_host"] = self.proxy_manager.config.host
            stats["proxy_port"] = self.proxy_manager.config.port
            stats["proxy_protocol"] = self.proxy_manager.config.protocol.value
        else:
            stats["proxy_enabled"] = False

        return stats
