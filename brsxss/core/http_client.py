#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 21:38:09 MSK
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import aiohttp
import asyncio
import time
from typing import Dict, Optional, Any, Union
from dataclasses import dataclass, field

from ..utils.logger import Logger
logger = Logger("core.http_client")


@dataclass
class HTTPResponse:
    """HTTP response wrapper"""
    status_code: int
    text: str
    headers: Dict[str, str]
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
    """
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        """Initialize HTTP client"""
        self.session: Optional[aiohttp.ClientSession] = None
        self.request_count = 0
        self.error_count = 0
        
        # Default settings
        self.default_timeout = timeout
        self.verify_ssl = verify_ssl
        self.default_headers = {
            'User-Agent': 'BRS-XSS Scanner v1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.default_timeout)
            connector = aiohttp.TCPConnector(
                limit=100, 
                limit_per_host=10,
                ssl=self.verify_ssl  # SSL verification control
            )
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=self.default_headers,
                connector=connector
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
    
    async def get(self, url: str, **kwargs) -> HTTPResponse:
        """Make GET request"""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> HTTPResponse:
        """Make POST request"""
        return await self.request('POST', url, **kwargs)
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Union[str, Dict]] = None,
        timeout: Optional[int] = None,
        retries: int = 3
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
                
                async with session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as response:
                    
                    text = await response.text()
                    response_time = time.time() - start_time
                    
                    http_response = HTTPResponse(
                        status_code=response.status,
                        text=text,
                        headers=dict(response.headers),
                        url=str(response.url),
                        response_time=response_time
                    )
                    
                    logger.debug(f"{method} {url} -> {response.status} ({response_time:.2f}s)")
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
            error=last_error
        )
    
    def get_sync(self, url: str, **kwargs) -> HTTPResponse:
        """Synchronous GET request"""
        return asyncio.run(self.get(url, **kwargs))
    
    def post_sync(self, url: str, **kwargs) -> HTTPResponse:
        """Synchronous POST request"""
        return asyncio.run(self.post(url, **kwargs))
    

    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics"""
        return {
            'request_count': self.request_count,
            'error_count': self.error_count,
            'error_rate': self.error_count / max(1, self.request_count),
            'session_active': self.session is not None and not self.session.closed
        }