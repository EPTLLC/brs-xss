#!/usr/bin/env python3

"""
Project: BRS-XSS Session Manager
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 15:00:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

import aiohttp
import asyncio
from typing import Optional, Any
from urllib.parse import urlparse, urljoin

from ..utils.logger import Logger
from .http_client import HTTPClient

logger = Logger("core.session_manager")


class SessionManager:
    """
    Manages HTTP sessions for stored XSS testing.
    
    Features:
    - Login and authentication
    - Session cookie persistence
    - POST requests with session
    - Multiple concurrent sessions
    """
    
    def __init__(self, http_client: Optional[HTTPClient] = None):
        """Initialize session manager"""
        self.http_client = http_client or HTTPClient()
        self.sessions: dict[str, aiohttp.ClientSession] = {}
        self.session_cookies: dict[str, dict[str, str]] = {}
        self.session_metadata: dict[str, dict[str, Any]] = {}
    
    async def login(
        self,
        login_url: str,
        credentials: dict[str, str],
        session_id: str = "default",
        form_selector: Optional[str] = None,
        success_indicators: Optional[list[str]] = None
    ) -> bool:
        """
        Perform login and maintain session.
        
        Args:
            login_url: URL of login page
            credentials: dict with username/password or other fields
            session_id: Unique identifier for this session
            form_selector: Optional CSS selector for form (for auto-detection)
            success_indicators: list of strings that indicate successful login
            
        Returns:
            True if login successful
        """
        try:
            # Get login page first to get any CSRF tokens
            response = await self.http_client.get(login_url)
            if not response.text:
                logger.error(f"Failed to get login page: {login_url}")
                return False
            
            # Extract CSRF token if present
            csrf_token = self._extract_csrf_token(response.text)
            if csrf_token:
                credentials['csrf_token'] = csrf_token
                credentials['_token'] = csrf_token
                credentials['csrf'] = csrf_token
            
            # Prepare login data
            login_data = credentials.copy()
            
            # Determine content type
            content_type = "application/x-www-form-urlencoded"
            if any(key.startswith('_') or key == 'csrf_token' for key in login_data.keys()):
                # Likely JSON API
                content_type = "application/json"
            
            # Perform login POST
            login_response = await self.http_client.post(
                login_url,
                data=login_data if content_type == "application/x-www-form-urlencoded" else None,
                json=login_data if content_type == "application/json" else None,
                headers={"Content-Type": content_type}
            )
            
            # Check for success indicators
            if success_indicators:
                success = any(indicator in login_response.text.lower() for indicator in success_indicators)
            else:
                # Default: check for common success patterns
                success = self._check_login_success(login_response)
            
            if success:
                # Extract cookies from response
                cookies = self._extract_cookies(login_response.headers)
                if cookies:
                    self.session_cookies[session_id] = cookies
                    logger.info(f"Login successful for session: {session_id}")
                    return True
                else:
                    logger.warning(f"Login appeared successful but no cookies found")
                    return False
            else:
                logger.warning(f"Login failed for session: {session_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error during login: {e}")
            return False
    
    async def post_with_session(
        self,
        url: str,
        data: dict[str, Any],
        session_id: str = "default",
        content_type: str = "application/x-www-form-urlencoded"
    ) -> Optional[Any]:
        """
        Perform POST request with session cookies.
        
        Args:
            url: Target URL
            data: POST data
            session_id: Session identifier
            content_type: Content type for POST
            
        Returns:
            HTTPResponse or None
        """
        try:
            cookies = self.session_cookies.get(session_id, {})
            
            # Prepare headers
            headers = {"Content-Type": content_type}
            
            # Perform POST with cookies
            if content_type == "application/json":
                response = await self.http_client.post(
                    url,
                    json=data,
                    headers=headers,
                    cookies=cookies
                )
            else:
                response = await self.http_client.post(
                    url,
                    data=data,
                    headers=headers,
                    cookies=cookies
                )
            
            return response
            
        except Exception as e:
            logger.error(f"Error in POST with session: {e}")
            return None
    
    async def get_with_session(
        self,
        url: str,
        session_id: str = "default"
    ) -> Optional[Any]:
        """
        Perform GET request with session cookies.
        
        Args:
            url: Target URL
            session_id: Session identifier
            
        Returns:
            HTTPResponse or None
        """
        try:
            cookies = self.session_cookies.get(session_id, {})
            response = await self.http_client.get(url, cookies=cookies)
            return response
        except Exception as e:
            logger.error(f"Error in GET with session: {e}")
            return None
    
    def _extract_csrf_token(self, html: str) -> Optional[str]:
        """Extract CSRF token from HTML"""
        import re
        
        patterns = [
            r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']',
            r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']',
            r'name=["\']csrf["\']\s+value=["\']([^"\']+)["\']',
            r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']',
            r'csrf["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_cookies(self, headers: dict[str, str]) -> dict[str, str]:
        """Extract cookies from response headers"""
        cookies = {}
        
        # Extract set-Cookie headers
        set_cookie_values = []
        for key, value in headers.items():
            if key.lower() == 'set-cookie':
                set_cookie_values.append(value)
        
        # Parse cookies
        for cookie_string in set_cookie_values:
            # Parse "name=value; Path=/; HttpOnly" format
            parts = cookie_string.split(';')
            if parts:
                name_value = parts[0].strip().split('=', 1)
                if len(name_value) == 2:
                    cookies[name_value[0]] = name_value[1]
        
        return cookies
    
    def _check_login_success(self, response: Any) -> bool:
        """Check if login was successful"""
        if not response or not response.text:
            return False
        
        text_lower = response.text.lower()
        
        # Common success indicators
        success_patterns = [
            'dashboard',
            'welcome',
            'logout',
            'profile',
            'account',
            'successfully logged in',
            'login successful'
        ]
        
        # Common failure indicators
        failure_patterns = [
            'invalid',
            'incorrect',
            'failed',
            'error',
            'login failed',
            'authentication failed'
        ]
        
        # Check for success patterns
        has_success = any(pattern in text_lower for pattern in success_patterns)
        has_failure = any(pattern in text_lower for pattern in failure_patterns)
        
        # Also check status code
        if hasattr(response, 'status_code'):
            if response.status_code == 302 or response.status_code == 301:
                # Redirect usually means success
                return True
        
        return has_success and not has_failure
    
    def has_session(self, session_id: str = "default") -> bool:
        """Check if session exists"""
        return session_id in self.session_cookies and bool(self.session_cookies[session_id])
    
    async def logout(self, logout_url: str, session_id: str = "default") -> bool:
        """Logout and clear session"""
        try:
            cookies = self.session_cookies.get(session_id, {})
            await self.http_client.get(logout_url, cookies=cookies)
            
            # Clear session
            if session_id in self.session_cookies:
                del self.session_cookies[session_id]
            if session_id in self.session_metadata:
                del self.session_metadata[session_id]
            
            logger.info(f"Logged out session: {session_id}")
            return True
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            return False
    
    async def close(self):
        """Close all sessions"""
        self.session_cookies.clear()
        self.session_metadata.clear()
        await self.http_client.close()

