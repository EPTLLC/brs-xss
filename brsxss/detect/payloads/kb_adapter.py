#!/usr/bin/env python3

"""
Project: BRS-XSS v4.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 28 Dec 2025 UTC
Status: Updated - Remote API support
Telegram: https://t.me/EasyProTech

BRS-KB Adapter - Integration with BRS-KB (BRS XSS Knowledge Base).
Supports both remote API (default) and local library modes.
Configuration is read from config files and environment variables.
"""

import os
import sys
import time
import json
import hashlib
import http.client
import ssl
from urllib.parse import urlparse, urlencode
from typing import Optional, Any
from dataclasses import dataclass
from abc import ABC, abstractmethod

from brsxss.version import get_user_agent, update_knowledge_base_version


# Environment variable names
ENV_KB_API_KEY = "BRSXSS_KB_API_KEY"
ENV_KB_API_URL = "BRSXSS_KB_API_URL"
ENV_KB_MODE = "BRSXSS_KB_MODE"
ENV_KB_LOCAL_PATH = "BRSXSS_KB_LOCAL_PATH"

# Default values (can be overridden by config/env)
DEFAULT_API_URL = "https://brs-kb.easypro.tech/api/v1"
DEFAULT_API_KEY = "BRS-KB_free_kUOgkmm2lxr2sgIg_hFsmuBsFGB4fVpakvu0pzANStRIpeGs8"
DEFAULT_LOCAL_PATH = "/var/BRS/BRS-KB"
DEFAULT_TIMEOUT = 30
DEFAULT_CACHE_TTL = 300  # 5 minutes - KB data can change frequently


@dataclass
class CacheEntry:
    """Cache entry with TTL"""

    data: Any
    timestamp: float
    etag: Optional[str] = None
    ttl: int = DEFAULT_CACHE_TTL

    @property
    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.ttl


@dataclass
class KBConfig:
    """Knowledge Base configuration"""

    mode: str = "remote"  # remote, local, auto
    api_url: str = DEFAULT_API_URL
    api_key: str = ""
    timeout: int = DEFAULT_TIMEOUT
    max_retries: int = 3
    retry_delay: float = 1.0
    local_path: str = DEFAULT_LOCAL_PATH
    fallback_enabled: bool = True
    cache_enabled: bool = True
    cache_ttl: int = DEFAULT_CACHE_TTL
    etag_enabled: bool = True

    @classmethod
    def from_config(cls, config_data: Optional[dict] = None) -> "KBConfig":
        """Create KBConfig from configuration dictionary"""
        cfg = cls()

        # First, apply config file values
        if config_data and "kb" in config_data:
            kb_cfg = config_data["kb"]
            cfg.mode = kb_cfg.get("mode", cfg.mode)

            if "api" in kb_cfg:
                api_cfg = kb_cfg["api"]
                cfg.api_url = api_cfg.get("url", cfg.api_url)
                cfg.api_key = api_cfg.get("key", cfg.api_key)
                cfg.timeout = api_cfg.get("timeout", cfg.timeout)
                cfg.max_retries = api_cfg.get("max_retries", cfg.max_retries)
                cfg.retry_delay = api_cfg.get("retry_delay", cfg.retry_delay)

            if "local" in kb_cfg:
                local_cfg = kb_cfg["local"]
                cfg.local_path = local_cfg.get("path", cfg.local_path)
                cfg.fallback_enabled = local_cfg.get(
                    "fallback_enabled", cfg.fallback_enabled
                )

            if "cache" in kb_cfg:
                cache_cfg = kb_cfg["cache"]
                cfg.cache_enabled = cache_cfg.get("enabled", cfg.cache_enabled)
                cfg.cache_ttl = cache_cfg.get("ttl", cfg.cache_ttl)

            cfg.etag_enabled = kb_cfg.get("etag_enabled", cfg.etag_enabled)

        # Then, override with environment variables (highest priority)
        cfg.api_key = os.environ.get(ENV_KB_API_KEY, cfg.api_key) or DEFAULT_API_KEY
        cfg.api_url = os.environ.get(ENV_KB_API_URL, cfg.api_url)
        cfg.mode = os.environ.get(ENV_KB_MODE, cfg.mode)
        cfg.local_path = os.environ.get(ENV_KB_LOCAL_PATH, cfg.local_path)

        return cfg


class KBClientBase(ABC):
    """Abstract base class for KB clients"""

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def get_all_payloads(self) -> list[str]:
        pass

    @abstractmethod
    def get_payloads_by_context(self, context: str) -> list[str]:
        pass

    @abstractmethod
    def get_payloads_by_tag(self, tag: str) -> list[str]:
        pass

    @abstractmethod
    def get_waf_bypass_payloads(self, waf: Optional[str] = None) -> list[str]:
        pass

    @abstractmethod
    def get_payloads_by_severity(self, severity: str) -> list[str]:
        pass

    @abstractmethod
    def get_kb_version(self) -> str:
        pass

    @abstractmethod
    def get_statistics(self) -> dict[str, Any]:
        pass

    @abstractmethod
    def search(self, term: str, case_sensitive: bool = False) -> list[str]:
        pass


class RemoteKBClient(KBClientBase):
    """
    Remote KB client - works via HTTP API.
    This is the default mode for BRS-XSS.
    """

    def __init__(self, config: KBConfig):
        self.config = config
        self._cache: dict[str, CacheEntry] = {}
        self._available: Optional[bool] = None
        self._version: Optional[str] = None
        self._initialized = False

    def _get_headers(self) -> dict[str, str]:
        """Get request headers"""
        return {
            "X-API-Key": self.config.api_key,
            "Accept": "application/json",
            "User-Agent": get_user_agent(),
        }

    def _cache_key(self, endpoint: str, params: Optional[dict] = None) -> str:
        """Generate cache key"""
        key_data = f"{endpoint}:{json.dumps(params or {}, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _get_cached(self, key: str) -> Optional[CacheEntry]:
        """Get cache entry if valid"""
        if not self.config.cache_enabled:
            return None
        entry = self._cache.get(key)
        if entry and not entry.is_expired:
            return entry
        return None

    def _set_cached(self, key: str, data: Any, etag: Optional[str] = None):
        """set cache entry"""
        if self.config.cache_enabled:
            self._cache[key] = CacheEntry(
                data=data, timestamp=time.time(), etag=etag, ttl=self.config.cache_ttl
            )

    def _request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        method: str = "GET",
        body: Optional[dict] = None,
    ) -> Optional[dict]:
        """Make HTTP request with retry logic using http.client"""
        # Check cache first
        cache_key = self._cache_key(endpoint, params)
        cached = self._get_cached(cache_key)
        if cached is not None and method == "GET":
            return cached.data

        # Parse URL
        parsed = urlparse(self.config.api_url)
        host = parsed.netloc
        base_path = parsed.path.rstrip("/")

        # Build request path
        path = f"{base_path}{endpoint}"
        if params:
            path = f"{path}?{urlencode(params)}"

        headers = self._get_headers()

        # Add ETag header if available
        if self.config.etag_enabled and cached and cached.etag:
            headers["If-None-Match"] = cached.etag

        # Prepare body
        body_data = None
        if body:
            body_data = json.dumps(body)
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body_data))

        last_error: Optional[Exception] = None
        for attempt in range(self.config.max_retries):
            conn: Optional[http.client.HTTPConnection] = None
            try:
                # Create connection (HTTPS or HTTP)
                if parsed.scheme == "https":
                    context = ssl.create_default_context()
                    conn = http.client.HTTPSConnection(
                        host, timeout=self.config.timeout, context=context
                    )
                else:
                    conn = http.client.HTTPConnection(host, timeout=self.config.timeout)

                # Make request
                conn.request(method, path, body=body_data, headers=headers)
                response = conn.getresponse()

                # Handle 304 Not Modified
                if response.status == 304 and cached:
                    conn.close()
                    return cached.data

                # Read response
                response_body = response.read().decode("utf-8")

                if response.status >= 400:
                    last_error = Exception(f"HTTP {response.status}: {response.reason}")
                    if response.status in (401, 403, 404):
                        conn.close()
                        break  # Don't retry auth/not found errors
                    conn.close()
                    continue

                response_data = json.loads(response_body)

                # Get ETag for caching
                etag = response.getheader("ETag")
                self._set_cached(cache_key, response_data, etag)

                conn.close()
                return response_data

            except json.JSONDecodeError as e:
                last_error = e

            except Exception as e:
                last_error = e

            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass

            # Wait before retry
            if attempt < self.config.max_retries - 1:
                time.sleep(self.config.retry_delay * (attempt + 1))

        if last_error:
            print(f"[KB] API request failed: {last_error}")
        return None

    def _initialize(self):
        """Initialize client and check availability"""
        if self._initialized:
            return

        result = self._request("/health")
        if result and result.get("status") == "operational":
            self._available = True

            # Update KB version info
            if "service" in result:
                update_knowledge_base_version(
                    {
                        "version": result["service"].get("version", "unknown"),
                        "build": result["service"].get("build", "unknown"),
                        "revision": "stable",
                    }
                )
                self._version = result["service"].get("version")

            # Get info for version
            info = self._request("/info")
            if info:
                self._version = info.get("version", self._version)
        else:
            self._available = False

        self._initialized = True

    def is_available(self) -> bool:
        """Check if remote API is available"""
        if self._available is None:
            self._initialize()
        return self._available or False

    def get_all_payloads(self) -> list[str]:
        """Get all payloads from remote API"""
        result = self._request("/export/payloads")
        if result and "payloads" in result:
            return self._extract_payloads(result["payloads"])
        return []

    def _extract_payloads(self, payloads_data: list) -> list[str]:
        """Extract payload strings from API response"""
        payloads = []
        for p in payloads_data:
            if isinstance(p, dict):
                payloads.append(p.get("payload", ""))
            else:
                payloads.append(str(p))
        return [p for p in payloads if p]

    def get_payloads_by_context(self, context: str) -> list[str]:
        """Get payloads for a specific context"""
        result = self._request("/payloads", {"context": context.lower(), "limit": 1000})
        if result and "payloads" in result:
            return self._extract_payloads(result["payloads"])
        return []

    def get_payloads_by_tag(self, tag: str) -> list[str]:
        """Get payloads with a specific tag"""
        result = self._request("/payloads/search", {"q": tag.lower()})
        if result and "results" in result:
            return self._extract_payloads(result["results"])
        return []

    def get_waf_bypass_payloads(self, waf: Optional[str] = None) -> list[str]:
        """Get WAF bypass payloads"""
        params = {"waf_evasion": "true", "limit": 1000}
        result = self._request("/payloads", params)
        if result and "payloads" in result:
            return self._extract_payloads(result["payloads"])
        return []

    def get_payloads_by_severity(self, severity: str) -> list[str]:
        """Get payloads by severity level"""
        result = self._request(
            "/payloads", {"severity": severity.lower(), "limit": 1000}
        )
        if result and "payloads" in result:
            return self._extract_payloads(result["payloads"])
        return []

    def get_kb_version(self) -> str:
        """Get BRS-KB version"""
        if self._version:
            return self._version
        if not self._initialized:
            self._initialize()
        return self._version or "unknown"

    def get_statistics(self) -> dict[str, Any]:
        """Get KB statistics"""
        result = self._request("/stats")
        if result:
            return {
                "available": True,
                "mode": "remote",
                "api_url": self.config.api_url,
                **result,
            }
        return {"available": False, "mode": "remote"}

    def get_kb_info(self) -> dict[str, Any]:
        """Get KB info from /info endpoint"""
        result = self._request("/info")
        if result:
            return result
        return {}

    def search(self, term: str, case_sensitive: bool = False) -> list[str]:
        """Search payloads by term"""
        result = self._request("/payloads/search", {"q": term})
        if result and "results" in result:
            return self._extract_payloads(result["results"])
        return []

    def get_context_details(self, context_id: str) -> Optional[dict[str, Any]]:
        """Get detailed context information"""
        return self._request(f"/contexts/{context_id}")

    def get_defenses(self, context_id: str) -> Optional[dict[str, Any]]:
        """Get defense recommendations for a context"""
        return self._request("/defenses", {"context": context_id})

    def analyze_payload(self, payload: str) -> Optional[dict[str, Any]]:
        """Analyze a single payload"""
        return self._request("/analyze", method="POST", body={"payload": payload})

    def analyze_batch(self, payloads: list[str]) -> Optional[dict[str, Any]]:
        """Analyze multiple payloads (max 100)"""
        return self._request(
            "/analyze/batch", method="POST", body={"payloads": payloads[:100]}
        )

    # Convenience methods for specific contexts
    def get_websocket_payloads(self) -> list[str]:
        return self.get_payloads_by_context("websocket")

    def get_graphql_payloads(self) -> list[str]:
        return self.get_payloads_by_context("graphql")

    def get_sse_payloads(self) -> list[str]:
        return self.get_payloads_by_context("sse")

    def get_modern_browser_payloads(self) -> list[str]:
        return self.get_payloads_by_tag("modern") + self.get_payloads_by_tag("es6")

    def get_exotic_payloads(self) -> list[str]:
        payloads = []
        for tag in ["mxss", "dom-clobbering", "prototype-pollution", "dangling-markup"]:
            payloads.extend(self.get_payloads_by_tag(tag))
        return payloads


class LocalKBClient(KBClientBase):
    """
    Local KB client - works via local BRS-KB library.
    For offline/airgapped environments.
    """

    def __init__(self, config: KBConfig):
        self.config = config
        self._kb_available = False
        self._payload_db: Optional[dict[str, Any]] = None
        self._full_db: dict[str, Any] = {}
        self._initialize()

    def _initialize(self):
        """Initialize connection to local BRS-KB"""
        local_path = self.config.local_path
        if os.path.exists(local_path) and local_path not in sys.path:
            sys.path.insert(0, local_path)

        try:
            from brs_kb.payloads_db import FULL_PAYLOAD_DATABASE

            self._full_db = FULL_PAYLOAD_DATABASE
            self._kb_available = True

            # Update version info
            try:
                from brs_kb import __version__

                update_knowledge_base_version(
                    {"version": __version__, "build": "local", "revision": "local"}
                )
            except ImportError:
                pass

        except ImportError as e:
            print(f"[KB] Local library not available: {e}")
            self._kb_available = False

    def is_available(self) -> bool:
        return self._kb_available

    def get_all_payloads(self) -> list[str]:
        if not self._kb_available:
            return []
        return [entry.payload for entry in self._full_db.values()]

    def get_payloads_by_context(self, context: str) -> list[str]:
        if not self._kb_available:
            return []
        context = context.lower()
        return [
            entry.payload
            for entry in self._full_db.values()
            if any(context in ctx.lower() for ctx in entry.contexts)
        ]

    def get_payloads_by_tag(self, tag: str) -> list[str]:
        if not self._kb_available:
            return []
        tag = tag.lower()
        return [
            entry.payload
            for entry in self._full_db.values()
            if any(tag in t.lower() for t in entry.tags)
        ]

    def get_waf_bypass_payloads(self, waf: Optional[str] = None) -> list[str]:
        if not self._kb_available:
            return []
        payloads = []
        for entry in self._full_db.values():
            if entry.waf_evasion:
                if waf is None:
                    payloads.append(entry.payload)
                elif entry.bypasses and any(
                    waf.lower() in b.lower() for b in entry.bypasses
                ):
                    payloads.append(entry.payload)
        return payloads

    def get_payloads_by_severity(self, severity: str) -> list[str]:
        if not self._kb_available:
            return []
        severity = severity.lower()
        return [
            entry.payload
            for entry in self._full_db.values()
            if entry.severity.lower() == severity
        ]

    def get_kb_version(self) -> str:
        if not self._kb_available:
            return "N/A"
        try:
            from brs_kb import __version__

            return __version__
        except ImportError:
            return "unknown"

    def get_statistics(self) -> dict[str, Any]:
        if not self._kb_available:
            return {"available": False, "mode": "local"}

        severity_counts: dict[str, int] = {}
        for entry in self._full_db.values():
            sev = entry.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "available": True,
            "mode": "local",
            "total_payloads": len(self._full_db),
            "by_severity": severity_counts,
            "waf_bypass_payloads": sum(
                1 for e in self._full_db.values() if e.waf_evasion
            ),
        }

    def search(self, term: str, case_sensitive: bool = False) -> list[str]:
        if not self._kb_available:
            return []

        search_term = term if case_sensitive else term.lower()
        payloads = []
        for entry in self._full_db.values():
            payload = entry.payload if case_sensitive else entry.payload.lower()
            desc = entry.description if case_sensitive else entry.description.lower()
            if search_term in payload or search_term in desc:
                payloads.append(entry.payload)
        return payloads

    # Convenience methods
    def get_websocket_payloads(self) -> list[str]:
        return self.get_payloads_by_context("websocket")

    def get_graphql_payloads(self) -> list[str]:
        return self.get_payloads_by_context("graphql")

    def get_sse_payloads(self) -> list[str]:
        return self.get_payloads_by_context("sse")

    def get_modern_browser_payloads(self) -> list[str]:
        return self.get_payloads_by_tag("modern") + self.get_payloads_by_tag("es6")

    def get_exotic_payloads(self) -> list[str]:
        payloads = []
        for tag in ["mxss", "dom-clobbering", "prototype-pollution", "dangling-markup"]:
            payloads.extend(self.get_payloads_by_tag(tag))
        return payloads


class KBAdapter:
    """
    Main KB adapter with automatic mode selection and fallback.

    Modes:
    - "remote": Use remote API only
    - "local": Use local library only
    - "auto": Try remote first, fallback to local if unavailable
    """

    def __init__(self, config_data: Optional[dict] = None):
        self.config = KBConfig.from_config(config_data)
        self._remote_client: Optional[RemoteKBClient] = None
        self._local_client: Optional[LocalKBClient] = None
        self._active_client: Optional[KBClientBase] = None
        self._initialize()

    def _initialize(self):
        """Initialize clients based on mode"""
        mode = self.config.mode.lower()

        if mode == "local":
            self._local_client = LocalKBClient(self.config)
            if self._local_client.is_available():
                self._active_client = self._local_client
                print("[KB] Using local library mode")
            else:
                print("[KB] Local library not available")

        elif mode == "remote":
            self._remote_client = RemoteKBClient(self.config)
            if self._remote_client.is_available():
                self._active_client = self._remote_client
                print(f"[KB] Using remote API: {self.config.api_url}")
            else:
                print("[KB] Remote API not available")

        else:  # auto mode
            # Try remote first
            self._remote_client = RemoteKBClient(self.config)
            if self._remote_client.is_available():
                self._active_client = self._remote_client
                print(f"[KB] Using remote API: {self.config.api_url}")
            elif self.config.fallback_enabled:
                # Fallback to local
                self._local_client = LocalKBClient(self.config)
                if self._local_client.is_available():
                    self._active_client = self._local_client
                    print("[KB] Fallback to local library mode")
                else:
                    print("[KB] No KB source available")
            else:
                print("[KB] Remote API not available, fallback disabled")

    @property
    def is_available(self) -> bool:
        return self._active_client is not None and self._active_client.is_available()

    @property
    def mode(self) -> str:
        if self._active_client is self._remote_client:
            return "remote"
        elif self._active_client is self._local_client:
            return "local"
        return "none"

    # Delegate all methods to active client
    def get_all_payloads(self) -> list[str]:
        if not self._active_client:
            return []
        return self._active_client.get_all_payloads()

    def get_payloads_by_context(self, context: str) -> list[str]:
        if not self._active_client:
            return []
        return self._active_client.get_payloads_by_context(context)

    def get_payloads_by_tag(self, tag: str) -> list[str]:
        if not self._active_client:
            return []
        return self._active_client.get_payloads_by_tag(tag)

    def get_waf_bypass_payloads(self, waf: Optional[str] = None) -> list[str]:
        if not self._active_client:
            return []
        return self._active_client.get_waf_bypass_payloads(waf)

    def get_payloads_by_severity(self, severity: str) -> list[str]:
        if not self._active_client:
            return []
        return self._active_client.get_payloads_by_severity(severity)

    def get_kb_version(self) -> str:
        if not self._active_client:
            return "N/A"
        return self._active_client.get_kb_version()

    def get_statistics(self) -> dict[str, Any]:
        if not self._active_client:
            return {"available": False}
        return self._active_client.get_statistics()

    def get_kb_info(self) -> dict[str, Any]:
        """Get KB info from API"""
        if isinstance(self._active_client, RemoteKBClient):
            return self._active_client.get_kb_info()
        # For local mode, return basic info
        return {"name": "BRS-KB", "version": self.get_kb_version(), "mode": "local"}

    def search(self, term: str, case_sensitive: bool = False) -> list[str]:
        if not self._active_client:
            return []
        return self._active_client.search(term, case_sensitive)

    # Convenience methods
    def get_websocket_payloads(self) -> list[str]:
        return self.get_payloads_by_context("websocket")

    def get_graphql_payloads(self) -> list[str]:
        return self.get_payloads_by_context("graphql")

    def get_sse_payloads(self) -> list[str]:
        return self.get_payloads_by_context("sse")

    def get_modern_browser_payloads(self) -> list[str]:
        if not self._active_client:
            return []
        if hasattr(self._active_client, "get_modern_browser_payloads"):
            return getattr(self._active_client, "get_modern_browser_payloads")()
        return self._active_client.get_payloads_by_tag("modern")

    def get_exotic_payloads(self) -> list[str]:
        if not self._active_client:
            return []
        if hasattr(self._active_client, "get_exotic_payloads"):
            return getattr(self._active_client, "get_exotic_payloads")()
        return self._active_client.get_payloads_by_tag("exotic")

    # Remote-only methods (return None for local mode)
    def get_context_details(self, context_id: str) -> Optional[dict[str, Any]]:
        if isinstance(self._active_client, RemoteKBClient):
            return self._active_client.get_context_details(context_id)
        return None

    def get_defenses(self, context_id: str) -> Optional[dict[str, Any]]:
        if isinstance(self._active_client, RemoteKBClient):
            return self._active_client.get_defenses(context_id)
        return None

    def analyze_payload(self, payload: str) -> Optional[dict[str, Any]]:
        if isinstance(self._active_client, RemoteKBClient):
            return self._active_client.analyze_payload(payload)
        return None


# Singleton instance
_kb_adapter: Optional[KBAdapter] = None


def get_kb_adapter(config_data: Optional[dict] = None) -> KBAdapter:
    """Get singleton KB adapter instance"""
    global _kb_adapter
    if _kb_adapter is None:
        _kb_adapter = KBAdapter(config_data)
    return _kb_adapter


def reset_kb_adapter():
    """Reset singleton instance (for testing)"""
    global _kb_adapter
    _kb_adapter = None


def kb_available() -> bool:
    """Check if BRS-KB is available"""
    return get_kb_adapter().is_available
