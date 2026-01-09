#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created

Endpoint Discovery - Crawl and discover all testable endpoints.
Finds links, forms, parameters, and JavaScript endpoints.
"""

import asyncio
import re
from typing import Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass, field
from html.parser import HTMLParser

from ..utils.logger import Logger

logger = Logger("recon.endpoint_discovery")


@dataclass
class FormInfo:
    """Information about discovered form"""

    action: str
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    input_types: dict[str, str] = field(default_factory=dict)


@dataclass
class EndpointInfo:
    """Single discovered endpoint"""

    url: str
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    source: str = ""  # link, form, js, robots, sitemap
    depth: int = 0


@dataclass
class DiscoveryResult:
    """Complete discovery result"""

    base_url: str = ""
    domain: str = ""
    endpoints: list[EndpointInfo] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    all_parameters: set[str] = field(default_factory=set)
    js_endpoints: list[str] = field(default_factory=list)
    total_urls_found: int = 0
    total_parameters_found: int = 0
    crawl_depth: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "domain": self.domain,
            "endpoints": [
                {
                    "url": e.url,
                    "method": e.method,
                    "parameters": e.parameters,
                    "source": e.source,
                }
                for e in self.endpoints
            ],
            "forms": [
                {"action": f.action, "method": f.method, "parameters": f.parameters}
                for f in self.forms
            ],
            "all_parameters": list(self.all_parameters),
            "js_endpoints": self.js_endpoints,
            "total_urls_found": self.total_urls_found,
            "total_parameters_found": self.total_parameters_found,
            "crawl_depth": self.crawl_depth,
            "errors": self.errors,
        }


class LinkExtractor(HTMLParser):
    """Extract links and forms from HTML"""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: set[str] = set()
        self.forms: list[FormInfo] = []
        self._current_form: Optional[FormInfo] = None

    def handle_starttag(self, tag: str, attrs: list[tuple]):
        attrs_dict = dict(attrs)

        if tag == "a":
            href = attrs_dict.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                full_url = urljoin(self.base_url, href)
                self.links.add(full_url)

        elif tag == "form":
            action = attrs_dict.get("action", self.base_url)
            method = attrs_dict.get("method", "GET").upper()
            self._current_form = FormInfo(
                action=urljoin(self.base_url, action), method=method
            )

        elif tag == "input" and self._current_form:
            name = attrs_dict.get("name", "")
            input_type = attrs_dict.get("type", "text")
            if name:
                self._current_form.parameters.append(name)
                self._current_form.input_types[name] = input_type

        elif tag in ("select", "textarea") and self._current_form:
            name = attrs_dict.get("name", "")
            if name:
                self._current_form.parameters.append(name)

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form:
            if self._current_form.parameters:
                self.forms.append(self._current_form)
            self._current_form = None


class EndpointDiscovery:
    """
    Discover all testable endpoints on a target.
    Crawls pages, extracts forms, finds parameters.
    """

    # Common paths to check
    COMMON_PATHS = [
        "/robots.txt",
        "/sitemap.xml",
        "/admin",
        "/login",
        "/search",
        "/contact",
        "/api",
        "/api/v1",
        "/api/v2",
        "/user",
        "/profile",
        "/account",
        "/register",
        "/signup",
        "/signin",
        "/forgot-password",
        "/reset-password",
        "/comment",
        "/comments",
        "/feedback",
        "/upload",
        "/download",
        "/file",
        "/news",
        "/blog",
        "/article",
        "/post",
        "/product",
        "/products",
        "/item",
        "/items",
        "/category",
        "/categories",
        "/cat",
        "/page",
        "/pages",
        "/content",
        "/ajax",
        "/async",
        "/xhr",
    ]

    # Common parameter names
    COMMON_PARAMS = [
        "id",
        "page",
        "q",
        "query",
        "search",
        "s",
        "name",
        "user",
        "username",
        "email",
        "url",
        "redirect",
        "return",
        "next",
        "ref",
        "file",
        "path",
        "dir",
        "folder",
        "action",
        "cmd",
        "command",
        "exec",
        "cat",
        "category",
        "type",
        "sort",
        "order",
        "limit",
        "offset",
        "start",
        "count",
        "lang",
        "language",
        "locale",
        "callback",
        "jsonp",
        "format",
        "output",
        "message",
        "msg",
        "text",
        "content",
        "body",
        "title",
        "subject",
        "comment",
        "review",
    ]

    def __init__(
        self,
        http_client=None,
        max_depth: int = 2,
        max_urls: int = 50,
        timeout: float = 30.0,
    ):
        self.http_client = http_client
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self._visited: set[str] = set()
        self._domain: str = ""

    async def discover(self, url: str) -> DiscoveryResult:
        """
        Discover all endpoints starting from URL.

        Args:
            url: Starting URL

        Returns:
            DiscoveryResult with all found endpoints
        """
        result = DiscoveryResult()
        parsed = urlparse(url)
        self._domain = parsed.netloc
        result.base_url = url
        result.domain = self._domain

        self._visited.clear()

        logger.info(f"Starting endpoint discovery for {self._domain}")

        try:
            # Phase 1: Crawl from starting URL
            await self._crawl(url, result, depth=0)

            # Phase 2: Check common paths
            await self._check_common_paths(url, result)

            # Phase 3: Extract JS endpoints from visited pages
            # (already done during crawl)

            # Phase 4: Parse robots.txt and sitemap
            await self._parse_robots(url, result)
            await self._parse_sitemap(url, result)

            # Finalize
            result.total_urls_found = len(result.endpoints)
            result.total_parameters_found = len(result.all_parameters)
            result.crawl_depth = self.max_depth

            logger.info(
                f"Discovery complete: {result.total_urls_found} endpoints, "
                f"{result.total_parameters_found} parameters"
            )

        except Exception as e:
            logger.error(f"Discovery error: {e}")
            result.errors.append(str(e))

        return result

    async def _crawl(self, url: str, result: DiscoveryResult, depth: int):
        """Crawl page and extract links/forms"""
        if depth > self.max_depth:
            return
        if len(self._visited) >= self.max_urls:
            return

        # Normalize URL
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if normalized in self._visited:
            return

        self._visited.add(normalized)

        # Only crawl same domain
        if parsed.netloc != self._domain:
            return

        try:
            if not self.http_client:
                return

            response = await asyncio.wait_for(self.http_client.get(url), timeout=10.0)

            if not response or not hasattr(response, "text"):
                return

            content = response.text
            content_type = ""
            if hasattr(response, "headers"):
                content_type = response.headers.get("content-type", "")

            # Only parse HTML
            if "text/html" not in content_type and not content.strip().startswith("<!"):
                return

            # Extract URL parameters
            if parsed.query:
                params = parse_qs(parsed.query)
                endpoint = EndpointInfo(
                    url=url,
                    method="GET",
                    parameters=list(params.keys()),
                    source="link",
                    depth=depth,
                )
                result.endpoints.append(endpoint)
                result.all_parameters.update(params.keys())

            # Parse HTML for links and forms
            extractor = LinkExtractor(url)
            try:
                extractor.feed(content)
            except Exception:
                pass

            # Add forms
            for form in extractor.forms:
                result.forms.append(form)
                result.all_parameters.update(form.parameters)

                # Create endpoint from form
                endpoint = EndpointInfo(
                    url=form.action,
                    method=form.method,
                    parameters=form.parameters,
                    source="form",
                    depth=depth,
                )
                result.endpoints.append(endpoint)

            # Extract JS endpoints
            js_endpoints = self._extract_js_endpoints(content)
            result.js_endpoints.extend(js_endpoints)
            for js_url in js_endpoints:
                full_url = urljoin(url, js_url)
                parsed_js = urlparse(full_url)
                if parsed_js.query:
                    params = parse_qs(parsed_js.query)
                    endpoint = EndpointInfo(
                        url=full_url,
                        method="GET",
                        parameters=list(params.keys()),
                        source="javascript",
                        depth=depth,
                    )
                    result.endpoints.append(endpoint)
                    result.all_parameters.update(params.keys())

            # Crawl discovered links
            for link in extractor.links:
                await self._crawl(link, result, depth + 1)

        except asyncio.TimeoutError:
            logger.debug(f"Timeout crawling {url}")
        except Exception as e:
            logger.debug(f"Error crawling {url}: {e}")

    async def _check_common_paths(self, base_url: str, result: DiscoveryResult):
        """Check common paths for endpoints"""
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        tasks = []
        for path in self.COMMON_PATHS[:20]:  # Limit to prevent overload
            url = urljoin(base, path)
            if url not in self._visited:
                tasks.append(self._check_path(url, result))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_path(self, url: str, result: DiscoveryResult):
        """Check if path exists and has parameters"""
        try:
            if not self.http_client:
                return

            response = await asyncio.wait_for(self.http_client.get(url), timeout=5.0)

            if response and hasattr(response, "status_code"):
                if response.status_code == 200:
                    self._visited.add(url)

                    # Try common parameters
                    params_to_test = self.COMMON_PARAMS[:10]
                    test_url = f"{url}?{'&'.join(f'{p}=test' for p in params_to_test)}"

                    endpoint = EndpointInfo(
                        url=test_url,
                        method="GET",
                        parameters=params_to_test,
                        source="common_path",
                        depth=0,
                    )
                    result.endpoints.append(endpoint)
                    result.all_parameters.update(params_to_test)

        except Exception:
            pass

    async def _parse_robots(self, base_url: str, result: DiscoveryResult):
        """Parse robots.txt for paths"""
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        try:
            if not self.http_client:
                return

            response = await asyncio.wait_for(
                self.http_client.get(robots_url), timeout=5.0
            )

            if response and hasattr(response, "text"):
                content = response.text

                # Extract Disallow and Allow paths
                for line in content.split("\n"):
                    line = line.strip()
                    if line.startswith(("Disallow:", "Allow:")):
                        path = line.split(":", 1)[1].strip()
                        if path and not path.startswith("*"):
                            full_url = urljoin(base_url, path)
                            if full_url not in self._visited:
                                endpoint = EndpointInfo(
                                    url=full_url,
                                    method="GET",
                                    parameters=[],
                                    source="robots",
                                    depth=0,
                                )
                                result.endpoints.append(endpoint)

        except Exception:
            pass

    async def _parse_sitemap(self, base_url: str, result: DiscoveryResult):
        """Parse sitemap.xml for URLs"""
        parsed = urlparse(base_url)
        sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"

        try:
            if not self.http_client:
                return

            response = await asyncio.wait_for(
                self.http_client.get(sitemap_url), timeout=5.0
            )

            if response and hasattr(response, "text"):
                content = response.text

                # Simple regex extraction of URLs
                urls = re.findall(r"<loc>([^<]+)</loc>", content)

                for url in urls[:30]:  # Limit
                    if url not in self._visited:
                        parsed_url = urlparse(url)
                        params = []
                        if parsed_url.query:
                            params = list(parse_qs(parsed_url.query).keys())
                            result.all_parameters.update(params)

                        endpoint = EndpointInfo(
                            url=url,
                            method="GET",
                            parameters=params,
                            source="sitemap",
                            depth=0,
                        )
                        result.endpoints.append(endpoint)

        except Exception:
            pass

    def _extract_js_endpoints(self, content: str) -> list[str]:
        """Extract endpoints from JavaScript code"""
        endpoints = []

        # Patterns for finding URLs in JS
        patterns = [
            # fetch/axios/ajax calls
            r'(?:fetch|axios|ajax)\s*\(\s*[\'"]([^\'"]+)[\'"]',
            # URL assignments
            r'(?:url|endpoint|api)\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            # XMLHttpRequest open
            r'\.open\s*\(\s*[\'"][A-Z]+[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]',
            # href assignments
            r'href\s*=\s*[\'"]([^\'"]+\?[^\'"]+)[\'"]',
            # Action URLs
            r'action\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if "?" in match or match.startswith("/api"):
                    endpoints.append(match)

        return list(set(endpoints))[:20]
