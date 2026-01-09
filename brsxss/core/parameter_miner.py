#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 26 Dec 2025 21:00:00 UTC
Status: Created

Parameter Miner - Discover hidden parameters in web applications.
Uses wordlists, response analysis, and behavioral detection.
"""

import re
import asyncio
from typing import Optional, Any
from dataclasses import dataclass
from urllib.parse import urlencode
from difflib import SequenceMatcher

from .http_client import HTTPClient
from ..utils.logger import Logger

logger = Logger("core.parameter_miner")


@dataclass
class DiscoveredParameter:
    """A discovered hidden parameter"""

    name: str
    method: str  # GET or POST
    evidence: str  # How it was discovered
    confidence: float = 0.5
    response_diff: float = 0.0  # How different the response was
    reflected: bool = False  # Was our value reflected

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "method": self.method,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "response_diff": self.response_diff,
            "reflected": self.reflected,
        }


class ParameterMiner:
    """
    Discover hidden parameters in web applications.

    Techniques:
    1. Wordlist-based parameter fuzzing
    2. Response length/content analysis
    3. JavaScript/HTML parsing for hidden params
    4. Error-based detection
    5. Behavioral analysis (timing, redirects)
    """

    # Common parameter wordlist (top 200)
    COMMON_PARAMS = [
        # Auth/User
        "id",
        "user",
        "username",
        "login",
        "email",
        "password",
        "pass",
        "pwd",
        "token",
        "key",
        "api_key",
        "apikey",
        "auth",
        "session",
        "sid",
        "user_id",
        "uid",
        "userid",
        "account",
        "admin",
        "role",
        "level",
        # Content
        "page",
        "p",
        "q",
        "query",
        "search",
        "s",
        "keyword",
        "keywords",
        "term",
        "text",
        "content",
        "body",
        "message",
        "msg",
        "comment",
        "title",
        "name",
        "description",
        "desc",
        "data",
        "value",
        "val",
        # Navigation
        "url",
        "uri",
        "path",
        "file",
        "filename",
        "dir",
        "directory",
        "redirect",
        "next",
        "return",
        "returnUrl",
        "returnurl",
        "goto",
        "destination",
        "dest",
        "target",
        "link",
        "ref",
        "referer",
        "referrer",
        # Pagination
        "limit",
        "offset",
        "start",
        "end",
        "count",
        "num",
        "number",
        "size",
        "per_page",
        "perpage",
        "pagesize",
        "page_size",
        # Sorting/Filtering
        "sort",
        "order",
        "orderby",
        "order_by",
        "sortby",
        "sort_by",
        "filter",
        "type",
        "category",
        "cat",
        "tag",
        "status",
        "state",
        # Format/Output
        "format",
        "output",
        "callback",
        "jsonp",
        "json",
        "xml",
        "html",
        "template",
        "view",
        "layout",
        "theme",
        "style",
        "mode",
        # Actions
        "action",
        "act",
        "cmd",
        "command",
        "do",
        "func",
        "function",
        "method",
        "op",
        "operation",
        "task",
        "step",
        "process",
        # Files/Media
        "image",
        "img",
        "photo",
        "pic",
        "picture",
        "avatar",
        "icon",
        "upload",
        "download",
        "attachment",
        "doc",
        "document",
        # Location/Geo
        "lang",
        "language",
        "locale",
        "country",
        "region",
        "city",
        "lat",
        "lng",
        "latitude",
        "longitude",
        "location",
        "address",
        # Time
        "date",
        "time",
        "datetime",
        "timestamp",
        "year",
        "month",
        "day",
        "from",
        "to",
        "start_date",
        "end_date",
        "created",
        "updated",
        # Debug/Dev
        "debug",
        "test",
        "dev",
        "preview",
        "draft",
        "verbose",
        "trace",
        "log",
        "error",
        "exception",
        "include",
        "require",
        "import",
        # Security
        "csrf",
        "csrf_token",
        "xsrf",
        "nonce",
        "hash",
        "signature",
        "sig",
        "verify",
        "validate",
        "check",
        "confirm",
        "captcha",
        # API
        "version",
        "v",
        "api",
        "endpoint",
        "resource",
        "object",
        "entity",
        "fields",
        "select",
        "include",
        "expand",
        "embed",
        "with",
        # Misc
        "source",
        "src",
        "origin",
        "channel",
        "campaign",
        "utm_source",
        "code",
        "coupon",
        "promo",
        "discount",
        "price",
        "amount",
        "hidden",
        "private",
        "internal",
        "secret",
        "flag",
        "option",
    ]

    # Test value for parameter detection
    TEST_VALUE = "brsxss_param_test_7x9k2"

    def __init__(
        self,
        http_client: Optional[HTTPClient] = None,
        timeout: float = 10.0,
        max_concurrent: int = 10,
        custom_wordlist: Optional[list[str]] = None,
    ):
        """Initialize parameter miner"""
        self.http_client = http_client
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)

        # Combine wordlists
        self.wordlist = list(set(self.COMMON_PARAMS))
        if custom_wordlist:
            self.wordlist.extend(custom_wordlist)
            self.wordlist = list(set(self.wordlist))

        # Statistics
        self.params_tested = 0
        self.params_found = 0

        logger.info(f"Parameter miner initialized with {len(self.wordlist)} params")

    async def mine(
        self,
        url: str,
        method: str = "GET",
        existing_params: Optional[dict[str, str]] = None,
        wordlist: Optional[list[str]] = None,
    ) -> list[DiscoveredParameter]:
        """
        Mine for hidden parameters.

        Args:
            url: Target URL
            method: HTTP method (GET/POST)
            existing_params: Known parameters to include
            wordlist: Custom wordlist (None = use default)

        Returns:
            list of discovered parameters
        """
        if not self.http_client:
            self.http_client = HTTPClient(timeout=int(self.timeout))

        params_to_test = wordlist or self.wordlist
        existing_params = existing_params or {}

        # Get baseline response
        baseline = await self._get_baseline(url, method, existing_params)
        if not baseline:
            logger.error(f"Failed to get baseline for {url}")
            return []

        logger.info(f"Mining {len(params_to_test)} parameters on {url}")

        # Test parameters concurrently
        tasks = []
        for param in params_to_test:
            if param not in existing_params:
                tasks.append(
                    self._test_parameter(url, method, param, existing_params, baseline)
                )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect discovered parameters
        discovered = []
        for result in results:
            if isinstance(result, DiscoveredParameter):
                discovered.append(result)
                self.params_found += 1

        # Sort by confidence
        discovered.sort(key=lambda x: x.confidence, reverse=True)

        logger.info(f"Discovered {len(discovered)} hidden parameters")
        return discovered

    async def mine_from_page(self, url: str) -> list[DiscoveredParameter]:
        """
        Extract parameters from page content (JS, forms, comments).

        Args:
            url: Target URL

        Returns:
            list of discovered parameters
        """
        if not self.http_client:
            self.http_client = HTTPClient(timeout=int(self.timeout))

        discovered: list[DiscoveredParameter] = []

        try:
            response = await self.http_client.get(url)
            if not response or not response.text:
                return discovered

            content = response.text

            # Extract from JavaScript
            js_params = self._extract_js_params(content)
            for param in js_params:
                discovered.append(
                    DiscoveredParameter(
                        name=param,
                        method="GET",
                        evidence="JavaScript source",
                        confidence=0.7,
                    )
                )

            # Extract from forms
            form_params = self._extract_form_params(content)
            for param in form_params:
                discovered.append(
                    DiscoveredParameter(
                        name=param, method="POST", evidence="HTML form", confidence=0.9
                    )
                )

            # Extract from HTML comments
            comment_params = self._extract_comment_params(content)
            for param in comment_params:
                discovered.append(
                    DiscoveredParameter(
                        name=param,
                        method="GET",
                        evidence="HTML comment",
                        confidence=0.6,
                    )
                )

            # Extract from data attributes
            data_params = self._extract_data_attrs(content)
            for param in data_params:
                discovered.append(
                    DiscoveredParameter(
                        name=param,
                        method="GET",
                        evidence="data-* attribute",
                        confidence=0.5,
                    )
                )

        except Exception as e:
            logger.error(f"Error mining from page: {e}")

        # Deduplicate
        seen = set()
        unique = []
        for p in discovered:
            if p.name not in seen:
                seen.add(p.name)
                unique.append(p)

        return unique

    async def _get_baseline(
        self, url: str, method: str, params: dict[str, str]
    ) -> Optional[dict[str, Any]]:
        """Get baseline response for comparison"""
        try:
            if method.upper() == "GET":
                if params:
                    test_url = f"{url}?{urlencode(params)}"
                else:
                    test_url = url
                if self.http_client:
                    response = await self.http_client.get(test_url)
            else:
                if self.http_client:
                    response = await self.http_client.post(url, data=params)

            if response:
                return {
                    "status": response.status_code,
                    "length": len(response.text),
                    "content": response.text,
                    "headers": (
                        dict(response.headers) if hasattr(response, "headers") else {}
                    ),
                }
        except Exception as e:
            logger.error(f"Baseline request failed: {e}")

        return None

    async def _test_parameter(
        self,
        url: str,
        method: str,
        param: str,
        existing_params: dict[str, str],
        baseline: dict[str, Any],
    ) -> Optional[DiscoveredParameter]:
        """Test a single parameter"""
        async with self.semaphore:
            self.params_tested += 1

            try:
                # Add test parameter
                test_params = existing_params.copy()
                test_params[param] = self.TEST_VALUE

                if method.upper() == "GET":
                    test_url = f"{url}?{urlencode(test_params)}"
                    if self.http_client:
                        response = await self.http_client.get(test_url)
                else:
                    if self.http_client:
                        response = await self.http_client.post(url, data=test_params)

                if not response:
                    return None

                # Analyze response
                result = self._analyze_response(
                    param, baseline, response.text, response.status_code
                )

                if result:
                    result.method = method
                    return result

            except Exception as e:
                logger.debug(f"Error testing param {param}: {e}")

            return None

    def _analyze_response(
        self, param: str, baseline: dict[str, Any], response_text: str, status_code: int
    ) -> Optional[DiscoveredParameter]:
        """Analyze response to detect valid parameter"""

        # Check for reflection
        reflected = self.TEST_VALUE in response_text

        # Calculate response difference
        baseline_len = baseline["length"]
        response_len = len(response_text)
        len_diff = abs(response_len - baseline_len)
        len_diff_pct = len_diff / max(baseline_len, 1)

        # Calculate content similarity
        similarity = SequenceMatcher(
            None, baseline["content"][:5000], response_text[:5000]
        ).ratio()

        # Check status code change
        status_changed = status_code != baseline["status"]

        # Determine if parameter is valid
        is_valid = False
        confidence = 0.0
        evidence = ""

        # Reflection = strong signal
        if reflected:
            is_valid = True
            confidence = 0.9
            evidence = "Value reflected in response"

        # Significant length change
        elif len_diff_pct > 0.1 and len_diff > 100:
            is_valid = True
            confidence = 0.7
            evidence = f"Response length changed by {len_diff} bytes"

        # Low content similarity
        elif similarity < 0.85:
            is_valid = True
            confidence = 0.6
            evidence = f"Response content changed (similarity: {similarity:.2f})"

        # Status code change
        elif status_changed:
            is_valid = True
            confidence = 0.8
            evidence = f"Status code changed from {baseline['status']} to {status_code}"

        if is_valid:
            return DiscoveredParameter(
                name=param,
                method="",  # set by caller
                evidence=evidence,
                confidence=confidence,
                response_diff=1.0 - similarity,
                reflected=reflected,
            )

        return None

    def _extract_js_params(self, content: str) -> set[str]:
        """Extract parameters from JavaScript"""
        params = set()

        # Look for parameter patterns in JS
        patterns = [
            r"[\?&](\w+)=",  # URL params
            r'params\[[\'"](w+)[\'\"]\]',  # params['name']
            r'\.(\w+)\s*=\s*[\'"]',  # .param = 'value'
            r'data\s*:\s*\{[^}]*[\'"](\w+)[\'"]',  # data: {'param': }
            r'name[\'"]\s*:\s*[\'"](\w+)[\'"]',  # 'name': 'param'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content)
            params.update(matches)

        return params

    def _extract_form_params(self, content: str) -> set[str]:
        """Extract parameters from HTML forms"""
        params = set()

        # Input name attributes
        input_pattern = r'<input[^>]*name=[\'"](\w+)[\'"]'
        params.update(re.findall(input_pattern, content, re.IGNORECASE))

        # Textarea name attributes
        textarea_pattern = r'<textarea[^>]*name=[\'"](\w+)[\'"]'
        params.update(re.findall(textarea_pattern, content, re.IGNORECASE))

        # Select name attributes
        select_pattern = r'<select[^>]*name=[\'"](\w+)[\'"]'
        params.update(re.findall(select_pattern, content, re.IGNORECASE))

        # Hidden inputs
        hidden_pattern = r'<input[^>]*type=[\'"]hidden[\'"][^>]*name=[\'"](\w+)[\'"]'
        params.update(re.findall(hidden_pattern, content, re.IGNORECASE))

        return params

    def _extract_comment_params(self, content: str) -> set[str]:
        """Extract parameters from HTML comments"""
        params = set()

        # Find comments
        comments = re.findall(r"<!--(.*?)-->", content, re.DOTALL)

        for comment in comments:
            # Look for param patterns in comments
            param_pattern = r"(\w+)\s*="
            params.update(re.findall(param_pattern, comment))

        return params

    def _extract_data_attrs(self, content: str) -> set[str]:
        """Extract from data-* attributes"""
        params = set()

        # data-param-name or data-paramname
        data_pattern = r"data-(\w+)="
        matches = re.findall(data_pattern, content, re.IGNORECASE)

        for match in matches:
            # Convert data-user-id to user_id
            param = match.replace("-", "_")
            params.add(param)

        return params

    def get_statistics(self) -> dict[str, int]:
        """Get miner statistics"""
        return {
            "params_tested": self.params_tested,
            "params_found": self.params_found,
            "wordlist_size": len(self.wordlist),
        }
