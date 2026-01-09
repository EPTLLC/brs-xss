#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 26 Dec 2025 UTC
Status: Updated - Crawler integration
Telegram: https://t.me/EasyProTech

Scanner service with full Crawler integration for Web UI.
"""

import asyncio
import time
import uuid
from typing import Optional, Callable, Any, Dict
from urllib.parse import urlparse, parse_qs

from .models import (
    ScanRequest,
    ScanProgress,
    ScanStatus,
    VulnerabilityInfo,
    WAFInfo,
    SeverityLevel,
)
from .storage import ScanStorage
from brsxss.utils.logger import Logger

logger = Logger("web_ui.scanner_service")


class ScannerService:
    """
    Service layer for scanner operations.

    Wraps brsxss core scanner with:
    - Target reconnaissance (intelligence gathering)
    - Crawler integration for URL/form discovery
    - Progress tracking via WebSocket
    - Result persistence
    """

    def __init__(
        self,
        storage: ScanStorage,
        progress_callback: Optional[Callable[[ScanProgress], Any]] = None,
        vulnerability_callback: Optional[
            Callable[[str, VulnerabilityInfo], Any]
        ] = None,
        recon_callback: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
    ):
        self.storage = storage
        self.progress_callback = progress_callback
        self.vulnerability_callback = vulnerability_callback
        self.recon_callback = recon_callback
        self._scanner = None
        self._crawler = None
        self._http_client = None
        self._http_client_pool_size = None
        self._http_client_proxy_sig = None
        self._target_profiler = None
        self._active_scans: dict = {}
        self._cancelled_scans: set = set()
        self._kb_payload_cache: Dict[str, Dict[str, Any]] = {}

    def _get_proxy_signature(self, settings) -> Optional[tuple]:
        """
        Build a stable signature for current proxy settings.
        Returns None if proxy disabled or incomplete.
        """
        try:
            proxy = getattr(settings, "proxy", None)
            if not proxy or not getattr(proxy, "enabled", False):
                return None
            host = getattr(proxy, "host", "") or ""
            port = int(getattr(proxy, "port", 0) or 0)
            if not host or port <= 0:
                return None
            protocol = getattr(proxy, "protocol", None)
            proto_value = (
                protocol.value
                if hasattr(protocol, "value")
                else str(protocol or "socks5")
            )
            username = getattr(proxy, "username", None)
            password = getattr(proxy, "password", None)
            return (
                True,
                host,
                port,
                proto_value.lower(),
                username or "",
                password or "",
            )
        except Exception:
            return None

    def _build_proxy_config(self, settings):
        """Convert SettingsModel.proxy into brsxss.core.proxy_manager.ProxyConfig (or None)."""
        sig = self._get_proxy_signature(settings)
        if sig is None:
            return None
        _, host, port, proto_value, username, password = sig
        try:
            from brsxss.core.proxy_manager import ProxyConfig, ProxyProtocol

            proto = ProxyProtocol(proto_value)
            return ProxyConfig(
                enabled=True,
                host=host,
                port=port,
                username=username or None,
                password=password or None,
                protocol=proto,
            )
        except Exception as exc:
            logger.debug(f"Proxy config build failed: {exc}")
            return None

    def _normalize_kb_payload_info(self, payload: str, raw: Any) -> Dict[str, Any]:
        """Normalize KB analyze response into VulnerabilityInfo-compatible payload fields."""
        if not raw or not isinstance(raw, dict):
            return {}
        data = raw.get("payload") or raw.get("result") or raw.get("data") or raw
        if not isinstance(data, dict):
            return {}

        payload_id = data.get("id") or data.get("payload_id") or data.get("key")
        payload_name = data.get("name") or data.get("title") or None
        payload_description = data.get("description") or data.get("details") or None
        severity = data.get("severity") or data.get("risk") or None
        cvss_score = data.get("cvss_score") or data.get("cvss") or None
        contexts = data.get("contexts") or data.get("context_types") or None
        tags = data.get("tags") or data.get("labels") or None

        def _norm_list(value):
            if not isinstance(value, list):
                return None
            out = []
            for item in value:
                if isinstance(item, str):
                    v = item.strip()
                    if v:
                        out.append(v)
                elif isinstance(item, dict):
                    v = (
                        item.get("name") or item.get("id") or item.get("key") or ""
                    ).strip()
                    if v:
                        out.append(v)
            return out or None

        try:
            cvss_score = float(cvss_score) if cvss_score is not None else None
        except Exception:
            cvss_score = None

        if isinstance(severity, str):
            severity = severity.strip().lower() or None

        normalized = {
            "id": payload_id,
            "name": payload_name,
            "description": payload_description,
            "severity": severity,
            "cvss_score": cvss_score,
            "contexts": _norm_list(contexts),
            "tags": _norm_list(tags),
        }
        return normalized

    async def _get_payload_kb_info(self, payload: str) -> Dict[str, Any]:
        """Get payload metadata from KB (remote) with in-memory cache."""
        payload = payload or ""
        if not payload:
            return {}
        cached = self._kb_payload_cache.get(payload)
        if cached is not None:
            return cached

        info: Dict[str, Any] = {}
        try:
            from brsxss.payloads.kb_adapter import get_kb_adapter

            kb = get_kb_adapter()
            if getattr(kb, "is_available", False):
                loop = asyncio.get_running_loop()
                raw = await loop.run_in_executor(None, kb.analyze_payload, payload)
                info = self._normalize_kb_payload_info(payload, raw)
        except Exception as e:
            logger.debug(f"KB analyze error: {e}")

        self._kb_payload_cache[payload] = info
        return info

    async def _get_http_client(self, pool_size: Optional[int] = None):
        """Get or create shared HTTP client (applies proxy settings if enabled)."""
        desired_pool = pool_size or self._http_client_pool_size or 64
        if self._http_client is None or self._http_client_pool_size != desired_pool:
            try:
                from brsxss.core.http_client import HTTPClient

                connector_limit = desired_pool
                per_host = max(10, desired_pool // 4)
                if self._http_client:
                    await self._http_client.close()
                self._http_client = HTTPClient(
                    timeout=15,
                    verify_ssl=True,
                    connector_limit=connector_limit,
                    connector_limit_per_host=per_host,
                )
                self._http_client_pool_size = desired_pool
                self._http_client_proxy_sig = None
            except ImportError:
                self._http_client = None
                return self._http_client

        # Apply (or remove) proxy settings if changed
        try:
            settings = self.storage.get_settings()
            sig = self._get_proxy_signature(settings)
            if sig != self._http_client_proxy_sig:
                proxy_cfg = self._build_proxy_config(settings)
                if self._http_client:
                    self._http_client.set_proxy(proxy_cfg)
                    if proxy_cfg:
                        logger.debug(
                            "Proxy applied: %s://%s:%s",
                            proxy_cfg.protocol.value,
                            proxy_cfg.host,
                            proxy_cfg.port,
                        )
                    else:
                        logger.debug("Proxy disabled")
                self._http_client_proxy_sig = sig
        except Exception as e:
            logger.debug(f"Proxy apply error: {e}")
        return self._http_client

    async def _get_scanner(
        self, max_payloads: Optional[int] = None, perf: Optional[Dict[str, Any]] = None
    ):
        """Get or create scanner instance with shared HTTP client"""
        try:
            from brsxss.core import XSSScanner

            http_client = await self._get_http_client(
                perf.get("http_pool_size") if perf else None
            )
            dom_workers = perf.get("dom_workers", 2) if perf else 2
            dom_gpu = perf.get("gpu_available", False) if perf else False
            scanner = XSSScanner(
                max_payloads=max_payloads,
                max_concurrent=perf.get("threads", 10) if perf else 10,
                http_client=http_client,
                dom_workers=dom_workers,
                dom_use_gpu=dom_gpu,
            )
            scanner.scan_start_time = time.time()
            return scanner
        except ImportError as e:
            print(f"Warning: Could not import XSSScanner: {e}")
            return None

    async def _get_crawler(self, config: dict):
        """Get crawler instance with shared HTTP client"""
        try:
            from brsxss.crawler import CrawlerEngine, CrawlConfig

            http_client = await self._get_http_client()

            crawl_config = CrawlConfig(
                max_depth=config.get("max_depth", 2),
                max_urls=config.get("max_urls", 50),
                max_concurrent=config.get("max_concurrent", 5),
                request_delay=config.get("request_delay", 0.2),
                extract_forms=True,
                extract_links=True,
            )
            return CrawlerEngine(crawl_config, http_client=http_client)
        except ImportError as e:
            print(f"Warning: Could not import CrawlerEngine: {e}")
            return None

    async def _get_target_profiler(self):
        """Get target profiler instance with shared HTTP client"""
        if self._target_profiler is None:
            try:
                from brsxss.reconnaissance import TargetProfiler

                http_client = await self._get_http_client()
                self._target_profiler = TargetProfiler(
                    http_client=http_client, timeout=30.0, enable_filter_probe=True
                )
            except ImportError as e:
                print(f"Warning: Could not import TargetProfiler: {e}")
                self._target_profiler = None
        return self._target_profiler

    async def start_scan(self, request: ScanRequest) -> str:
        """Start a new scan with crawling."""
        scan_id = str(uuid.uuid4())[:12]

        # Get performance mode from request
        perf_mode = getattr(request, "performance_mode", None)
        perf_mode_value = perf_mode.value if perf_mode else "standard"

        # Get current proxy settings to record with scan
        settings = self.storage.get_settings()
        proxy_used: dict
        if (
            settings.proxy
            and settings.proxy.enabled
            and settings.proxy.host
            and settings.proxy.port
        ):
            proxy_used = {
                "enabled": True,
                "ip": f"{settings.proxy.host}:{settings.proxy.port}",
                "country": settings.proxy.country,
                "country_code": settings.proxy.country_code,
            }
        else:
            proxy_used = {"enabled": False}

        self.storage.create_scan(
            scan_id=scan_id,
            url=request.target_url,
            mode=request.mode,
            performance_mode=perf_mode_value,
            settings=request.model_dump(),
            proxy_used=proxy_used,
        )

        self.storage.update_scan_status(scan_id, ScanStatus.RUNNING)

        self._active_scans[scan_id] = {
            "request": request,
            "started_at": time.time(),
            "cancelled": False,
        }

        # Notify Telegram about scan start
        asyncio.create_task(
            self._notify_telegram_start(
                scan_id, request.target_url, request.mode.value, proxy_used
            )
        )

        asyncio.create_task(self._run_scan(scan_id, request))
        return scan_id

    async def _notify_telegram_start(
        self, scan_id: str, target: str, mode: str, proxy_used: dict
    ):
        """Notify Telegram about scan start"""
        try:
            from brsxss.integrations.telegram_service import telegram_service

            proxy_info = None
            if proxy_used.get("enabled"):
                country = proxy_used.get("country", "")
                ip = proxy_used.get("ip", "")
                proxy_info = f"{country} ({ip})" if country else ip

            await telegram_service.on_scan_started(
                scan_id=scan_id, target=target, mode=mode, proxy_info=proxy_info
            )
        except Exception as e:
            print(f"Telegram notify error: {e}")

    def _extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if v else "" for k, v in params.items()}

    def _get_base_url(self, url: str) -> str:
        """Get base URL without query parameters"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _get_performance_settings(self, requested_mode: str = None) -> Dict[str, Any]:
        """
        Get performance mode settings.

        Args:
            requested_mode: Performance mode from scan request (overrides saved)
        """
        try:
            from .system_info import get_system_detector

            detector = get_system_detector()
            info = detector.get_system_info()

            # Use requested mode if provided, otherwise use saved
            mode_name = requested_mode or info.get("saved_mode", "standard")
            mode_config = info["modes"].get(mode_name, info["modes"]["standard"])

            return {
                "threads": mode_config["threads"],
                "max_concurrent": mode_config["max_concurrent"],
                "requests_per_second": mode_config["requests_per_second"],
                "request_delay_ms": mode_config["request_delay_ms"],
                "dom_workers": mode_config.get(
                    "dom_workers", max(1, mode_config["threads"] // 4)
                ),
                "playwright_browsers": mode_config.get("playwright_browsers", 2),
                "http_pool_size": mode_config.get("http_pool_size", 64),
                "gpu_available": info["system"].get("gpu_count", 0) > 0,
                "mode_name": mode_name,
            }
        except Exception as e:
            print(f"Could not get performance settings: {e}")
            return {
                "threads": 5,
                "max_concurrent": 5,
                "requests_per_second": 50,
                "request_delay_ms": 20,
                "dom_workers": 2,
                "playwright_browsers": 1,
                "http_pool_size": 32,
                "gpu_available": False,
                "mode_name": "standard",
            }

    async def _run_scan(self, scan_id: str, request: ScanRequest):
        """Run full scan with reconnaissance and crawling"""
        start_time = time.time()
        urls_scanned = 0
        forms_scanned = 0
        payloads_sent = 0
        parameters_tested = 0
        all_vulnerabilities = []
        target_profile = None

        try:
            # Get performance settings - use mode from request if provided
            perf_mode = getattr(request, "performance_mode", None)
            perf_mode_value = perf_mode.value if perf_mode else None
            perf = self._get_performance_settings(perf_mode_value)
            await self._get_http_client(perf.get("http_pool_size"))

            # Determine payload limit based on scan mode
            mode_limits = {"quick": 50, "standard": 200, "deep": None, "stealth": 100}
            max_payloads = mode_limits.get(request.mode.value, 200)

            # Crawl limits based on scan mode + performance settings
            base_crawl = {
                "quick": {"max_depth": 1, "max_urls": 10},
                "standard": {"max_depth": 2, "max_urls": 30},
                "deep": {"max_depth": 3, "max_urls": 100},
                "stealth": {"max_depth": 1, "max_urls": 15},
            }
            crawl_config = base_crawl.get(request.mode.value, base_crawl["standard"])
            # Apply performance mode concurrency
            crawl_config["max_concurrent"] = perf["max_concurrent"]
            crawl_config["request_delay"] = perf["request_delay_ms"] / 1000.0

            # Phase 0: Target Reconnaissance (NEW!)
            await self._notify_progress(
                ScanProgress(
                    scan_id=scan_id,
                    status=ScanStatus.RUNNING,
                    progress_percent=2,
                    current_phase="reconnaissance",
                    current_url=request.target_url,
                    elapsed_seconds=0,
                )
            )

            target_profile = await self._run_reconnaissance(scan_id, request.target_url)

            if self._is_cancelled(scan_id):
                self.storage.update_scan_status(scan_id, ScanStatus.CANCELLED)
                return

            # Store target profile
            if target_profile:
                self.storage.set_target_profile(scan_id, target_profile)

                # Adjust max_payloads based on reconnaissance
                if target_profile.get("risk") and target_profile["risk"].get(
                    "estimated_payloads"
                ):
                    estimated = target_profile["risk"]["estimated_payloads"]
                    if request.mode.value != "deep":
                        max_payloads = min(max_payloads or 200, estimated)
                        print(f"[RECON] Optimized payload count: {max_payloads}")

                # Use WAF from reconnaissance
                if target_profile.get("waf") and target_profile["waf"].get("detected"):
                    waf_data = target_profile["waf"]
                    waf_info = WAFInfo(
                        name=waf_data.get("name", "Unknown"),
                        type=waf_data.get("waf_type", "unknown"),
                        confidence=waf_data.get("confidence", 0.5),
                        bypass_available=bool(waf_data.get("known_bypasses")),
                    )
                    self.storage.set_waf_info(scan_id, waf_info)

            # Phase 1: Initialization
            await self._notify_progress(
                ScanProgress(
                    scan_id=scan_id,
                    status=ScanStatus.RUNNING,
                    progress_percent=18,
                    current_phase="initializing",
                    elapsed_seconds=time.time() - start_time,
                )
            )

            if self._is_cancelled(scan_id):
                self.storage.update_scan_status(scan_id, ScanStatus.CANCELLED)
                return

            # Skip separate WAF detection if we have it from recon
            waf_info = None
            if not target_profile or not target_profile.get("waf", {}).get("detected"):
                # Phase 2: WAF Detection (fallback)
                await self._notify_progress(
                    ScanProgress(
                        scan_id=scan_id,
                        status=ScanStatus.RUNNING,
                        progress_percent=20,
                        current_phase="waf_detection",
                        current_url=request.target_url,
                        elapsed_seconds=time.time() - start_time,
                    )
                )

                waf_info = await self._detect_waf(request.target_url)
                if waf_info:
                    self.storage.set_waf_info(scan_id, waf_info)

            # Phase 3: Crawling
            await self._notify_progress(
                ScanProgress(
                    scan_id=scan_id,
                    status=ScanStatus.RUNNING,
                    progress_percent=15,
                    current_phase="crawling",
                    current_url=request.target_url,
                    elapsed_seconds=time.time() - start_time,
                )
            )

            # Collect scan targets: URLs with params + forms
            scan_targets = []

            # Get target domain for scope filtering
            target_parsed = urlparse(request.target_url)
            target_domain = target_parsed.netloc.lower()

            def is_in_scope(url: str) -> bool:
                """Check if URL is in scope (same domain)"""
                try:
                    parsed = urlparse(url)
                    url_domain = parsed.netloc.lower()
                    # Same domain or subdomain
                    return url_domain == target_domain or url_domain.endswith(
                        "." + target_domain
                    )
                except Exception:
                    return False

            # Always add original URL - even without parameters for DOM XSS
            # DOM XSS works through forms, storage, fragments - not just URL params
            url_params = self._extract_parameters(request.target_url)
            scan_targets.append(
                {
                    "url": request.target_url,  # Keep full URL for DOM XSS
                    "method": "GET",
                    "params": url_params
                    or {},  # Empty dict if no params - DOM XSS still works
                    "source": "input",
                }
            )

            # Use discovered endpoints from reconnaissance
            if target_profile and target_profile.get("discovered_endpoints"):
                discovered = target_profile["discovered_endpoints"]
                endpoints = discovered.get("endpoints", [])

                print(
                    f"[RECON] Using {len(endpoints)} discovered endpoints from reconnaissance"
                )

                for ep in endpoints:
                    if not is_in_scope(ep.get("url", "")):
                        continue

                    ep_params = {}
                    for param_name in ep.get("parameters", []):
                        ep_params[param_name] = "test"

                    if ep_params:
                        scan_targets.append(
                            {
                                "url": self._get_base_url(ep["url"]),
                                "method": ep.get("method", "GET").upper(),
                                "params": ep_params,
                                "source": f"recon_{ep.get('source', 'discovery')}",
                            }
                        )

            # Crawl for more targets (if not enough from recon)
            crawl_config["max_concurrent"] = perf["max_concurrent"]
            crawl_config["request_delay"] = perf["request_delay_ms"] / 1000.0
            crawler = await self._get_crawler(crawl_config)
            if crawler:
                try:
                    crawl_results = await crawler.crawl(request.target_url)
                    crawler.get_crawl_stats()

                    # Extract URLs with parameters
                    for result in crawl_results:
                        if self._is_cancelled(scan_id):
                            break

                        # Check discovered URLs for parameters (only in scope)
                        for discovered in result.discovered_urls:
                            if not is_in_scope(discovered.url):
                                continue
                            discovered_params = self._extract_parameters(discovered.url)
                            if discovered_params:
                                scan_targets.append(
                                    {
                                        "url": self._get_base_url(discovered.url),
                                        "method": "GET",
                                        "params": discovered_params,
                                        "source": "crawl",
                                    }
                                )

                        # Extract forms (only in scope)
                        print(
                            f"[CRAWLER] Found {len(result.extracted_forms)} forms on {result.url}"
                        )
                        for form_idx, form in enumerate(result.extracted_forms):
                            print(
                                f"[CRAWLER] Form {form_idx+1}: action='{form.action}', method='{form.method}', fields={len(form.fields)}"
                            )
                            form_action = form.action or result.url
                            if not is_in_scope(form_action):
                                continue

                            # Check if form is JavaScript-handled (no real action or action="?")
                            # JavaScript forms should be tested via DOM XSS, not POST
                            # Also check if form has onsubmit handler (indicates JS processing)
                            is_js_form = (
                                not form.action
                                or form.action == "?"
                                or form.action == "#"
                                or form.action
                                == result.url  # Same URL = likely JS handled
                                or (
                                    form.action and form.action.endswith("?")
                                )  # action="?" pattern
                                or (
                                    form.action
                                    and form.action == urlparse(result.url).path + "?"
                                )  # Relative "?"
                            )

                            form_params = {}
                            for field in form.fields:
                                field_name = getattr(field, "name", None)
                                if field_name:
                                    form_params[field_name] = (
                                        getattr(field, "value", "") or "test"
                                    )

                            if form_params:
                                if is_js_form:
                                    # JavaScript-handled form: add as DOM XSS target (no POST, just DOM testing)
                                    # Use source URL for DOM XSS testing
                                    form_dom_target = {
                                        "url": result.url,  # Use page URL, not form action
                                        "method": "GET",  # DOM XSS doesn't need POST
                                        "params": {},  # Empty - DOM XSS will test form via browser
                                        "source": "form_dom",
                                        "form_info": {  # Store form info for DOM XSS detector
                                            "fields": form_params,
                                            "form_id": getattr(form, "form_id", None),
                                            "form_class": getattr(
                                                form, "form_class", None
                                            ),
                                        },
                                    }
                                    scan_targets.append(form_dom_target)
                                    forms_scanned += 1
                                    print(
                                        f"[FORM] JavaScript-handled form detected: {result.url}"
                                    )
                                    print(f"[FORM] Form fields: {form_params}")
                                    print(
                                        f"[FORM] Added form_dom target: {form_dom_target['url']}"
                                    )
                                else:
                                    # Regular form: test via POST/GET
                                    scan_targets.append(
                                        {
                                            "url": form_action,
                                            "method": (
                                                form.method.upper()
                                                if form.method
                                                else "POST"
                                            ),
                                            "params": form_params,
                                            "source": "form",
                                        }
                                    )
                                    forms_scanned += 1

                    await crawler.close()

                except Exception as e:
                    print(f"Crawler error: {e}")

            # Deduplicate targets
            seen = set()
            unique_targets = []
            for target in scan_targets:
                key = (
                    target["url"],
                    target["method"],
                    tuple(sorted(target["params"].keys())),
                )
                if key not in seen:
                    seen.add(key)
                    unique_targets.append(target)

            total_targets = len(unique_targets)

            # Fallback: if deduplication somehow removed everything, add original URL
            if not unique_targets:
                unique_targets.append(
                    {
                        "url": request.target_url,  # Keep original URL for DOM XSS
                        "method": "GET",
                        "params": {},  # Empty - DOM XSS doesn't need URL params
                        "source": "fallback",
                    }
                )
                total_targets = 1
                print(
                    f"[FALLBACK] No targets found, using original URL for DOM XSS: {request.target_url}"
                )

            # Phase 4: Scanning
            await self._notify_progress(
                ScanProgress(
                    scan_id=scan_id,
                    status=ScanStatus.RUNNING,
                    progress_percent=25,
                    current_phase="scanning",
                    urls_total=total_targets,
                    elapsed_seconds=time.time() - start_time,
                )
            )

            scanner = await self._get_scanner(max_payloads=max_payloads, perf=perf)
            if scanner is None:
                raise Exception("Scanner not available - brsxss not installed")

            # Parallel scanning - adapts to machine capacity via performance mode
            max_parallel_targets = perf.get("max_concurrent", 10)
            print(
                f"[PERF] Using performance mode: {perf['mode_name']} - {max_parallel_targets} parallel targets, {perf['threads']} threads"
            )

            # Thread-safe state for parallel scanning
            import threading

            scan_lock = threading.Lock()
            seen_vuln_keys: set = set()
            urls_scanned_counter = [0]
            parameters_tested_counter = [0]

            async def scan_single_target(
                target: Dict[str, Any],
                semaphore: asyncio.Semaphore,
            ) -> list:
                """Scan single target with semaphore-controlled parallelism.

                Adapts to machine capacity - weak machines get fewer parallel tasks,
                powerful machines get more (controlled by max_parallel_targets from perf mode).
                """
                async with semaphore:
                    if self._is_cancelled(scan_id):
                        return []

                    target_url = target["url"]
                    target_method = target["method"]
                    target_params = target["params"]
                    form_info = target.get("form_info")
                    target_vulns = []

                    try:
                        # Pass form_info to scanner for DOM XSS detection
                        if form_info and scanner.dom_detector:
                            scanner._current_target_form_info = form_info

                        results = await scanner.scan_url(
                            target_url, method=target_method, parameters=target_params
                        )

                        print(
                            f"[SCAN] scan_url returned {len(results)} results for {target_url}"
                        )

                        # Clear form_info after scan
                        if hasattr(scanner, "_current_target_form_info"):
                            delattr(scanner, "_current_target_form_info")

                        # Update counters thread-safely
                        with scan_lock:
                            urls_scanned_counter[0] += 1
                            parameters_tested_counter[0] += len(target_params)

                        # Process vulnerabilities
                        for vuln in results:
                            if not vuln or vuln.get("vulnerable") is False:
                                continue

                            payload_str = vuln.get("payload", "")
                            kb_info = await self._get_payload_kb_info(payload_str)

                            # KB is source of truth for severity
                            kb_severity = kb_info.get("severity")
                            scanner_severity = vuln.get("severity")
                            final_severity = (
                                kb_severity
                                if kb_severity
                                else (
                                    scanner_severity if scanner_severity else "medium"
                                )
                            )

                            # Determine XSS type
                            reflection_type = vuln.get("reflection_type", "")
                            xss_type_from_vuln = vuln.get("xss_type", "")
                            ctx = vuln.get("context", vuln.get("context_type", "html"))

                            is_dom_xss = (
                                reflection_type == "dom_based"
                                or xss_type_from_vuln == "DOM-based XSS"
                                or "DOM" in ctx
                                or "dom" in ctx.lower()
                                or "->" in ctx
                            )

                            # Handle evidence
                            evidence_value = vuln.get("evidence") or vuln.get(
                                "response_snippet"
                            )
                            if isinstance(evidence_value, list):
                                evidence_str = "; ".join(
                                    [
                                        f"{e.get('trigger', 'unknown')}: {e.get('payload', '')[:50]}"
                                        for e in evidence_value[:3]
                                    ]
                                )
                            else:
                                evidence_str = evidence_value or ""

                            # Improve parameter field for DOM XSS
                            param = vuln.get("parameter", "unknown")
                            if is_dom_xss and (
                                not param or param == "N/A" or param == "unknown"
                            ):
                                if "->" in ctx:
                                    source = ctx.split("->")[0].strip()
                                    param = f"DOM source: {source}"
                                else:
                                    param = "DOM source: form input"

                            vuln_info = VulnerabilityInfo(
                                url=target_url,
                                parameter=param,
                                context_type=ctx,
                                severity=self._map_severity(final_severity),
                                confidence=vuln.get("confidence", 0.8),
                                payload=payload_str,
                                payload_id=kb_info.get("id"),
                                payload_name=kb_info.get("name"),
                                payload_description=kb_info.get("description"),
                                payload_contexts=kb_info.get("contexts"),
                                payload_tags=kb_info.get("tags"),
                                cvss_score=kb_info.get("cvss_score"),
                                evidence=evidence_str,
                                waf_detected=waf_info.name if waf_info else None,
                            )

                            # Store additional metadata
                            vuln_info._xss_type = (
                                "DOM-Based XSS" if is_dom_xss else "Reflected XSS"
                            )
                            vuln_info._reflection_type = reflection_type
                            vuln_info._sink = (
                                ctx.split("->")[-1].strip() if "->" in ctx else ""
                            )
                            vuln_info._source = (
                                ctx.split("->")[0].strip() if "->" in ctx else ""
                            )

                            # Deduplicate thread-safely
                            sink_for_dedup = vuln_info._sink or "none"
                            dedup_key = (target_url, sink_for_dedup, payload_str)

                            with scan_lock:
                                if dedup_key in seen_vuln_keys:
                                    continue
                                seen_vuln_keys.add(dedup_key)

                            target_vulns.append(vuln_info)

                            # Save and notify
                            self.storage.add_vulnerability(scan_id, vuln_info)
                            if self.vulnerability_callback:
                                await self.vulnerability_callback(scan_id, vuln_info)
                            asyncio.create_task(
                                self._notify_telegram_vuln(scan_id, vuln_info)
                            )

                    except Exception as e:
                        print(f"Error scanning {target_url}: {e}")

                    return target_vulns

            # Semaphore controls parallelism - adapts to machine capacity
            parallel_semaphore = asyncio.Semaphore(max_parallel_targets)

            # Background progress updater - updates both WebSocket and storage
            async def update_progress_loop():
                while not self._is_cancelled(scan_id):
                    with scan_lock:
                        current_scanned = urls_scanned_counter[0]
                        current_params = parameters_tested_counter[0]
                    if current_scanned >= total_targets:
                        break
                    progress_pct = 25 + int(
                        (current_scanned / max(1, total_targets)) * 65
                    )
                    # Update storage for API polling
                    self.storage.update_scan_progress(
                        scan_id,
                        urls_scanned=current_scanned,
                        parameters_tested=current_params,
                        duration_seconds=time.time() - start_time,
                    )
                    # Notify WebSocket clients
                    await self._notify_progress(
                        ScanProgress(
                            scan_id=scan_id,
                            status=ScanStatus.RUNNING,
                            progress_percent=min(progress_pct, 90),
                            current_phase="scanning",
                            current_url=f"Parallel: {current_scanned}/{total_targets}",
                            urls_scanned=current_scanned,
                            urls_total=total_targets,
                            elapsed_seconds=time.time() - start_time,
                        )
                    )
                    await asyncio.sleep(1.0)  # Update every second

            # Start progress updater
            progress_task = asyncio.create_task(update_progress_loop())

            # Run all scans in parallel with adaptive semaphore control
            print(
                f"[PARALLEL] Starting {total_targets} targets with {max_parallel_targets} concurrent (adapts to machine)"
            )
            tasks = [scan_single_target(t, parallel_semaphore) for t in unique_targets]
            results_lists = await asyncio.gather(*tasks, return_exceptions=True)

            # Stop progress updater
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass

            # Collect results
            for result in results_lists:
                if isinstance(result, list):
                    all_vulnerabilities.extend(result)
                elif isinstance(result, Exception):
                    print(f"[PARALLEL] Task error: {result}")

            urls_scanned = urls_scanned_counter[0]
            parameters_tested = parameters_tested_counter[0]
            print(
                f"[PARALLEL] Done: {urls_scanned} URLs, {len(all_vulnerabilities)} vulns"
            )

            # Get real statistics from scanner
            if hasattr(scanner, "get_scan_statistics"):
                stats = scanner.get_scan_statistics()
                payloads_sent = stats.get("total_tests", 0)

            await scanner.close()

            # Phase 5: Finalizing
            await self._notify_progress(
                ScanProgress(
                    scan_id=scan_id,
                    status=ScanStatus.RUNNING,
                    progress_percent=95,
                    current_phase="finalizing",
                    urls_scanned=urls_scanned,
                    urls_total=total_targets,
                    vulnerabilities_found=len(all_vulnerabilities),
                    elapsed_seconds=time.time() - start_time,
                )
            )

            # Update storage with real results
            self.storage.update_scan_progress(
                scan_id,
                urls_scanned=urls_scanned,
                parameters_tested=parameters_tested,
                payloads_sent=payloads_sent,
                duration_seconds=time.time() - start_time,
            )

            # Completion
            await self._notify_progress(
                ScanProgress(
                    scan_id=scan_id,
                    status=ScanStatus.COMPLETED,
                    progress_percent=100,
                    current_phase="completed",
                    urls_scanned=urls_scanned,
                    urls_total=total_targets,
                    vulnerabilities_found=len(all_vulnerabilities),
                    elapsed_seconds=time.time() - start_time,
                )
            )

            self.storage.update_scan_status(scan_id, ScanStatus.COMPLETED)

            # Notify Telegram about completion
            # Get proxy info string from storage
            proxy_str = ""
            try:
                proxy_data = self.storage.get_proxy_used(scan_id)
                if proxy_data and proxy_data.get("enabled") and proxy_data.get("ip"):
                    country = proxy_data.get("country", "")
                    proxy_str = (
                        f"{country} ({proxy_data['ip']})"
                        if country
                        else proxy_data["ip"]
                    )
            except Exception:
                pass

            asyncio.create_task(
                self._notify_telegram_complete(
                    scan_id=scan_id,
                    target=request.target_url,
                    mode=request.mode.value,
                    proxy=proxy_str,
                    duration_seconds=time.time() - start_time,
                    urls_scanned=urls_scanned,
                    payloads_sent=payloads_sent,
                    vulnerabilities=all_vulnerabilities,
                    target_profile=target_profile,
                )
            )

        except Exception as e:
            import traceback

            traceback.print_exc()

            self.storage.update_scan_status(
                scan_id, ScanStatus.FAILED, error_message=str(e)
            )

            # Notify Telegram about failure
            asyncio.create_task(self._notify_telegram_failed(scan_id, str(e)))

            await self._notify_progress(
                ScanProgress(
                    scan_id=scan_id,
                    status=ScanStatus.FAILED,
                    progress_percent=0,
                    current_phase="failed",
                    elapsed_seconds=time.time() - start_time,
                )
            )

        finally:
            if scan_id in self._active_scans:
                del self._active_scans[scan_id]

            # Cleanup HTTP client
            if self._http_client:
                try:
                    await self._http_client.close()
                except Exception:
                    pass
                self._http_client = None

    async def _run_reconnaissance(
        self, scan_id: str, url: str
    ) -> Optional[Dict[str, Any]]:
        """Run target reconnaissance phase"""
        try:
            profiler = await self._get_target_profiler()
            if not profiler:
                print("[RECON] Target profiler not available, skipping reconnaissance")
                return None

            print(f"[RECON] Starting reconnaissance for {url}")

            # Extract parameters from URL
            parsed = urlparse(url)
            parameters = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            # Define progress callback for recon phases
            async def recon_progress_callback(phase: str, percent: int):
                # Map recon percent (0-100) to scan percent (2-18)
                scan_percent = 2 + int(percent * 0.16)
                await self._notify_progress(
                    ScanProgress(
                        scan_id=scan_id,
                        status=ScanStatus.RUNNING,
                        progress_percent=scan_percent,
                        current_phase=f"recon_{phase}",
                        current_url=url,
                        elapsed_seconds=0,
                    )
                )

                # Send recon-specific callback
                if self.recon_callback:
                    await self.recon_callback(
                        scan_id, {"phase": phase, "percent": percent}
                    )

            profiler.progress_callback = recon_progress_callback

            # Run reconnaissance
            profile = await profiler.profile_target(
                url=url, scan_id=scan_id, parameters=parameters if parameters else None
            )

            if profile:
                profile_dict = profile.to_dict()
                print(
                    f"[RECON] Complete: {profile.domain}, duration: {profile.recon_duration_seconds:.2f}s"
                )

                # Send final recon data via callback
                if self.recon_callback:
                    await self.recon_callback(
                        scan_id, {"phase": "complete", "profile": profile_dict}
                    )

                return profile_dict

        except Exception as e:
            import traceback

            traceback.print_exc()
            print(f"[RECON] Error: {e}")

        return None

    async def _detect_waf(self, url: str) -> Optional[WAFInfo]:
        """Detect WAF on target"""
        try:
            http_client = await self._get_http_client()
            if not http_client:
                return None
            response = await http_client.get(url, timeout=10)
            if not response or getattr(response, "status_code", 0) <= 0:
                return None

            headers = dict(getattr(response, "headers", {}) or {})
            content = getattr(response, "text", "") or ""

            waf_signatures = {
                "cloudflare": ["cf-ray", "cf-cache-status", "cloudflare"],
                "akamai": ["akamai", "x-akamai"],
                "aws-waf": ["x-amzn-waf", "awswaf"],
                "imperva": ["incap_ses", "visid_incap"],
                "f5": ["x-cnection", "bigip"],
                "modsecurity": ["mod_security", "modsec"],
                "sucuri": ["x-sucuri", "sucuri"],
            }

            headers_str = str(headers).lower()
            content_lower = content.lower()[:5000]

            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig in headers_str or sig in content_lower:
                        return WAFInfo(
                            name=waf_name.upper(),
                            type=(
                                "cloud"
                                if waf_name
                                in ["cloudflare", "akamai", "aws-waf", "sucuri"]
                                else "host"
                            ),
                            confidence=0.85,
                            bypass_available=True,
                        )
        except Exception as e:
            print(f"WAF detection error: {e}")
        return None

    def _map_severity(self, severity: str) -> SeverityLevel:
        """Map severity string to enum"""
        if isinstance(severity, SeverityLevel):
            return severity
        mapping = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        return mapping.get(str(severity).lower(), SeverityLevel.MEDIUM)

    async def _notify_progress(self, progress: ScanProgress):
        """Send progress notification via WebSocket"""
        if self.progress_callback:
            try:
                await self.progress_callback(progress)
            except Exception as e:
                print(f"Progress notification error: {e}")

    def _is_cancelled(self, scan_id: str) -> bool:
        """Check if scan has been cancelled"""
        return scan_id in self._cancelled_scans or self._active_scans.get(
            scan_id, {}
        ).get("cancelled", False)

    def cancel_scan(self, scan_id: str) -> bool:
        """
        Cancel a running scan.

        Returns:
            True if scan was cancelled, False if not found or already completed
        """
        if scan_id in self._active_scans:
            self._cancelled_scans.add(scan_id)
            self._active_scans[scan_id]["cancelled"] = True
            # Update status in storage
            self.storage.update_scan_status(scan_id, ScanStatus.CANCELLED)
            print(f"[CANCEL] Scan {scan_id} marked for cancellation")
            return True
        return False

    def get_active_scans(self) -> list:
        """Get list of active scan IDs"""
        return list(self._active_scans.keys())

    # === Telegram Notification Methods ===

    async def _notify_telegram_vuln(self, scan_id: str, vuln_info):
        """Notify Telegram about found vulnerability"""
        try:
            from brsxss.integrations.telegram_service import telegram_service

            await telegram_service.on_vulnerability_found(
                scan_id=scan_id,
                severity=vuln_info.severity,
                url=vuln_info.url,
                parameter=vuln_info.parameter,
                payload=vuln_info.payload,
                context=vuln_info.context_type,
            )
        except Exception as e:
            print(f"Telegram vuln notify error: {e}")

    async def _notify_telegram_complete(
        self,
        scan_id: str,
        target: str,
        mode: str,
        proxy: str,
        duration_seconds: float,
        urls_scanned: int,
        payloads_sent: int,
        vulnerabilities: list,
        target_profile: dict = None,
    ):
        """Notify Telegram about scan completion"""
        try:
            from brsxss.integrations.telegram_service import telegram_service

            # v4.0.0 Phase 9: Import finding normalizer
            try:
                from brsxss.core.finding_normalizer import prepare_findings_for_report

                NORMALIZER_AVAILABLE = True
            except ImportError:
                NORMALIZER_AVAILABLE = False
                prepare_findings_for_report = None

            # Convert VulnerabilityInfo objects to dicts for PDF generation with deduplication FIRST
            # Then count statistics from deduplicated list
            # Deduplicate by URL + sink + payload (same vulnerability = same finding)
            seen_keys = set()
            vuln_dicts = []
            for v in vulnerabilities:
                # Extract metadata from stored attributes or context
                ctx = getattr(v, "context_type", "") or getattr(v, "context", "")

                # Get sink from stored attribute or extract from context
                sink = getattr(v, "_sink", None) or ""
                if not sink and "->" in ctx:
                    sink = ctx.split("->")[-1].strip()

                # Get source from stored attribute or extract from context
                source = getattr(v, "_source", None) or ""
                if not source and "->" in ctx:
                    source = ctx.split("->")[0].strip()

                # Create deduplication key: URL + sink + payload
                dedup_key = (
                    getattr(v, "url", ""),
                    sink or "none",  # Use 'none' if sink is empty for deduplication
                    getattr(v, "payload", ""),
                )

                if dedup_key in seen_keys:
                    continue  # Skip duplicate
                seen_keys.add(dedup_key)

                # Determine XSS type from stored metadata or context
                xss_type = getattr(v, "_xss_type", None) or "Reflected XSS"
                if not xss_type or xss_type == "Reflected XSS":
                    # Check stored reflection_type first
                    reflection_type = getattr(v, "_reflection_type", None) or ""
                    if reflection_type == "dom_based":
                        xss_type = "DOM-Based XSS"
                    elif "DOM" in ctx or "dom" in ctx.lower() or sink or "->" in ctx:
                        xss_type = "DOM-Based XSS"

                # Improve parameter field for DOM XSS
                param = getattr(v, "parameter", "")
                if xss_type == "DOM-Based XSS":
                    # Check if param needs improvement (handle various formats)
                    if (
                        not param
                        or param == "N/A"
                        or param == "unknown"
                        or "N/A (DOM source)" in param
                        or param.startswith("N/A")
                    ):
                        if source:
                            param = f"DOM source: {source}"
                        elif "->" in ctx:
                            source_from_ctx = ctx.split("->")[0].strip()
                            param = f"DOM source: {source_from_ctx}"
                        else:
                            param = "DOM source: form input"

                vuln_dicts.append(
                    {
                        "severity": getattr(v, "severity", "unknown"),
                        "vulnerability_type": xss_type,  # v4.0.0: Use vulnerability_type for normalizer
                        "xss_type": xss_type,
                        "url": getattr(v, "url", ""),
                        "parameter": param,
                        "payload": getattr(v, "payload", ""),
                        "context": ctx,
                        "sink": sink,
                        "source": ctx.split("->")[0].strip() if "->" in ctx else "",
                        "confidence": getattr(v, "confidence", 0.8),
                        "cvss_score": getattr(v, "cvss_score", None),
                        "evidence_count": getattr(v, "evidence_count", 1),
                        "evidence_payloads": getattr(v, "evidence_payloads", []),
                    }
                )

            # ========================================
            # v4.0.0 Phase 9: UNIFIED NORMALIZATION
            # ALL findings MUST pass through normalizer before report/telegram
            # ========================================
            normalized = {"confirmed": vuln_dicts, "potential": []}
            if NORMALIZER_AVAILABLE and prepare_findings_for_report:
                print(
                    f"[NORMALIZE] Applying unified normalization to {len(vuln_dicts)} findings (mode={mode})"
                )
                normalized = prepare_findings_for_report(vuln_dicts, mode=mode)
                print("[NORMALIZE] Normalization complete")

            confirmed_vulns = normalized.get("confirmed", [])
            potential_vulns = normalized.get("potential", [])

            # Count statistics from normalized (confirmed) list
            critical = sum(
                1 for v in confirmed_vulns if v.get("severity", "") == "critical"
            )
            high = sum(1 for v in confirmed_vulns if v.get("severity", "") == "high")
            medium = sum(
                1 for v in confirmed_vulns if v.get("severity", "") == "medium"
            )
            low = sum(1 for v in confirmed_vulns if v.get("severity", "") == "low")

            await telegram_service.on_scan_completed(
                scan_id=scan_id,
                target=target,
                mode=mode,
                duration_seconds=duration_seconds,
                proxy=proxy,
                total_vulns=len(confirmed_vulns),
                critical=critical,
                high=high,
                medium=medium,
                low=low,
                urls_scanned=urls_scanned,
                payloads_sent=payloads_sent,
                target_profile=target_profile,
                vulnerabilities={
                    "confirmed": confirmed_vulns,
                    "potential": potential_vulns,
                },
            )
        except Exception as e:
            print(f"Telegram complete notify error: {e}")
            import traceback

            traceback.print_exc()

    async def _notify_telegram_failed(self, scan_id: str, error: str):
        """Notify Telegram about scan failure"""
        try:
            from brsxss.integrations.telegram_service import telegram_service

            await telegram_service.on_scan_failed(scan_id=scan_id, error=error)
        except Exception as e:
            print(f"Telegram failed notify error: {e}")
