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
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    from playwright.async_api import async_playwright, Browser
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from ..utils.logger import Logger

logger = Logger("dom.headless_detector")


@dataclass
class DOMXSSResult:
    """DOM XSS detection result"""
    url: str
    vulnerable: bool = False
    payload: str = ""
    trigger_method: str = ""  # fragment, postMessage, etc.
    execution_context: str = ""  # innerHTML, eval, etc.
    screenshot_path: Optional[str] = None
    console_logs: List[str] = field(default_factory=list)
    error_logs: List[str] = field(default_factory=list)
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
    
    def __init__(self, headless: bool = True, timeout: int = 30):
        """Initialize detector"""
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError("Playwright is required for DOM XSS detection. Install with: pip install playwright")
        
        self.headless = headless
        self.timeout = timeout
        self.browser: Optional[Browser] = None
        self.context = None
        
        # DOM XSS payloads for different injection points
        self.fragment_payloads = [
            "<script>alert('DOM_XSS_FRAGMENT')</script>",
            "<img src=x onerror=alert('DOM_XSS_FRAGMENT')>",
            "javascript:alert('DOM_XSS_FRAGMENT')",
            "<svg onload=alert('DOM_XSS_FRAGMENT')>",
            "</script><script>alert('DOM_XSS_FRAGMENT')</script>",
            "'-alert('DOM_XSS_FRAGMENT')-'",
            "\";alert('DOM_XSS_FRAGMENT');//",
        ]
        
        self.postmessage_payloads = [
            "<script>alert('DOM_XSS_POSTMSG')</script>",
            "<img src=x onerror=alert('DOM_XSS_POSTMSG')>",
            "javascript:alert('DOM_XSS_POSTMSG')",
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
            self.browser = await self.playwright.chromium.launch(
                headless=self.headless,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-web-security',
                    '--disable-features=VizDisplayCompositor'
                ]
            )
            self.context = await self.browser.new_context(
                viewport={'width': 1280, 'height': 720},
                user_agent='BRS-XSS DOM Scanner v1.0'
            )
            logger.info("Browser instance started")
        except Exception as e:
            logger.error(f"Failed to start browser: {e}")
            logger.info("If this is the first run, install browsers: `playwright install`.")
            raise
    
    async def close(self):
        """Close browser instance"""
        try:
            if self.context:
                await self.context.close()
            if self.browser is not None:
                await self.browser.close()
            if hasattr(self, 'playwright'):
                await self.playwright.stop()
            logger.info("Browser instance closed")
        except Exception as e:
            logger.error(f"Error closing browser: {e}")
    
    async def detect_dom_xss(self, url: str, parameters: Optional[Dict[str, str]] = None) -> List[DOMXSSResult]:
        """
        Main DOM XSS detection method.
        
        Args:
            url: Target URL
            parameters: Optional parameters to test
            
        Returns:
            List of DOM XSS results
        """
        results = []
        
        if not self.browser:
            await self.start()
        
        try:
            # Test fragment-based XSS
            fragment_results = await self._test_fragment_xss(url)
            results.extend(fragment_results)
            
            # Test postMessage XSS
            postmsg_results = await self._test_postmessage_xss(url)
            results.extend(postmsg_results)
            
            # Test URL parameter DOM injection
            if parameters:
                param_results = await self._test_parameter_dom_xss(url, parameters)
                results.extend(param_results)
            
            self.vulnerabilities_found += sum(1 for r in results if r.vulnerable)
            
        except Exception as e:
            logger.error(f"Error during DOM XSS detection: {e}")
        
        return results
    
    async def _test_fragment_xss(self, url: str) -> List[DOMXSSResult]:
        """Test fragment-based DOM XSS (location.hash)"""
        results = []
        
        for payload in self.fragment_payloads:
            self.tests_performed += 1
            
            try:
                # Construct URL with fragment payload
                test_url = f"{url}#{payload}"
                
                result = await self._execute_payload_test(
                    test_url, payload, "fragment", "location.hash"
                )
                results.append(result)
                
                if result.vulnerable:
                    logger.warning(f"Fragment XSS found: {url}")
                    break  # Stop on first successful payload
                    
            except Exception as e:
                logger.error(f"Error testing fragment payload {payload[:20]}...: {e}")
        
        return results
    
    async def _test_postmessage_xss(self, url: str) -> List[DOMXSSResult]:
        """Test postMessage-based DOM XSS"""
        results = []
        
        for payload in self.postmessage_payloads:
            self.tests_performed += 1
            
            try:
                result = await self._execute_postmessage_test(url, payload)
                results.append(result)
                
                if result.vulnerable:
                    logger.warning(f"postMessage XSS found: {url}")
                    break
                    
            except Exception as e:
                logger.error(f"Error testing postMessage payload: {e}")
        
        return results
    
    async def _test_parameter_dom_xss(self, url: str, parameters: Dict[str, str]) -> List[DOMXSSResult]:
        """Test URL parameter DOM injection"""
        results = []
        
        for param_name in parameters:
            for payload in self.fragment_payloads:
                self.tests_performed += 1
                
                try:
                    # Inject payload into parameter
                    test_url = self._inject_parameter_payload(url, param_name, payload)
                    
                    result = await self._execute_payload_test(
                        test_url, payload, "parameter", f"URL parameter: {param_name}"
                    )
                    results.append(result)
                    
                    if result.vulnerable:
                        logger.warning(f"Parameter DOM XSS found: {param_name} in {url}")
                        break
                        
                except Exception as e:
                    logger.error(f"Error testing parameter {param_name}: {e}")
        
        return results
    
    async def _execute_payload_test(self, test_url: str, payload: str, trigger_method: str, context: str) -> DOMXSSResult:
        """Execute payload test in browser"""
        result = DOMXSSResult(
            url=test_url,
            payload=payload,
            trigger_method=trigger_method,
            execution_context=context
        )
        
        page = None
        try:
            page = await self.context.new_page()  # type: ignore[attr-defined]
            
            # Set up console monitoring
            console_logs = []
            error_logs = []
            
            page.on("console", lambda msg: console_logs.append(f"{msg.type}: {msg.text}"))
            page.on("pageerror", lambda exc: error_logs.append(str(exc)))
            # Capture dialogs (alert/confirm/prompt)
            page.on("dialog", lambda dlg: (console_logs.append(f"dialog: {dlg.type} {dlg.message}"), asyncio.create_task(dlg.dismiss()))); page  # type: ignore[func-returns-value]
            
            # Navigate to page with payload
            await page.goto(test_url, timeout=self.timeout * 1000, wait_until="networkidle")
            
            # Wait for potential DOM execution
            await page.wait_for_timeout(2000)
            
            # Check for successful XSS execution
            result.vulnerable = self._check_xss_execution(console_logs, error_logs, payload)
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
            execution_context="window.postMessage"
        )
        
        page = None
        try:
            page = await self.context.new_page()  # type: ignore[attr-defined]
            
            console_logs = []
            error_logs = []
            
            page.on("console", lambda msg: console_logs.append(f"{msg.type}: {msg.text}"))
            page.on("pageerror", lambda exc: error_logs.append(str(exc)))
            page.on("dialog", lambda dlg: (console_logs.append(f"dialog: {dlg.type} {dlg.message}"), asyncio.create_task(dlg.dismiss()))); page  # type: ignore[func-returns-value]
            
            # Navigate to page
            await page.goto(url, timeout=self.timeout * 1000, wait_until="networkidle")
            
            # Send postMessage with payload
            await page.evaluate(f"""
                window.postMessage({repr(payload)}, '*');
                window.postMessage({{data: {repr(payload)}}}, '*');
            """)
            
            await page.wait_for_timeout(2000)
            
            result.vulnerable = self._check_xss_execution(console_logs, error_logs, payload)
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
    
    def _check_xss_execution(self, console_logs: List[str], error_logs: List[str], payload: str) -> bool:
        """Check if XSS payload executed successfully"""
        
        # Look for alert/dialog signatures in console
        alert_signatures = [
            "DOM_XSS_FRAGMENT",
            "DOM_XSS_POSTMSG",
            "alert('DOM_XSS",
            "XSS_DETECTED"
        ]
        
        all_logs = " ".join(console_logs + error_logs).lower()
        
        for signature in alert_signatures:
            if signature.lower() in all_logs:
                return True
        
        # Check for JavaScript execution errors that might indicate successful injection
        execution_indicators = [
            "script error",
            "uncaught referenceerror",
            "unexpected token",
            "syntax error"
        ]
        
        for indicator in execution_indicators:
            if indicator in all_logs and any(sig in payload.lower() for sig in ["script", "alert", "onerror"]):
                return True
        
        return False
    
    def _inject_parameter_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return {
            "tests_performed": self.tests_performed,
            "vulnerabilities_found": self.vulnerabilities_found,
            "success_rate": self.vulnerabilities_found / max(self.tests_performed, 1)
        }