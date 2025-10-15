#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 21:38:09 MSK
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import time
from typing import Dict, List, Optional, Any, Callable
from urllib.parse import urlparse

from .config_manager import ConfigManager
from .http_client import HTTPClient
from .payload_generator import PayloadGenerator
from .reflection_detector import ReflectionDetector
from .context_analyzer import ContextAnalyzer
from .scoring_engine import ScoringEngine
from ..waf.detector import WAFDetector
from ..utils.logger import Logger

# Optional DOM XSS support
try:
    from ..dom.headless_detector import HeadlessDOMDetector
    DOM_XSS_AVAILABLE = True
except ImportError:
    DOM_XSS_AVAILABLE = False

logger = Logger("core.scanner")


class XSSScanner:
    """
    Main XSS vulnerability scanner.
    
    Functions:
    - Parameter discovery and testing
    - Context-aware payload generation
    - Reflection detection and analysis
    - WAF detection and evasion
    - vulnerability scoring
    """
    
    def __init__(self, config: Optional[ConfigManager] = None, timeout: int = 10, max_concurrent: int = 10, verify_ssl: bool = True, enable_dom_xss: bool = True, blind_xss_webhook: Optional[str] = None, progress_callback: Optional[Callable[[int, int], None]] = None, max_payloads: Optional[int] = None, http_client: Optional[HTTPClient] = None):
        """Initialize XSS scanner"""
        self.config = config or ConfigManager()
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.verify_ssl = verify_ssl
        self.enable_dom_xss = enable_dom_xss and DOM_XSS_AVAILABLE
        self.max_payloads = max_payloads
        
        # Use provided HTTP client or create a new one
        self.http_client = http_client or HTTPClient(timeout=timeout, verify_ssl=verify_ssl)
        self._owns_http_client = http_client is None

        # Track sessions for cleanup
        self._sessions_created: List[Any] = []
        self.payload_generator = PayloadGenerator(blind_xss_webhook=blind_xss_webhook)
        self.reflection_detector = ReflectionDetector()
        self.context_analyzer = ContextAnalyzer()
        self.scoring_engine = ScoringEngine()
        self.waf_detector = WAFDetector(self.http_client)  # Pass shared HTTP client
        
        # DOM XSS detector (optional)
        self.dom_detector = None
        if self.enable_dom_xss:
            try:
                self.dom_detector = HeadlessDOMDetector(headless=True, timeout=timeout)
                logger.info("DOM XSS detection enabled")
            except Exception as e:
                logger.warning(f"Could not initialize DOM XSS detector: {e}")
                self.enable_dom_xss = False
        
        # State
        self.scan_results: List[Dict[str, Any]] = []
        self.tested_parameters: set[tuple[str, str, str]] = set()
        self.detected_wafs: List[Any] = []
        
        # Progress tracking
        self.progress_callback = progress_callback
        self.current_payload_index = 0
        self.total_payloads_count = 0
        
        # Statistics
        self.total_tests = 0
        self.vulnerabilities_found = 0
        self.dom_vulnerabilities_found = 0
        self.scan_start_time: float = 0.0
    
    async def scan_url(self, url: str, method: str = "GET", parameters: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Scan a specific entry point (URL + method + parameters) for XSS.
        
        Args:
            url: Target URL
            method: HTTP method (GET or POST)
            parameters: Parameters to test
            
        Returns:
            List of vulnerability findings
        """
        logger.info(f"Scanning entry point: {method.upper()} {url} with params {list(parameters.keys()) if parameters else '[]'}")

        if not parameters:
            logger.warning("No parameters found for testing")
            return []

        # Detect WAF on the base URL
        waf_check_url = urlparse(url)._replace(query="").geturl()
        self.detected_wafs = await self.waf_detector.detect_waf(waf_check_url)
        if self.detected_wafs:
            logger.info(f"WAF detected: {self.detected_wafs[0].name}")
        
        # Calculate total payloads for progress tracking
        if self.progress_callback:
            estimated_payloads_per_param = 950
            self.total_payloads_count = len(parameters) * estimated_payloads_per_param
            self.current_payload_index = 0
        
        # Test each parameter
        vulnerabilities = []
        for param_name, param_value in parameters.items():
            if (url, method, param_name) in self.tested_parameters:
                continue
            
            self.tested_parameters.add((url, method, param_name))
            
            vuln_results = await self._test_parameter(url, method, param_name, param_value, parameters)
            vulnerabilities.extend(vuln_results)
        
        # DOM XSS scan (runs on GET requests to the URL)
        if self.enable_dom_xss and self.dom_detector and method.upper() == "GET":
            try:
                await self.dom_detector.start()
                dom_results = await self.dom_detector.detect_dom_xss(url, parameters)
                
                # Convert DOM XSS results to standard format
                for dom_result in dom_results:
                    if dom_result.vulnerable:
                        vulnerabilities.append(self._format_dom_vulnerability(dom_result))
                        self.dom_vulnerabilities_found += 1
                        logger.warning(f"DOM XSS vulnerability found via {dom_result.trigger_method}")
                
                await self.dom_detector.close()
                
            except Exception as e:
                logger.error(f"DOM XSS detection failed: {e}")
        
        scan_duration = time.time() - self.scan_start_time
        logger.info(f"Entry point scan completed in {scan_duration:.2f}s. Found {len(vulnerabilities)} vulnerabilities.")
        
        return vulnerabilities
    
    def _format_dom_vulnerability(self, dom_result) -> Dict[str, Any]:
        """Formats a DOM XSS result into the standard vulnerability dictionary."""
        return {
            'url': dom_result.url,
            'parameter': 'DOM_XSS',
            'payload': dom_result.payload,
            'vulnerable': True,
            'reflection_type': 'dom_based',
            'context': dom_result.execution_context,
            'severity': 'high',
            'score': dom_result.score,
            'confidence': 0.95,
            'timestamp': time.time(),
            'trigger_method': dom_result.trigger_method,
            'console_logs': dom_result.console_logs,
            'error_logs': dom_result.error_logs,
            'screenshot_path': dom_result.screenshot_path,
            'dom_xss': True
        }

    async def _test_parameter(self, url: str, method: str, param_name: str, param_value: str, all_params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test single parameter for XSS using the specified HTTP method."""
        logger.debug(f"Testing parameter: {param_name} via {method}")
        vulnerabilities = []
        
        try:
            # 1. Get initial response for context analysis
            # We send a benign request first to see where the parameter reflects.
            if method.upper() == 'GET':
                context_url = self._build_test_url(url, {param_name: param_value})
                initial_response = await self.http_client.get(context_url)
            else: # POST
                initial_response = await self.http_client.post(url, data={param_name: param_value})

            if initial_response.status_code >= 400:
                logger.debug(f"Server returned {initial_response.status_code} for context analysis.")

            # 2. Analyze context
            context_analysis_result = self.context_analyzer.analyze_context(
                param_name, param_value, initial_response.text
            )
            context_info = self._convert_context_result(context_analysis_result)
            
            # 3. Generate payloads
            payloads = self.payload_generator.generate_payloads(
                context_info, self.detected_wafs, max_payloads=self.max_payloads
            )
            logger.debug(f"Generated {len(payloads)} payloads for {param_name}")
            
            if self.progress_callback and self.total_payloads_count == 0:
                self.total_payloads_count = len(payloads)
            
            # 4. Test each payload
            for payload_obj in payloads:
                self.total_tests += 1
                self.current_payload_index += 1
                
                payload_str = payload_obj.payload if hasattr(payload_obj, 'payload') else str(payload_obj)
                
                if self.progress_callback:
                    self.progress_callback(self.current_payload_index, self.total_payloads_count)
                
                # Create a mutable copy of all params for this test
                current_test_params = all_params.copy()
                current_test_params[param_name] = payload_str

                result = await self._test_payload(url, method, param_name, payload_str, current_test_params, context_info)
                
                if result and result.get('vulnerable'):
                    vulnerabilities.append(result)
                    self.vulnerabilities_found += 1
                    logger.info(f"Vulnerability found in {param_name} via {method}: {payload_str[:50]}...")
        
        except Exception as e:
            logger.error(f"Error testing parameter {param_name}: {e}")
        
        return vulnerabilities
    
    async def _cleanup_sessions(self):
        """Clean up any open HTTP sessions"""
        try:
            if hasattr(self, 'http_client') and self.http_client:
                await self.http_client.close()
        except Exception as e:
            logger.debug(f"Error cleaning up HTTP sessions: {e}")
    
    async def close(self):
        """Close scanner and cleanup resources"""
        # Only close the client if this scanner instance created it
        if self._owns_http_client:
            await self._cleanup_sessions()
        # Close WAF detector if it owns an HTTP client
        if hasattr(self.waf_detector, 'close'):
            await self.waf_detector.close()
    
    def _convert_context_result(self, context_result) -> dict:
        """Convert ContextAnalysisResult to dict for backward compatibility"""
        if context_result is None:
            return {
                'context_type': 'unknown',
                'injection_points': [],
                'filters_detected': [],
                'encoding_detected': 'none'
            }
        
        # Extract primary injection point info if available
        primary_injection = context_result.injection_points[0] if context_result.injection_points else None
        
        # Use the most specific context from the first injection point for reporting
        specific_context = primary_injection.context_type.value if (primary_injection and primary_injection.context_type) else 'unknown'

        return {
            'context_type': context_result.primary_context.value if context_result.primary_context else 'unknown',
            'specific_context': specific_context,
            'injection_points': context_result.injection_points,
            'total_injections': context_result.total_injections,
            'risk_level': context_result.risk_level,
            'tag_name': primary_injection.tag_name if primary_injection else '',
            'attribute_name': primary_injection.attribute_name if primary_injection else '',
            'quote_char': primary_injection.quote_char if primary_injection else '"',
            'filters_detected': primary_injection.filters_detected if primary_injection else [],
            'encoding_detected': primary_injection.encoding_detected if primary_injection else 'none',
            'position': primary_injection.position if primary_injection else 0,
            'surrounding_code': primary_injection.surrounding_code if primary_injection else '',
            'payload_recommendations': context_result.payload_recommendations,
            'bypass_recommendations': context_result.bypass_recommendations
        }
    
    async def _test_payload(self, url: str, method: str, param_name: str, payload: str, all_params: Dict[str, str], context_info: Dict) -> Optional[Dict[str, Any]]:
        """Test individual payload via the specified HTTP method."""
        try:
            test_url = url
            if method.upper() == 'GET':
                test_url = self._build_test_url(url, all_params)
                response = await self.http_client.get(test_url)
            else: # POST
                response = await self.http_client.post(url, data=all_params)
            
            if not response.text or len(response.text.strip()) == 0:
                return None
            
            # Check for reflection
            reflection_result = self.reflection_detector.detect_reflections(
                payload, response.text
            )
            
            has_reflections = reflection_result and len(getattr(reflection_result, 'reflection_points', [])) > 0
            blind_mode_enabled = bool(self.payload_generator and getattr(self.payload_generator, 'blind_xss', None) is not None)
            if not has_reflections and not blind_mode_enabled:
                return None
                
            # Score vulnerability
            vulnerability_score = self.scoring_engine.score_vulnerability(
                payload, reflection_result, context_info, response
            )
            
            min_score = self.config.get('scanner.min_vulnerability_score', 2.0)
            if vulnerability_score.score < min_score:
                return None
            
            exploitation_likelihood = self._estimate_exploitation_likelihood(context_info, reflection_result)

            # Create vulnerability report
            return {
                'url': url,
                'parameter': param_name,
                'payload': payload,
                'vulnerable': True,
                'reflection_type': (reflection_result.overall_reflection_type.value if (reflection_result and getattr(reflection_result, 'overall_reflection_type', None)) else 'none'),
                'context': context_info.get('specific_context', 'unknown'), # Use specific context for report
                'severity': vulnerability_score.severity,
                'detection_score': round(vulnerability_score.score, 2),
                'exploitation_likelihood': round(exploitation_likelihood, 2),
                'likelihood_level': self._likelihood_level(exploitation_likelihood),
                'likelihood_reason': self._likelihood_reason(context_info, reflection_result),
                'confidence': round(vulnerability_score.confidence, 2),
                'response_snippet': (reflection_result.reflection_points[0].reflected_value[:200] if (reflection_result and getattr(reflection_result, 'reflection_points', None)) else ''),
                'timestamp': time.time(),
                
                # Additional detailed information
                'http_method': method.upper(),
                'http_status': response.status_code,
                'response_headers': dict(response.headers) if hasattr(response, 'headers') else {},
                'response_length': len(response.text),
                'reflections_found': (len(reflection_result.reflection_points) if (reflection_result and getattr(reflection_result, 'reflection_points', None)) else 0),
                'reflection_positions': ([rp.position for rp in reflection_result.reflection_points] if (reflection_result and getattr(reflection_result, 'reflection_points', None)) else []),
                'test_url': test_url, # For GET, this includes the payload
                'exploitation_confidence': (getattr(reflection_result, 'exploitation_confidence', 0.0) if reflection_result else 0.0),
                'payload_type': getattr(payload, 'payload_type', 'unknown'),
                'context_analysis': context_info
            }
        
        except Exception as e:
            logger.error(f"Error testing payload {payload[:30]}: {e}")
            return None

    def _estimate_exploitation_likelihood(self, context_info: Dict[str, Any], reflection_result: Any) -> float:
        score = 0.4
        ctx = (context_info or {}).get('context_type', 'unknown')
        if ctx in ('javascript', 'js_string'):
            score += 0.3
        elif ctx in ('html_content', 'html_attribute'):
            score += 0.2
        rtype = getattr(reflection_result, 'overall_reflection_type', None)
        rvalue = rtype.value if hasattr(rtype, 'value') else (str(rtype) if rtype else '')  # type: ignore[union-attr]
        if rvalue == 'exact':
            score += 0.3
        elif rvalue in ('partial', 'modified'):
            score += 0.15
        elif rvalue in ('encoded', 'filtered'):
            score -= 0.15
        filters = context_info.get('filters_detected', []) if context_info else []
        if filters:
            score -= min(0.2, 0.05 * len(filters))
        return max(0.0, min(1.0, score))

    def _likelihood_level(self, likelihood: float) -> str:
        if likelihood >= 0.7:
            return 'high'
        if likelihood >= 0.4:
            return 'medium'
        return 'low'

    def _likelihood_reason(self, context_info: Dict[str, Any], reflection_result: Any) -> str:
        ctx = (context_info or {}).get('context_type', 'unknown')
        rtype = getattr(reflection_result, 'overall_reflection_type', None)
        rvalue = rtype.value if hasattr(rtype, 'value') else (str(rtype) if rtype else 'none')  # type: ignore[union-attr]
        parts = []
        parts.append(f"context={ctx}")
        parts.append(f"reflection={rvalue}")
        filters = context_info.get('filters_detected', []) if context_info else []
        if filters:
            parts.append(f"filters={len(filters)}")
        return ", ".join(parts)
    
    def _build_test_url(self, base_url: str, params: Dict[str, str]) -> str:
        """Build test URL with payload in query string for GET requests."""
        from urllib.parse import urlencode, parse_qs, urlunparse, urlparse
        
        parsed_url = urlparse(base_url)
        # Start with existing query params from base_url
        query_params = parse_qs(parsed_url.query)
        
        # Update/add new params
        for name, value in params.items():
            query_params[name] = [value]
        
        # Rebuild URL
        new_query = urlencode(query_params, doseq=True)
        return urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scan statistics"""
        scan_duration = time.time() - self.scan_start_time if self.scan_start_time else 0
        
        return {
            'scan_duration': scan_duration,
            'total_tests': self.total_tests,
            'vulnerabilities_found': self.vulnerabilities_found,
            'dom_vulnerabilities_found': self.dom_vulnerabilities_found,
            'parameters_tested': len(self.tested_parameters),
            'wafs_detected': len(self.detected_wafs),
            'success_rate': self.vulnerabilities_found / max(1, self.total_tests)
        }
    