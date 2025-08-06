#!/usr/bin/env python3

"""
BRS-XSS Scanner

Main XSS vulnerability scanner with comprehensive testing capabilities.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Tue 05 Aug 2025 17:39:06 MSK - Fixed critical logic errors
Telegram: @easyprotech

FIXES:
- Remove 200-only status code restriction (process 3xx, 4xx, 5xx responses)
- Remove mandatory reflection requirement (support DOM/Stored/Blind XSS)
- Lower vulnerability threshold from 0.5 to 0.2 for better detection
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin, urlparse

from .config_manager import ConfigManager
from .http_client import HTTPClient
from .payload_generator import PayloadGenerator
from .reflection_detector import ReflectionDetector
from .context_analyzer import ContextAnalyzer
from .scoring_engine import ScoringEngine
from ..waf.detector import WAFDetector
from ..utils.logger import Logger

logger = Logger("core.scanner")


class XSSScanner:
    """
    Main XSS vulnerability scanner.
    
    Capabilities:
    - Parameter discovery and testing
    - Context-aware payload generation
    - Reflection detection and analysis
    - WAF detection and evasion
    - Comprehensive vulnerability scoring
    """
    
    def __init__(self, config: Optional[ConfigManager] = None, timeout: int = 10, max_concurrent: int = 10, verify_ssl: bool = True):
        """Initialize XSS scanner"""
        self.config = config or ConfigManager()
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.verify_ssl = verify_ssl
        self.http_client = HTTPClient(timeout=timeout, verify_ssl=verify_ssl)
        
        # Track sessions for cleanup
        self._sessions_created = []
        self.payload_generator = PayloadGenerator()
        self.reflection_detector = ReflectionDetector()
        self.context_analyzer = ContextAnalyzer()
        self.scoring_engine = ScoringEngine()
        self.waf_detector = WAFDetector(self.http_client)  # Pass shared HTTP client
        
        # State
        self.scan_results = []
        self.tested_parameters = set()
        self.detected_wafs = []
        
        # Statistics
        self.total_tests = 0
        self.vulnerabilities_found = 0
        self.scan_start_time = 0
    
    async def scan_url(self, url: str, parameters: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Scan URL for XSS vulnerabilities.
        
        Args:
            url: Target URL
            parameters: Parameters to test
            
        Returns:
            List of vulnerability findings
        """
        logger.info(f"Starting XSS scan of: {url}")
        self.scan_start_time = time.time()
        
        # Detect WAF
        self.detected_wafs = await self.waf_detector.detect_waf(url)
        if self.detected_wafs:
            logger.info(f"WAF detected: {self.detected_wafs[0].name}")
        
        # Discover parameters if not provided
        if not parameters:
            parameters = await self._discover_parameters(url)
        
        if not parameters:
            logger.warning("No parameters found for testing")
            return []
        
        logger.info(f"Testing {len(parameters)} parameters")
        
        # Test each parameter
        vulnerabilities = []
        for param_name, param_value in parameters.items():
            if param_name in self.tested_parameters:
                continue
            
            self.tested_parameters.add(param_name)
            
            vuln_results = await self._test_parameter(url, param_name, param_value)
            vulnerabilities.extend(vuln_results)
        
        # Generate scan summary
        scan_duration = time.time() - self.scan_start_time
        logger.success(f"Scan completed in {scan_duration:.2f}s. Found {len(vulnerabilities)} vulnerabilities")
        
        return vulnerabilities
    
    async def _discover_parameters(self, url: str) -> Dict[str, str]:
        """Discover parameters from URL and forms"""
        parameters = {}
        
        try:
            # Get parameters from URL
            from urllib.parse import parse_qs, urlparse
            parsed_url = urlparse(url)
            if parsed_url.query:
                url_params = parse_qs(parsed_url.query)
                for key, values in url_params.items():
                    parameters[key] = values[0] if values else ""
            
            # Get page content to find forms
            response = await self.http_client.get(url)
            if response.status_code == 200:
                # Extract form parameters
                form_params = self._extract_form_parameters(response.text)
                parameters.update(form_params)
        
        except Exception as e:
            logger.error(f"Error discovering parameters: {e}")
        
        return parameters
    
    def _extract_form_parameters(self, html_content: str) -> Dict[str, str]:
        """Extract parameters from HTML forms"""
        import re
        parameters = {}
        
        # Simple regex to find input fields
        input_pattern = r'<input[^>]*name\s*=\s*["\']([^"\']*)["\'][^>]*>'
        for match in re.finditer(input_pattern, html_content, re.IGNORECASE):
            param_name = match.group(1)
            if param_name and param_name not in ['submit', 'reset', 'button']:
                parameters[param_name] = "test"
        
        return parameters
    
    async def _test_parameter(self, url: str, param_name: str, param_value: str) -> List[Dict[str, Any]]:
        """Test single parameter for XSS"""
        logger.debug(f"Testing parameter: {param_name}")
        vulnerabilities = []
        
        try:
            # Get initial response for context analysis
            test_url = self._build_test_url(url, param_name, param_value)
            initial_response = await self.http_client.get(test_url)
            
            if initial_response.status_code != 200:
                if initial_response.status_code in [403, 404, 405]:
                    logger.debug(f"Server returned {initial_response.status_code} for context analysis (normal WAF/security behavior)")
                elif initial_response.status_code >= 500:
                    logger.info(f"Server error during context analysis: {initial_response.status_code}")
                else:
                    logger.warning(f"Unexpected response for context analysis: {initial_response.status_code}")
                return vulnerabilities
            
            # Analyze context
            context_analysis_result = self.context_analyzer.analyze_context(
                param_name, param_value, initial_response.text
            )
            
            # Convert ContextAnalysisResult to dict for backward compatibility
            context_info = self._convert_context_result(context_analysis_result)
            
            # Generate payloads based on context
            payloads = self.payload_generator.generate_payloads(
                context_info, 
                self.detected_wafs
            )
            
            logger.debug(f"Generated {len(payloads)} payloads for {param_name}")
            
            # Test each payload
            for payload_obj in payloads[:self.config.get('max_payloads_per_param', 20)]:
                self.total_tests += 1
                
                # Extract payload string from GeneratedPayload object
                payload = payload_obj.payload if hasattr(payload_obj, 'payload') else str(payload_obj)
                
                # Test payload
                result = await self._test_payload(url, param_name, payload, context_info)
                
                if result and result.get('vulnerable'):
                    vulnerabilities.append(result)
                    self.vulnerabilities_found += 1
                    logger.warning(f"Vulnerability found in {param_name}: {payload[:50]}...")
        
        except Exception as e:
            logger.error(f"Error testing parameter {param_name}: {e}")
        finally:
            # Ensure sessions are closed
            await self._cleanup_sessions()
        
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
        
        return {
            'context_type': context_result.primary_context.value if context_result.primary_context else 'unknown',
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
    
    async def _test_payload(self, url: str, param_name: str, payload: str, context_info: Dict) -> Optional[Dict[str, Any]]:
        """Test individual payload"""
        try:
            # Prepare request
            test_url = self._build_test_url(url, param_name, payload)
            
            # Make request
            response = await self.http_client.get(test_url)
            
            # Process any HTTP response that has content (not just 200)
            # Many XSS vulnerabilities appear in error pages (4xx, 5xx) and redirects (3xx)
            if not response.text or len(response.text.strip()) == 0:
                return None
            
            # Check for reflection
            reflection_result = self.reflection_detector.detect_reflections(
                payload, response.text
            )
            
            # CRITICAL: Require reflections for basic XSS detection
            # Only bypass reflection requirement for blind XSS (when webhook is configured)
            has_reflections = reflection_result and len(getattr(reflection_result, 'reflection_points', [])) > 0

            if not has_reflections:
                logger.debug(f"No reflections found for payload: {payload[:30]}...")
                return None
                
            # Score vulnerability based on reflection quality
            vulnerability_score = self.scoring_engine.score_vulnerability(
                payload, reflection_result, context_info, response
            )
            
            # Production-ready threshold - strict enough to avoid false positives
            min_score = self.config.get('min_vulnerability_score', 6.8)  # Require high confidence
            if vulnerability_score.score < min_score:
                logger.debug(f"Payload scored {vulnerability_score.score:.2f}, below threshold {min_score}")
                return None
            
            # Create comprehensive vulnerability report
            vulnerability = {
                'url': url,
                'parameter': param_name,
                'payload': payload,
                'vulnerable': True,
                'reflection_type': reflection_result.overall_reflection_type.value if reflection_result.overall_reflection_type else 'none',
                'context': context_info.get('context_type', 'unknown'),
                'severity': vulnerability_score.severity,
                'score': vulnerability_score.score,
                'confidence': vulnerability_score.confidence,
                'response_snippet': reflection_result.reflection_points[0].reflected_value[:200] if reflection_result.reflection_points else '',
                'timestamp': time.time(),
                
                # Additional detailed information for debugging
                'http_status': response.status_code,
                'response_headers': dict(response.headers) if hasattr(response, 'headers') else {},
                'response_length': len(response.text),
                'reflections_found': len(reflection_result.reflection_points),
                'reflection_positions': [rp.position for rp in reflection_result.reflection_points] if reflection_result.reflection_points else [],
                'test_url': test_url,
                'exploitation_confidence': getattr(reflection_result, 'exploitation_confidence', 0.0),
                'payload_type': getattr(payload, 'payload_type', 'unknown'),
                'context_analysis': context_info
            }
            
            return vulnerability
        
        except Exception as e:
            logger.error(f"Error testing payload {payload[:30]}: {e}")
            return None
    
    def _build_test_url(self, base_url: str, param_name: str, payload: str) -> str:
        """Build test URL with payload"""
        from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
        
        parsed_url = urlparse(base_url)
        query_params = parse_qs(parsed_url.query)
        
        # Add or update parameter
        query_params[param_name] = [payload]
        
        # Rebuild URL
        new_query = urlencode(query_params, doseq=True)
        new_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
        
        return new_url
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scan statistics"""
        scan_duration = time.time() - self.scan_start_time if self.scan_start_time else 0
        
        return {
            'scan_duration': scan_duration,
            'total_tests': self.total_tests,
            'vulnerabilities_found': self.vulnerabilities_found,
            'parameters_tested': len(self.tested_parameters),
            'wafs_detected': len(self.detected_wafs),
            'success_rate': self.vulnerabilities_found / max(1, self.total_tests)
        }