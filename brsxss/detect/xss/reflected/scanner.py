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
from typing import Optional, Any, Callable
from urllib.parse import urlparse

from .config_manager import ConfigManager
from .http_client import HTTPClient
from .payload_generator import PayloadGenerator
from .reflection_detector import ReflectionDetector
from .context_analyzer import ContextAnalyzer
from .scoring_engine import ScoringEngine
from .response_diff import ResponseDiffEngine, ReflectionStatus
from .result_manager import ResultManager
from .xss_type_classifier import get_xss_classifier, InjectionSource
from .context_parser import get_context_parser
from .payload_classifier import get_payload_classifier
from .payload_analyzer import get_payload_analyzer
from brsxss.detect.waf.detector import WAFDetector
from brsxss.utils.logger import Logger

# Optional DOM XSS support
try:
    from brsxss.detect.xss.dom.headless_detector import HeadlessDOMDetector

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

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        timeout: int = 10,
        max_concurrent: int = 10,
        verify_ssl: bool = True,
        enable_dom_xss: bool = True,
        blind_xss_webhook: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        max_payloads: Optional[int] = None,
        http_client: Optional[HTTPClient] = None,
        dom_workers: int = 2,
        dom_use_gpu: bool = False,
        early_stop_threshold: int = 0,
        max_evidence: int = 0,
    ):
        """Initialize XSS scanner
        
        Args:
            early_stop_threshold: Stop testing parameter after N confirmed payloads.
                                  0 = disabled (test ALL payloads)
            max_evidence: Max evidence payloads to keep per parameter.
                          0 = unlimited (keep ALL successful payloads)
        """
        self.config = config or ConfigManager()
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.verify_ssl = verify_ssl
        self.enable_dom_xss = enable_dom_xss and DOM_XSS_AVAILABLE
        self.max_payloads = max_payloads
        self.early_stop_threshold = early_stop_threshold
        self.max_evidence = max_evidence

        # Use provided HTTP client or create a new one
        self.http_client = http_client or HTTPClient(
            timeout=timeout, verify_ssl=verify_ssl
        )
        self._owns_http_client = http_client is None

        # Track sessions for cleanup
        self._sessions_created: list[Any] = []
        self.payload_generator = PayloadGenerator(blind_xss_webhook=blind_xss_webhook)
        self.reflection_detector = ReflectionDetector()
        self.context_analyzer = ContextAnalyzer()
        self.scoring_engine = ScoringEngine()
        self.response_diff = ResponseDiffEngine()
        self.waf_detector = WAFDetector(self.http_client)  # Pass shared HTTP client

        # New v4.0.0 classifiers
        self.xss_classifier = get_xss_classifier()
        self.context_parser = get_context_parser()
        self.payload_classifier = get_payload_classifier()
        self.payload_analyzer = get_payload_analyzer()

        # DOM XSS detector (optional)
        self.dom_detector = None
        if self.enable_dom_xss:
            try:
                self.dom_detector = HeadlessDOMDetector(
                    headless=True,
                    timeout=timeout,
                    max_workers=max(1, dom_workers),
                    use_gpu=dom_use_gpu,
                )
                logger.info("DOM XSS detection enabled")
            except Exception as e:
                logger.warning(f"Could not initialize DOM XSS detector: {e}")
                self.enable_dom_xss = False

        # State
        self.scan_results: list[dict[str, Any]] = []
        self.tested_parameters: set[tuple[str, str, str]] = set()
        self.detected_wafs: list[Any] = []

        # Progress tracking
        self.progress_callback = progress_callback
        self.current_payload_index = 0
        self.total_payloads_count = 0

        # Statistics
        self.total_tests = 0
        self.vulnerabilities_found = 0
        self.dom_vulnerabilities_found = 0
        self.scan_start_time: float = 0.0

    async def scan_url(
        self, url: str, method: str = "GET", parameters: Optional[dict[str, str]] = None
    ) -> list[dict[str, Any]]:
        """
        Scan a specific entry point (URL + method + parameters) for XSS.

        Args:
            url: Target URL
            method: HTTP method (GET or POST)
            parameters: Parameters to test

        Returns:
            list of vulnerability findings
        """
        logger.info(
            f"Scanning entry point: {method.upper()} {url} with params {list(parameters.keys()) if parameters else '[]'}"
        )

        vulnerabilities = []

        # Even without parameters, we still run DOM XSS detection
        # DOM XSS can work through forms, storage, fragments - not just URL params

        # Detect WAF on the base URL
        waf_check_url = urlparse(url)._replace(query="").geturl()
        self.detected_wafs = await self.waf_detector.detect_waf(waf_check_url)
        if self.detected_wafs:
            logger.info(f"WAF detected: {self.detected_wafs[0].name}")

        # Calculate total payloads for progress tracking
        if self.progress_callback and parameters:
            estimated_payloads_per_param = 950
            self.total_payloads_count = len(parameters) * estimated_payloads_per_param
            self.current_payload_index = 0

        # Test each parameter (if any)
        if parameters:
            for param_name, param_value in parameters.items():
                if (url, method, param_name) in self.tested_parameters:
                    continue

                self.tested_parameters.add((url, method, param_name))

                vuln_results = await self._test_parameter(
                    url, method, param_name, param_value, parameters
                )
                vulnerabilities.extend(vuln_results)
        else:
            logger.info(
                "No URL parameters - skipping reflected XSS tests, proceeding to DOM XSS"
            )

        # DOM XSS scan (runs for all requests - fragment, postMessage, form, storage)
        # This runs ALWAYS regardless of parameters - DOM XSS uses different sources
        logger.info(
            f"[DOM PHASE] Starting DOM XSS detection: enable={self.enable_dom_xss}, detector={self.dom_detector is not None}"
        )
        if self.enable_dom_xss and self.dom_detector:
            try:
                logger.info("[DOM PHASE] Launching headless browser...")
                await self.dom_detector.start()
                logger.info(
                    "[DOM PHASE] Testing DOM XSS vectors (fragment, postMessage, form, storage)..."
                )

                # Check if this is a JavaScript-handled form (from scan_targets)
                form_info = None
                if hasattr(self, "_current_target_form_info"):
                    form_info = self._current_target_form_info

                dom_results = await self.dom_detector.detect_dom_xss(
                    url, parameters, form_info
                )
                logger.info(f"[DOM PHASE] Got {len(dom_results)} results")

                # Filter only vulnerable results
                vulnerable_dom = [r for r in dom_results if r.vulnerable]

                if vulnerable_dom:
                    # Aggregate DOM XSS findings - one finding with multiple evidence
                    aggregated_dom = self._aggregate_dom_findings(url, vulnerable_dom)
                    vulnerabilities.append(aggregated_dom)
                    self.dom_vulnerabilities_found += 1
                    logger.warning(
                        f"DOM XSS confirmed: 1 finding, {len(vulnerable_dom)} evidence"
                    )

                await self.dom_detector.close()

            except Exception as e:
                logger.error(f"DOM XSS detection failed: {e}")

        scan_duration = time.time() - self.scan_start_time
        logger.info(
            f"Entry point scan completed in {scan_duration:.2f}s. Found {len(vulnerabilities)} vulnerabilities."
        )

        return vulnerabilities

    def _format_dom_vulnerability(self, dom_result) -> dict[str, Any]:
        """Formats a DOM XSS result into the standard vulnerability dictionary."""
        return ResultManager.format_dom_vulnerability(dom_result)

    def _aggregate_dom_findings(
        self, base_url: str, vulnerable_results: list
    ) -> dict[str, Any]:
        """
        Aggregate multiple DOM XSS findings into single finding with evidence.
        """
        return ResultManager.aggregate_dom_findings(base_url, vulnerable_results)

    async def _test_parameter(
        self,
        url: str,
        method: str,
        param_name: str,
        param_value: str,
        all_params: dict[str, str],
    ) -> list[dict[str, Any]]:
        """
        Test single parameter for XSS using the specified HTTP method.

        Uses early-stop strategy:
        - After confirming reflected XSS (3 successful payloads), stop spraying
        - Return ONE aggregated vulnerability with multiple evidence payloads
        """
        logger.debug(f"Testing parameter: {param_name} via {method}")

        # Evidence collection for this parameter
        confirmed_payloads: list[dict[str, Any]] = []
        contexts_found: set[str] = set()
        highest_severity = "low"
        highest_score = 0.0

        # Early stop thresholds (0 = disabled, test all payloads)
        CONFIRMATION_THRESHOLD = self.early_stop_threshold
        MAX_EVIDENCE = self.max_evidence

        try:
            # 1. Get BASELINE response for comparison (using safe value)
            baseline_value = "brsxss_test_" + param_name[:8]
            baseline_params = all_params.copy()
            baseline_params[param_name] = baseline_value

            if method.upper() == "GET":
                baseline_url = self._build_test_url(url, baseline_params)
                baseline_response = await self.http_client.get(baseline_url)
            else:
                baseline_response = await self.http_client.post(
                    url, data=baseline_params
                )

            baseline_text = baseline_response.text if baseline_response else ""

            # 2. Get initial response for context analysis
            if method.upper() == "GET":
                context_url = self._build_test_url(url, {param_name: param_value})
                initial_response = await self.http_client.get(context_url)
            else:
                initial_response = await self.http_client.post(
                    url, data={param_name: param_value}
                )

            if initial_response.status_code >= 400:
                logger.debug(
                    f"Server returned {initial_response.status_code} for context analysis."
                )

            # 3. Analyze context
            context_analysis_result = self.context_analyzer.analyze_context(
                param_name, param_value, initial_response.text
            )
            context_info = self._convert_context_result(context_analysis_result)

            # Store baseline for diff analysis
            context_info["_baseline_value"] = baseline_value
            context_info["_baseline_response"] = baseline_text

            # 3. Generate payloads
            payloads = self.payload_generator.generate_payloads(
                context_info, self.detected_wafs, max_payloads=self.max_payloads
            )
            logger.debug(f"Generated {len(payloads)} payloads for {param_name}")

            if self.progress_callback and self.total_payloads_count == 0:
                self.total_payloads_count = len(payloads)

            # 4. Test payloads in PARALLEL with early stop
            import asyncio
            import threading

            xss_confirmed = False
            stop_flag = threading.Event()
            results_lock = threading.Lock()

            # Semaphore for parallel payload testing (I/O-bound)
            payload_semaphore = asyncio.Semaphore(self.max_concurrent)

            async def test_single_payload(payload_obj, idx: int):
                """Test single payload with semaphore control"""
                nonlocal xss_confirmed, highest_severity, highest_score

                # Check early stop
                if stop_flag.is_set():
                    return None

                payload_str = (
                    payload_obj.payload
                    if hasattr(payload_obj, "payload")
                    else str(payload_obj)
                )

                async with payload_semaphore:
                    # Double-check stop flag after acquiring semaphore
                    if stop_flag.is_set():
                        return None

                    self.total_tests += 1
                    
                    # Update progress incrementally for smooth UX
                    self.current_payload_index += 1
                    if self.progress_callback and self.total_payloads_count > 0:
                        self.progress_callback(
                            self.current_payload_index, self.total_payloads_count
                        )

                    # Create test params
                    current_test_params = all_params.copy()
                    current_test_params[param_name] = payload_str

                    result = await self._test_payload(
                        url,
                        method,
                        param_name,
                        payload_str,
                        current_test_params,
                        context_info,
                    )

                    if result and result.get("vulnerable"):
                        with results_lock:
                            # Collect evidence
                            confirmed_payloads.append(
                                {
                                    "payload": payload_str,
                                    "context": result.get("context", ""),
                                    "reflection_type": result.get(
                                        "reflection_type", ""
                                    ),
                                    "score": result.get("score", 0),
                                }
                            )

                            contexts_found.add(result.get("context", "unknown"))

                            # Track highest severity
                            result_severity = result.get("severity", "low")
                            result_score = result.get("score", 0)

                            severity_order = {
                                "critical": 4,
                                "high": 3,
                                "medium": 2,
                                "low": 1,
                            }
                            if severity_order.get(
                                result_severity, 0
                            ) > severity_order.get(highest_severity, 0):
                                highest_severity = result_severity
                            if result_score > highest_score:
                                highest_score = result_score

                            # Check if XSS is now confirmed - trigger early stop (if enabled)
                            if CONFIRMATION_THRESHOLD > 0 and len(confirmed_payloads) >= CONFIRMATION_THRESHOLD:
                                xss_confirmed = True
                                logger.info(
                                    f"[CONFIRMED] Reflected XSS in {param_name} after {len(confirmed_payloads)} payloads"
                                )

                            # Early stop if we have enough evidence (if enabled, 0 = unlimited)
                            if MAX_EVIDENCE > 0 and len(confirmed_payloads) >= MAX_EVIDENCE:
                                stop_flag.set()
                                logger.info(
                                    f"[EARLY STOP] XSS confirmed for {param_name}, stopping parallel tests"
                                )

                    return result

            # Create tasks for all payloads
            tasks = [
                test_single_payload(payload_obj, idx)
                for idx, payload_obj in enumerate(payloads)
            ]

            # Run all payload tests in parallel
            logger.debug(
                f"[PARALLEL] Testing {len(tasks)} payloads with {self.max_concurrent} concurrent"
            )
            await asyncio.gather(*tasks, return_exceptions=True)
            # Progress is updated incrementally inside test_single_payload

        except Exception as e:
            logger.error(f"Error testing parameter {param_name}: {e}")

        # 5. AGGREGATE: Return ONE vulnerability per parameter (if found)
        if confirmed_payloads:
            self.vulnerabilities_found += 1  # Count as ONE vulnerability

            # Primary payload for classification
            primary_payload = confirmed_payloads[0]["payload"]
            primary_context = confirmed_payloads[0]["context"]

            # ========================================
            # v4.0.0: RUNTIME PAYLOAD ANALYSIS
            # KB stores static data, we compute runtime characteristics
            # ========================================
            analyzed_payload = self.payload_analyzer.analyze(
                payload=primary_payload, kb_hints={"contexts": [primary_context]}
            )

            # ========================================
            # v4.0.0: XSS TYPE CLASSIFICATION
            # parameter=unknown/None -> NOT Reflected XSS
            # ========================================

            # Determine source based on method and whether parameter is known
            param_is_known = param_name and param_name != "unknown" and param_name != ""

            if param_is_known:
                source = (
                    InjectionSource.URL_PARAMETER
                    if method.upper() == "GET"
                    else InjectionSource.FORM_INPUT
                )
            else:
                # Unknown parameter = likely DOM-based source
                source = InjectionSource.DOM_API

            xss_classification = self.xss_classifier.classify(
                payload=primary_payload,
                parameter=param_name if param_is_known else None,
                source=source,
                dom_confirmed=False,  # Will be updated if DOM scan confirms
                reflection_context=primary_context,
            )

            # Classify payload for PAYLOAD CLASS (legacy, for compatibility)
            self.payload_classifier.classify(primary_payload)

            # ========================================
            # v4.0.0: CONFIDENCE CALCULATION
            # Use analyzed payload characteristics
            # ========================================
            base_confidence = self.scoring_engine.confidence_calculator.calculate(
                reflection_result=None,
                context_info=context_info,
                payload=primary_payload,
                classification_result=xss_classification,
            )

            # Apply payload analyzer confidence boost
            final_confidence_score = min(
                1.0, base_confidence.score + analyzed_payload.confidence_boost
            )

            # ========================================
            # v4.0.0: SEVERITY DETERMINATION
            # Use max of: detected severity, XSS classification minimum, payload analyzer minimum
            # ========================================
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

            severity_candidates = [
                highest_severity,
                xss_classification.severity_minimum,
                analyzed_payload.severity_minimum,
            ]

            final_severity = max(
                severity_candidates, key=lambda s: severity_order.get(s, 0)
            )

            # ========================================
            # v4.0.0: CONTEXT GRANULARITY
            # Use hierarchical context from context_parser
            # ========================================
            if primary_context == "html" or primary_context == "html_attribute":
                # Get more granular context using analyzer
                self.context_parser.parse(
                    content="",  # We don't have the full content here
                    payload=primary_payload,
                )

            # Build specific context string
            if analyzed_payload.trigger_element and analyzed_payload.trigger_attribute:
                specific_context = f"html > {analyzed_payload.trigger_element} > {analyzed_payload.trigger_attribute}"
            elif analyzed_payload.trigger_vector:
                specific_context = f"html > {analyzed_payload.trigger_vector}"
            else:
                specific_context = primary_context

            # Build aggregated vulnerability with dynamic classification
            aggregated_vuln = {
                "url": url,
                "parameter": param_name,
                "method": method,
                "vulnerable": True,
                "vulnerability_type": xss_classification.xss_type.value,
                # Use best payload as primary
                "payload": primary_payload,
                # Aggregated info
                "contexts": list(contexts_found),
                "context": specific_context,  # Now hierarchical: html > img > onerror
                "reflection_type": xss_classification.source.value,
                # Severity and scoring
                "severity": final_severity,
                "score": highest_score,
                "confidence": final_confidence_score,
                "confidence_level": base_confidence.level.value,
                "confidence_reason": base_confidence.primary_reason,
                # PAYLOAD CLASS from PayloadAnalyzer (v4.0.0)
                "payload_class": analyzed_payload.payload_class_string,
                "trigger": analyzed_payload.trigger_vector,
                "trigger_element": analyzed_payload.trigger_element,
                "trigger_attribute": analyzed_payload.trigger_attribute,
                "trigger_mechanism": analyzed_payload.execution.value,
                "is_deterministic": analyzed_payload.is_deterministic,
                "requires_interaction": analyzed_payload.requires_interaction,
                # Execution info (NEW v4.0.0)
                "execution": analyzed_payload.execution.value,
                "injection_class": analyzed_payload.injection_class.value,
                "xss_type_hint": analyzed_payload.xss_type_hint.value,
                # External resource info (for script src payloads)
                "contains_external_resource": analyzed_payload.contains_external_resource,
                "external_url": analyzed_payload.external_url,
                # Evidence (not individual vulns)
                "evidence_count": len(confirmed_payloads),
                "evidence_payloads": [
                    p["payload"] for p in (confirmed_payloads[:MAX_EVIDENCE] if MAX_EVIDENCE > 0 else confirmed_payloads)
                ],
                # Classification details
                "classification": {
                    "xss_type": xss_classification.xss_type.value,
                    "trigger_type": xss_classification.trigger_type.value,
                    "source": xss_classification.source.value,
                    "confidence_modifier": xss_classification.confidence_modifier,
                    "severity_minimum": xss_classification.severity_minimum,
                    # PayloadAnalyzer computed values
                    "payload_analysis": {
                        "trigger_element": analyzed_payload.trigger_element,
                        "trigger_attribute": analyzed_payload.trigger_attribute,
                        "trigger_vector": analyzed_payload.trigger_vector,
                        "execution": analyzed_payload.execution.value,
                        "is_deterministic": analyzed_payload.is_deterministic,
                        "injection_class": analyzed_payload.injection_class.value,
                        "xss_type_hint": analyzed_payload.xss_type_hint.value,
                        "confidence_boost": analyzed_payload.confidence_boost,
                        "severity_minimum": analyzed_payload.severity_minimum,
                    },
                },
                # Metadata
                "timestamp": time.time(),
                "early_stopped": CONFIRMATION_THRESHOLD > 0 and len(confirmed_payloads) >= CONFIRMATION_THRESHOLD,
            }

            logger.info(
                f"Aggregated vulnerability for {param_name}: "
                f"{xss_classification.xss_type.value}, "
                f"trigger={analyzed_payload.trigger_vector}, "
                f"deterministic={analyzed_payload.is_deterministic}, "
                f"{len(confirmed_payloads)} evidence payloads, "
                f"severity={final_severity}, "
                f"confidence={final_confidence_score*100:.0f}%"
            )

            return [aggregated_vuln]

        return []

    async def _cleanup_sessions(self):
        """Clean up any open HTTP sessions"""
        try:
            if hasattr(self, "http_client") and self.http_client:
                await self.http_client.close()
        except Exception as e:
            logger.debug(f"Error cleaning up HTTP sessions: {e}")

    async def close(self):
        """Close scanner and cleanup resources"""
        # Only close the client if this scanner instance created it
        if self._owns_http_client:
            await self._cleanup_sessions()
        # Close WAF detector if it owns an HTTP client
        if hasattr(self.waf_detector, "close"):
            await self.waf_detector.close()

    def _convert_context_result(self, context_result) -> dict:
        """Convert ContextAnalysisResult to dict for backward compatibility"""
        if context_result is None:
            return {
                "context_type": "unknown",
                "injection_points": [],
                "filters_detected": [],
                "encoding_detected": "none",
            }

        # Extract primary injection point info if available
        primary_injection = (
            context_result.injection_points[0]
            if context_result.injection_points
            else None
        )

        # Use the most specific context from the first injection point for reporting
        raw_specific_context = (
            primary_injection.context_type.value
            if (primary_injection and primary_injection.context_type)
            else "unknown"
        )

        # Payload generation MUST use a context key supported by ContextPayloadGenerator.
        # primary_context may intentionally collapse JS subcontexts (js_string/js_object)
        # into "javascript", which breaks tail-neutralizing payload selection.
        supported_payload_contexts = {
            "html_content",
            "html_attribute",
            "javascript",
            "js_string",
            "css_style",
            "url_parameter",
            "angular_template",
            "unknown",
        }
        payload_context_type = (
            raw_specific_context
            if raw_specific_context in supported_payload_contexts
            else (
                context_result.primary_context.value
                if context_result.primary_context
                else "unknown"
            )
        )

        specific_context = raw_specific_context

        # Normalize javascript context to more specific type
        if specific_context == "javascript":
            # Determine if it's expression or statement based on surrounding code
            surrounding = (
                primary_injection.surrounding_code if primary_injection else ""
            ).lower()
            if any(
                kw in surrounding
                for kw in [
                    "var ",
                    "let ",
                    "const ",
                    "function ",
                    "if ",
                    "for ",
                    "while ",
                ]
            ):
                specific_context = "javascript_statement"
            else:
                specific_context = "javascript_expression"

        # Detect if we're in an event handler or function call context
        # This is critical for generating correct tail-neutralizing payloads
        surrounding = (
            primary_injection.surrounding_code if primary_injection else ""
        )
        attr_name = (
            primary_injection.attribute_name if primary_injection else ""
        ).lower()
        
        # Event handler attributes: onclick, onload, onerror, onmouseover, etc.
        is_in_event_handler = attr_name.startswith("on") and len(attr_name) > 2
        
        # Check for function call pattern in surrounding code
        # Patterns like: func('...'), setTimeout('...'), startTimer('...')
        import re
        marker = getattr(context_result, "parameter_value", "") or ""
        marker_in_surrounding = surrounding.find(marker) if marker else -1
        before_marker = (
            surrounding[:marker_in_surrounding]
            if marker_in_surrounding != -1
            else surrounding
        )
        is_in_function_call = bool(re.search(r"\b\w+\s*\([^)]*$", before_marker))
        
        return {
            "context_type": payload_context_type,
            "specific_context": specific_context,
            "injection_points": context_result.injection_points,
            "total_injections": context_result.total_injections,
            "risk_level": context_result.risk_level,
            "tag_name": primary_injection.tag_name if primary_injection else "",
            "attribute_name": (
                primary_injection.attribute_name if primary_injection else ""
            ),
            "quote_char": primary_injection.quote_char if primary_injection else '"',
            "filters_detected": (
                primary_injection.filters_detected if primary_injection else []
            ),
            "encoding_detected": (
                primary_injection.encoding_detected if primary_injection else "none"
            ),
            "position": primary_injection.position if primary_injection else 0,
            "surrounding_code": (
                primary_injection.surrounding_code if primary_injection else ""
            ),
            "payload_recommendations": context_result.payload_recommendations,
            "bypass_recommendations": context_result.bypass_recommendations,
            # New fields for tail-aware payload generation
            "is_in_event_handler": is_in_event_handler,
            "is_in_function_call": is_in_function_call,
        }

    async def _test_payload(
        self,
        url: str,
        method: str,
        param_name: str,
        payload: str,
        all_params: dict[str, str],
        context_info: dict,
    ) -> Optional[dict[str, Any]]:
        """Test individual payload via the specified HTTP method."""
        try:
            test_url = url
            if method.upper() == "GET":
                test_url = self._build_test_url(url, all_params)
                response = await self.http_client.get(test_url)
            else:  # POST
                response = await self.http_client.post(url, data=all_params)

            if not response.text or len(response.text.strip()) == 0:
                return None

            # Use Response Diff Engine for accurate detection
            baseline_value = context_info.get("_baseline_value", "test")
            baseline_response = context_info.get("_baseline_response", "")

            diff_result = self.response_diff.analyze(
                parameter=param_name,
                baseline_value=baseline_value,
                baseline_response=baseline_response,
                payload=payload,
                payload_response=response.text,
            )

            # If Response Diff says not vulnerable and no raw reflection, skip
            if (
                not diff_result.is_vulnerable
                and diff_result.reflection_status != ReflectionStatus.REFLECTED_RAW
            ):
                # Still check with reflection detector for edge cases
                reflection_result = self.reflection_detector.detect_reflections(
                    payload, response.text
                )
                has_reflections = (
                    reflection_result
                    and len(getattr(reflection_result, "reflection_points", [])) > 0
                )
                blind_mode_enabled = bool(
                    self.payload_generator
                    and getattr(self.payload_generator, "blind_xss", None) is not None
                )

                if not has_reflections and not blind_mode_enabled:
                    return None
            else:
                # Response Diff detected vulnerability - create reflection result for scoring
                reflection_result = self.reflection_detector.detect_reflections(
                    payload, response.text
                )

            # Check for reflection
            has_reflections = (
                reflection_result
                and len(getattr(reflection_result, "reflection_points", [])) > 0
            )
            blind_mode_enabled = bool(
                self.payload_generator
                and getattr(self.payload_generator, "blind_xss", None) is not None
            )
            if (
                not has_reflections
                and not blind_mode_enabled
                and not diff_result.is_vulnerable
            ):
                return None

            # Classify payload (v4.0.0)
            payload_classification = self.payload_classifier.classify(payload)

            # Classify XSS type (v4.0.0)
            xss_classification = self.xss_classifier.classify(
                payload=payload,
                parameter=param_name if param_name != "unknown" else None,
                source=(
                    InjectionSource.URL_PARAMETER
                    if method.upper() == "GET"
                    else InjectionSource.FORM_INPUT
                ),
                dom_confirmed=False,
                reflection_context=context_info.get("specific_context"),
            )

            # Score vulnerability with new classifiers
            vulnerability_score = self.scoring_engine.score_vulnerability(
                payload,
                reflection_result,
                context_info,
                response,
                classification_result=xss_classification,
            )

            # Boost score if Response Diff confirms vulnerability
            if diff_result.is_vulnerable:
                vulnerability_score.score = max(vulnerability_score.score, 5.0)
                vulnerability_score.confidence = max(
                    vulnerability_score.confidence, diff_result.confidence
                )

            min_score = self.config.get("scanner.min_vulnerability_score", 2.0)
            if vulnerability_score.score < min_score:
                return None

            exploitation_likelihood = ResultManager.estimate_exploitation_likelihood(
                context_info, reflection_result
            )

            # Create vulnerability report
            # Convert severity enum to string
            severity_str = (
                vulnerability_score.severity.value
                if hasattr(vulnerability_score.severity, "value")
                else str(vulnerability_score.severity)
            )

            return {
                "url": url,
                "parameter": param_name,
                "payload": payload,
                "vulnerable": True,
                # Dynamic classification (v4.0.0)
                "vulnerability_type": xss_classification.xss_type.value,
                "reflection_type": xss_classification.source.value,
                "context": context_info.get("specific_context", "unknown"),
                # PAYLOAD CLASS (v4.0.0)
                "payload_class": payload_classification.to_payload_class_string(),
                "trigger": payload_classification.vector,
                "trigger_mechanism": payload_classification.trigger.value,
                "is_deterministic": payload_classification.is_deterministic,
                "requires_interaction": payload_classification.requires_interaction,
                "severity": severity_str,
                "detection_score": round(vulnerability_score.score, 2),
                "exploitation_likelihood": round(exploitation_likelihood, 2),
                "likelihood_level": ResultManager.get_likelihood_level(
                    exploitation_likelihood
                ),
                "likelihood_reason": ResultManager.get_likelihood_reason(
                    context_info, reflection_result
                ),
                "confidence": round(vulnerability_score.confidence, 2),
                "response_snippet": (
                    reflection_result.reflection_points[0].reflected_value[:200]
                    if (
                        reflection_result
                        and getattr(reflection_result, "reflection_points", None)
                    )
                    else ""
                ),
                "timestamp": time.time(),
                # Additional detailed information
                "http_method": method.upper(),
                "http_status": response.status_code,
                "response_headers": (
                    dict(response.headers) if hasattr(response, "headers") else {}
                ),
                "response_length": len(response.text),
                "reflections_found": (
                    len(reflection_result.reflection_points)
                    if (
                        reflection_result
                        and getattr(reflection_result, "reflection_points", None)
                    )
                    else 0
                ),
                "reflection_positions": (
                    [rp.position for rp in reflection_result.reflection_points]
                    if (
                        reflection_result
                        and getattr(reflection_result, "reflection_points", None)
                    )
                    else []
                ),
                "test_url": test_url,
                "exploitation_confidence": (
                    getattr(reflection_result, "exploitation_confidence", 0.0)
                    if reflection_result
                    else 0.0
                ),
                "payload_type": getattr(payload, "payload_type", "unknown"),
                "context_analysis": context_info,
                # Classification details (v4.0.0)
                "classification": {
                    "xss_type": xss_classification.xss_type.value,
                    "trigger_type": xss_classification.trigger_type.value,
                    "source": xss_classification.source.value,
                    "confidence_modifier": xss_classification.confidence_modifier,
                    "severity_minimum": xss_classification.severity_minimum,
                },
                # Response Diff analysis
                "diff_analysis": {
                    "reflection_status": diff_result.reflection_status.value,
                    "filter_detected": diff_result.filter_detected,
                    "filter_type": (
                        diff_result.filter_type.value
                        if diff_result.filter_detected
                        else None
                    ),
                    "bypass_suggestions": diff_result.bypass_suggestions,
                    "encoding_applied": diff_result.encoding_applied,
                },
            }

        except Exception as e:
            logger.error(f"Error testing payload {payload[:30]}: {e}")
            return None

    def _build_test_url(self, base_url: str, params: dict[str, str]) -> str:
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
        return urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment,
            )
        )

    def get_scan_statistics(self) -> dict[str, Any]:
        """Get scan statistics"""
        scan_duration = (
            time.time() - self.scan_start_time if self.scan_start_time else 0
        )

        return {
            "scan_duration": scan_duration,
            "total_tests": self.total_tests,
            "vulnerabilities_found": self.vulnerabilities_found,
            "dom_vulnerabilities_found": self.dom_vulnerabilities_found,
            "parameters_tested": len(self.tested_parameters),
            "wafs_detected": len(self.detected_wafs),
            "success_rate": self.vulnerabilities_found / max(1, self.total_tests),
        }
