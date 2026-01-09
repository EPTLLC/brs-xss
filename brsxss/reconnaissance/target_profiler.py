#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 14:37:26 MSK
Status: Created
Telegram: https://t.me/EasyProTech

Target Profiler - Main orchestrator for reconnaissance.
Coordinates all reconnaissance modules to build complete target profile.
"""

import asyncio
import time
from datetime import datetime
from typing import Optional, Dict, List, Any, Callable
from urllib.parse import urlparse, parse_qs

from .recon_types import (
    TargetProfile,
    DnsInfo,
    IpInfo,
    SslInfo,
    WafInfo,
    FilterProfile,
    RiskAssessment,
    RiskLevel,
    ProtectionStrength,
)
from .dns_resolver import DnsResolver
from .ssl_analyzer import SslAnalyzer
from .technology_detector import TechnologyDetector
from .headers_analyzer import HeadersAnalyzer
from .filter_probe import FilterProbe
from .endpoint_discovery import EndpointDiscovery, DiscoveryResult
from ..utils.logger import Logger

logger = Logger("recon.target_profiler")


class TargetProfiler:
    """
    Main orchestrator for target reconnaissance.
    Coordinates all reconnaissance modules to build complete target profile.
    """

    def __init__(
        self,
        http_client=None,
        timeout: float = 30.0,
        enable_filter_probe: bool = True,
        progress_callback: Optional[Callable[[str, int], Any]] = None,
    ):
        """
        Initialize target profiler.

        Args:
            http_client: HTTP client for requests
            timeout: Overall timeout for reconnaissance
            enable_filter_probe: Enable active filter probing
            progress_callback: Callback for progress updates (phase, percent)
        """
        self.http_client = http_client
        self.timeout = timeout
        self.enable_filter_probe = enable_filter_probe
        self.progress_callback = progress_callback

        # Initialize sub-modules
        self.dns_resolver = DnsResolver(timeout=10.0)
        self.ssl_analyzer = SslAnalyzer(timeout=10.0)
        self.tech_detector = TechnologyDetector()
        self.headers_analyzer = HeadersAnalyzer()
        self.filter_probe = FilterProbe(http_client=http_client, timeout=5.0)
        self.endpoint_discovery = EndpointDiscovery(
            http_client=http_client, max_depth=2, max_urls=50, timeout=30.0
        )

    async def profile_target(
        self, url: str, scan_id: str = "", parameters: Optional[Dict[str, str]] = None
    ) -> TargetProfile:
        """
        Build complete target profile.

        Args:
            url: Target URL
            scan_id: Associated scan ID
            parameters: Parameters to test for reflection

        Returns:
            Complete TargetProfile
        """
        start_time = time.time()

        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]

        profile = TargetProfile(
            url=url,
            domain=domain,
            scan_id=scan_id,
            timestamp=datetime.utcnow().isoformat(),
        )

        logger.info(f"Starting reconnaissance for: {domain}")

        # Extract parameters from URL if not provided
        if parameters is None:
            parameters = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        try:
            # Phase 1: DNS Resolution (10%)
            await self._notify_progress("dns_resolution", 5)
            profile.dns, profile.ip = await self._safe_execute(
                self.dns_resolver.resolve(url),
                (DnsInfo(domain=domain), IpInfo()),
                "DNS resolution",
            )
            await self._notify_progress("dns_resolution", 10)

            # Phase 2: SSL Analysis (20%)
            await self._notify_progress("ssl_analysis", 12)
            profile.ssl = await self._safe_execute(
                self.ssl_analyzer.analyze(url), SslInfo(), "SSL analysis"
            )
            await self._notify_progress("ssl_analysis", 20)

            # Phase 3: Initial Request for Headers/Content (35%)
            await self._notify_progress("http_analysis", 22)
            headers, content, cookies_raw = await self._fetch_initial_response(url)
            await self._notify_progress("http_analysis", 30)

            # Phase 4: Security Headers Analysis (40%)
            await self._notify_progress("headers_analysis", 32)
            profile.security_headers = self.headers_analyzer.analyze(headers)
            profile.cookies = self.headers_analyzer.analyze_cookies(cookies_raw)
            await self._notify_progress("headers_analysis", 40)

            # Phase 5: Server Detection (45%)
            await self._notify_progress("server_detection", 42)
            profile.server = self.tech_detector.detect_server(headers)
            await self._notify_progress("server_detection", 45)

            # Phase 6: Technology Detection (55%)
            await self._notify_progress("technology_detection", 47)
            profile.technology = self.tech_detector.detect(
                headers, content, profile.cookies
            )
            await self._notify_progress("technology_detection", 55)

            # Phase 7: WAF Detection (65%)
            await self._notify_progress("waf_detection", 57)
            profile.waf = await self._detect_waf(url, headers, content)
            await self._notify_progress("waf_detection", 65)

            # Phase 8: Endpoint Discovery (if no parameters provided) (75%)
            discovered_params = {}
            if not parameters:
                await self._notify_progress("endpoint_discovery", 50)
                discovery_result = await self._safe_execute(
                    self.endpoint_discovery.discover(url),
                    DiscoveryResult(),
                    "Endpoint discovery",
                )

                if discovery_result and discovery_result.endpoints:
                    profile.discovered_endpoints = discovery_result.to_dict()

                    # Collect all discovered parameters for filter probing
                    for endpoint in discovery_result.endpoints:
                        for param in endpoint.parameters:
                            discovered_params[param] = "test"

                    logger.info(
                        f"Discovered {len(discovery_result.endpoints)} endpoints, {len(discovered_params)} params"
                    )

                await self._notify_progress("endpoint_discovery", 70)
            else:
                discovered_params = parameters
                await self._notify_progress("endpoint_discovery", 70)

            # Phase 9: Filter Probe (if enabled) (85%)
            if self.enable_filter_probe and discovered_params:
                await self._notify_progress("filter_probe", 72)
                profile.filter_profile = await self._safe_execute(
                    self.filter_probe.probe_filters(
                        url, discovered_params, self.http_client
                    ),
                    FilterProfile(),
                    "Filter probe",
                )
                await self._notify_progress("filter_probe", 85)
            else:
                profile.filter_profile = FilterProfile()
                await self._notify_progress("filter_probe", 85)

            # Phase 10: Risk Assessment (95%)
            await self._notify_progress("risk_assessment", 87)
            profile.risk = self._calculate_risk_assessment(profile)
            await self._notify_progress("risk_assessment", 95)

            # Finalize
            profile.recon_duration_seconds = time.time() - start_time
            await self._notify_progress("complete", 100)

            logger.info(
                f"Reconnaissance complete for {domain} in {profile.recon_duration_seconds:.2f}s"
            )

        except Exception as e:
            logger.error(f"Reconnaissance failed: {e}")
            profile.recon_errors.append(str(e))
            profile.recon_duration_seconds = time.time() - start_time

        return profile

    async def _notify_progress(self, phase: str, percent: int):
        """Notify progress callback"""
        if self.progress_callback:
            try:
                result = self.progress_callback(phase, percent)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.debug(f"Progress callback error: {e}")

    async def _safe_execute(self, coro, default, operation: str):
        """Execute coroutine with error handling"""
        try:
            return await asyncio.wait_for(coro, timeout=self.timeout / 3)
        except asyncio.TimeoutError:
            logger.warning(f"{operation} timed out")
            return default
        except Exception as e:
            logger.warning(f"{operation} failed: {e}")
            return default

    async def _fetch_initial_response(self, url: str) -> tuple:
        """Fetch initial response for analysis"""
        headers: Dict[str, str] = {}
        content = ""
        cookies: List[str] = []

        if not self.http_client:
            logger.warning("No HTTP client for initial request")
            return headers, content, cookies

        try:
            response = await asyncio.wait_for(self.http_client.get(url), timeout=10.0)

            if response:
                headers = dict(response.headers) if hasattr(response, "headers") else {}
                content = response.text if hasattr(response, "text") else ""

                # Extract Set-Cookie headers
                if hasattr(response, "headers"):
                    # Handle both single and multiple Set-Cookie headers
                    if hasattr(response.headers, "getlist"):
                        cookies = response.headers.getlist("set-cookie")
                    elif "set-cookie" in headers:
                        cookies = [headers["set-cookie"]]

        except Exception as e:
            logger.warning(f"Initial request failed: {e}")

        return headers, content, cookies

    async def _detect_waf(
        self, url: str, headers: Dict[str, str], content: str
    ) -> WafInfo:
        """Detect WAF from response and probing"""
        waf_info = WafInfo()

        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        content_lower = content.lower()[:5000]

        # WAF signatures
        waf_signatures = {
            "cloudflare": {
                "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
                "content": ["cloudflare", "cf-browser-verification"],
                "vendor": "Cloudflare",
            },
            "akamai": {
                "headers": ["x-akamai", "akamai-origin-hop"],
                "content": ["akamai", "reference #"],
                "vendor": "Akamai",
            },
            "aws_waf": {
                "headers": ["x-amzn-requestid", "x-amz-cf-id"],
                "content": ["awswaf", "aws"],
                "vendor": "Amazon",
            },
            "imperva": {
                "headers": ["x-iinfo"],
                "content": ["incapsula", "imperva"],
                "vendor": "Imperva",
            },
            "sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache"],
                "content": ["sucuri", "sucuri website firewall"],
                "vendor": "Sucuri",
            },
            "modsecurity": {
                "headers": ["server: modsecurity"],
                "content": ["mod_security", "modsec", "not acceptable"],
                "vendor": "Trustwave",
            },
            "f5_big_ip": {
                "headers": ["x-wa-info", "x-cnection"],
                "content": ["bigip", "f5", "request rejected"],
                "vendor": "F5 Networks",
            },
            "barracuda": {
                "headers": ["barra_counter_session"],
                "content": ["barracuda"],
                "vendor": "Barracuda",
            },
            "fortinet": {
                "headers": [],
                "content": ["fortigate", "fortiweb", ".fgd_icon"],
                "vendor": "Fortinet",
            },
        }

        for waf_name, sigs in waf_signatures.items():
            confidence = 0.0
            evidence = []

            # Check headers
            for header_sig in sigs.get("headers", []):
                if header_sig in headers_lower:
                    confidence += 0.4
                    evidence.append(f"Header: {header_sig}")
                for h_val in headers_lower.values():
                    if header_sig in h_val:
                        confidence += 0.2
                        evidence.append(f"Header value contains: {header_sig}")

            # Check content
            for content_sig in sigs.get("content", []):
                if content_sig in content_lower:
                    confidence += 0.3
                    evidence.append(f"Content contains: {content_sig}")

            if confidence >= 0.3:
                waf_info.detected = True
                waf_info.name = waf_name.replace("_", " ").upper()
                waf_info.vendor = str(sigs.get("vendor", ""))
                waf_info.confidence = min(confidence, 1.0)
                waf_info.evidence = evidence
                waf_info.waf_type = (
                    "cloud"
                    if waf_name in ["cloudflare", "akamai", "aws_waf", "sucuri"]
                    else "host"
                )

                # Generate known bypasses
                waf_info.known_bypasses = self._get_waf_bypasses(waf_name)
                break

        return waf_info

    def _get_waf_bypasses(self, waf_name: str) -> List[str]:
        """Get known bypass techniques for WAF"""
        bypasses = {
            "cloudflare": [
                "Origin IP discovery via historical DNS",
                "Unicode normalization bypass",
                "Double URL encoding",
                "JSFuck/Hieroglyphy obfuscation",
                "Chunked transfer encoding",
            ],
            "akamai": [
                "Request smuggling",
                "Unicode bypass",
                "HPP (HTTP Parameter Pollution)",
                "Content-Type manipulation",
            ],
            "modsecurity": [
                "Rule-specific bypasses",
                "Comment injection",
                "Case variation",
                "Null byte injection",
            ],
            "aws_waf": [
                "Unicode normalization",
                "Size limit bypass",
                "Rate limiting timing",
            ],
        }
        return bypasses.get(
            waf_name, ["Try encoding variations", "Test alternative payloads"]
        )

    def _calculate_risk_assessment(self, profile: TargetProfile) -> RiskAssessment:
        """Calculate overall risk assessment"""
        risk = RiskAssessment()

        score = 5.0  # Start at medium

        # WAF reduces risk
        if profile.waf and profile.waf.detected:
            score -= 1.5
            if profile.waf.confidence > 0.8:
                score -= 0.5
            risk.waf_strength = (
                ProtectionStrength.STRONG
                if profile.waf.confidence > 0.7
                else ProtectionStrength.MEDIUM
            )
        else:
            risk.waf_strength = ProtectionStrength.NONE
            score += 1.0

        # Security headers reduce risk
        if profile.security_headers:
            if (
                profile.security_headers.csp_present
                and not profile.security_headers.csp_has_unsafe_inline
            ):
                score -= 1.5
                risk.header_strength = ProtectionStrength.STRONG
            elif profile.security_headers.csp_present:
                score -= 0.5
                risk.header_strength = ProtectionStrength.MEDIUM
            else:
                score += 0.5
                risk.header_strength = ProtectionStrength.WEAK

            risk.weak_csp = profile.security_headers.csp_has_unsafe_inline
        else:
            risk.header_strength = ProtectionStrength.NONE

        # Filter profile affects risk
        if profile.filter_profile:
            if profile.filter_profile.filter_strength == ProtectionStrength.STRONG:
                score -= 1.0
                risk.filter_strength = ProtectionStrength.STRONG
            elif profile.filter_profile.filter_strength == ProtectionStrength.MEDIUM:
                score -= 0.5
                risk.filter_strength = ProtectionStrength.MEDIUM
            elif profile.filter_profile.filter_strength == ProtectionStrength.WEAK:
                score += 0.5
                risk.filter_strength = ProtectionStrength.WEAK
            else:
                score += 1.0
                risk.filter_strength = ProtectionStrength.NONE

            risk.filter_bypass_chance = (
                0.8 if profile.filter_profile.is_bypassable else 0.2
            )

        # Calculate bypass chances
        if profile.waf and profile.waf.detected:
            if profile.waf.confidence > 0.9:
                risk.waf_bypass_chance = 0.3
            elif profile.waf.confidence > 0.7:
                risk.waf_bypass_chance = 0.5
            else:
                risk.waf_bypass_chance = 0.7
        else:
            risk.waf_bypass_chance = 1.0

        # CSP bypass chance
        if profile.security_headers and profile.security_headers.csp_present:
            if profile.security_headers.csp_has_unsafe_inline:
                risk.csp_bypass_chance = 0.9
            elif profile.security_headers.csp_has_unsafe_eval:
                risk.csp_bypass_chance = 0.6
            else:
                risk.csp_bypass_chance = 0.2
        else:
            risk.csp_bypass_chance = 1.0

        # Normalize score
        score = max(0.0, min(10.0, score))
        risk.overall_score = round(score, 1)

        # Determine risk level
        if score >= 8.0:
            risk.risk_level = RiskLevel.CRITICAL
        elif score >= 6.5:
            risk.risk_level = RiskLevel.HIGH
        elif score >= 4.5:
            risk.risk_level = RiskLevel.MEDIUM
        elif score >= 2.5:
            risk.risk_level = RiskLevel.LOW
        else:
            risk.risk_level = RiskLevel.INFO

        # Generate recommendations
        risk.recommended_strategy = self._generate_strategy(profile, risk)
        risk.primary_vector = self._determine_primary_vector(profile)
        risk.recommended_encoding = self._determine_encoding(profile)
        risk.evasion_techniques = self._determine_evasion_techniques(profile)
        risk.estimated_payloads = self._estimate_payload_count(profile, risk)

        return risk

    def _generate_strategy(self, profile: TargetProfile, risk: RiskAssessment) -> str:
        """Generate recommended scan strategy"""
        if risk.waf_strength == ProtectionStrength.STRONG:
            return "Stealth mode with WAF evasion, reduced payload set, encoding bypass"
        elif risk.waf_strength == ProtectionStrength.MEDIUM:
            return "Adaptive mode with WAF evasion techniques"
        elif risk.filter_strength in [
            ProtectionStrength.STRONG,
            ProtectionStrength.MEDIUM,
        ]:
            return "Focus on encoding bypass and alternative vectors"
        else:
            return "Standard mode with full payload coverage"

    def _determine_primary_vector(self, profile: TargetProfile) -> str:
        """Determine primary attack vector"""
        if profile.filter_profile and profile.filter_profile.best_vector:
            return profile.filter_profile.best_vector

        return "Context-dependent (analyze after crawling)"

    def _determine_encoding(self, profile: TargetProfile) -> str:
        """Determine recommended encoding"""
        if profile.filter_profile and profile.filter_profile.best_encoding:
            return profile.filter_profile.best_encoding

        return "Standard (no special encoding required)"

    def _determine_evasion_techniques(self, profile: TargetProfile) -> List[str]:
        """Determine evasion techniques to use"""
        techniques = []

        if profile.waf and profile.waf.detected:
            techniques.extend(profile.waf.known_bypasses[:3])

        if profile.filter_profile:
            techniques.extend(profile.filter_profile.bypass_techniques[:3])

        if not techniques:
            techniques = ["Standard payloads should work"]

        return list(set(techniques))[:5]

    def _estimate_payload_count(
        self, profile: TargetProfile, risk: RiskAssessment
    ) -> int:
        """Estimate optimal payload count"""
        base_count = 50

        # More payloads if no WAF
        if not profile.waf or not profile.waf.detected:
            base_count += 100

        # More payloads if weak filtering
        if risk.filter_strength in [ProtectionStrength.NONE, ProtectionStrength.WEAK]:
            base_count += 50

        # Fewer payloads if strong protection
        if risk.waf_strength == ProtectionStrength.STRONG:
            base_count = min(base_count, 30)

        return base_count
