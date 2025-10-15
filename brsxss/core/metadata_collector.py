#!/usr/bin/env python3

"""
BRS-XSS Metadata Collector

Main metadata collection orchestrator.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

import time
import hashlib
import platform
from typing import Optional, List
from .metadata_types import (
    ScanEnvironment, TargetMetadata, ScanConfiguration,
    SecurityFindings, PerformanceMetrics, QualityMetrics
)

from ..utils.logger import Logger

logger = Logger("core.metadata_collector")


class ScanMetadataCollector:
    """
    Main metadata collector for security scans.
    
    Collects:
    - Environment information
    - Target details
    - Scan configuration
    - Performance metrics
    - Security findings
    """
    
    def __init__(self, scan_id: Optional[str] = None):
        """Initialize metadata collector"""
        self.scan_id = scan_id or self._generate_scan_id()
        self.start_time = time.time()
        
        # Initialize all metadata structures
        self.environment = ScanEnvironment(scan_id=self.scan_id, start_time=self.start_time)
        self.target = TargetMetadata()
        self.configuration = ScanConfiguration()
        self.findings = SecurityFindings(contexts_tested=[], waf_detected=[], bypass_techniques_used=[])
        self.performance = PerformanceMetrics()
        self.quality = QualityMetrics()
        
        # Additional tracking
        self.request_times: List[float] = []
        self.tested_parameters: set[str] = set()
        self.tested_contexts: set[str] = set()
        self.payload_types_used: set[str] = set()
        
        logger.info(f"Scan metadata collector initialized: {self.scan_id}")
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        timestamp = str(int(time.time()))
        random_part = hashlib.md5(f"{time.time()}{platform.node()}".encode()).hexdigest()[:8]
        return f"brs-xss-{timestamp}-{random_part}"
    
    def set_target_info(self, url: str, **kwargs) -> None:
        """Set target information"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        self.target.url = url
        self.target.domain = parsed.netloc
        
        # Update with additional info
        for key, value in kwargs.items():
            if hasattr(self.target, key):
                setattr(self.target, key, value)
        
        logger.debug(f"Target info updated: {self.target.domain}")
    
    def set_scan_config(self, **config_params) -> None:
        """Set scan configuration parameters"""
        for key, value in config_params.items():
            if hasattr(self.configuration, key):
                setattr(self.configuration, key, value)
        
        logger.debug("Scan configuration updated")
    
    def record_request(self, response_time: float, status_code: int, success: bool = True) -> None:
        """Record individual request metrics"""
        self.request_times.append(response_time)
        self.performance.total_requests += 1
        
        if success:
            self.performance.successful_requests += 1
        else:
            self.performance.failed_requests += 1
        
        # Track status codes
        if self.target.status_codes_seen is None:
            self.target.status_codes_seen = []
        
        if status_code not in self.target.status_codes_seen:
            self.target.status_codes_seen.append(status_code)
    
    def record_parameter_test(self, parameter: str, context: str = "unknown") -> None:
        """Record parameter testing"""
        self.tested_parameters.add(parameter)
        self.tested_contexts.add(context)
        self.performance.unique_parameters_found = len(self.tested_parameters)
    
    def record_payload_test(self, payload_type: str) -> None:
        """Record payload testing"""
        self.payload_types_used.add(payload_type)
        self.performance.total_payloads_tested += 1
    
    def record_vulnerability(self, severity: str, context: str = "") -> None:
        """Record vulnerability finding"""
        self.findings.total_vulnerabilities += 1
        
        if severity.lower() == "high":
            self.findings.high_severity += 1
        elif severity.lower() == "medium":
            self.findings.medium_severity += 1
        elif severity.lower() == "low":
            self.findings.low_severity += 1
        
        if context and context not in self.findings.contexts_tested:
            self.findings.contexts_tested.append(context)
    
    def record_waf_detection(self, waf_name: str) -> None:
        """Record WAF detection"""
        if waf_name not in self.findings.waf_detected:
            self.findings.waf_detected.append(waf_name)
    
    def record_bypass_technique(self, technique: str) -> None:
        """Record bypass technique usage"""
        if technique not in self.findings.bypass_techniques_used:
            self.findings.bypass_techniques_used.append(technique)
    
    def finalize_scan(self) -> None:
        """Finalize scan and calculate metrics"""
        self.environment.end_time = time.time()
        self.performance.scan_duration = self.environment.end_time - self.environment.start_time
        
        # Calculate performance metrics
        if self.request_times:
            self.performance.average_response_time = sum(self.request_times) / len(self.request_times)
            
            if self.performance.scan_duration > 0:
                self.performance.requests_per_second = self.performance.total_requests / self.performance.scan_duration
        
        # Calculate quality metrics
        self._calculate_quality_metrics()
        
        # Update findings
        self.findings.unique_contexts = len(self.tested_contexts)
        
        logger.info(f"Scan finalized: {self.performance.scan_duration:.2f}s, {self.findings.total_vulnerabilities} vulnerabilities")
    
    def _calculate_quality_metrics(self) -> None:
        """Calculate scan quality metrics"""
        
        # Parameter coverage
        if self.performance.unique_parameters_found > 0:
            self.quality.parameter_coverage = min(1.0, self.performance.total_payloads_tested / 
                                                 (self.performance.unique_parameters_found * 10))
        
        # Context coverage
        expected_contexts = ["html", "attribute", "javascript", "css", "url"]
        found_contexts = len(self.tested_contexts)
        self.quality.context_coverage = min(1.0, found_contexts / len(expected_contexts))
        
        # Payload diversity
        expected_payload_types = 10
        self.quality.payload_diversity = min(1.0, len(self.payload_types_used) / expected_payload_types)
        
        # Confidence score
        factors = [
            self.quality.parameter_coverage,
            self.quality.context_coverage,
            self.quality.payload_diversity,
            min(1.0, self.performance.successful_requests / max(1, self.performance.total_requests)),
        ]
        self.quality.confidence_score = sum(factors) / len(factors)
        
        # Completeness score
        completeness_factors = [
            1.0 if self.performance.scan_duration > 10 else self.performance.scan_duration / 10,
            1.0 if self.performance.total_requests > 50 else self.performance.total_requests / 50,
            self.quality.context_coverage,
            1.0 if len(self.findings.waf_detected) > 0 else 0.5,
        ]
        self.quality.completeness_score = sum(completeness_factors) / len(completeness_factors)