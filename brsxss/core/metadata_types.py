#!/usr/bin/env python3

"""
BRS-XSS Metadata Types

Data types for scan metadata collection.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

import platform as _platform
from ..version import VERSION
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class ScanEnvironment:
    """Scan environment information"""
    scanner_version: str = VERSION
    python_version: str = _platform.python_version()
    platform: str = _platform.platform()
    hostname: str = _platform.node()
    scan_id: str = ""
    start_time: float = 0.0
    end_time: float = 0.0


@dataclass
class TargetMetadata:
    """Target-specific metadata"""
    url: str = ""
    domain: str = ""
    ip_address: str = ""
    technologies: List[str] = field(default_factory=list)
    cms_detected: str = ""
    server_software: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    status_codes_seen: List[int] = field(default_factory=list)


@dataclass
class ScanConfiguration:
    """Scan configuration metadata"""
    scan_type: str = "full"
    timeout: int = 10
    max_concurrent: int = 10
    deep_scan: bool = False
    ml_mode: bool = False
    blind_xss_enabled: bool = False
    blind_xss_webhook: str = ""
    custom_payloads: bool = False
    waf_evasion: bool = True


@dataclass
class SecurityFindings:
    """Security findings summary"""
    total_vulnerabilities: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0
    contexts_tested: List[str] = field(default_factory=list)
    waf_detected: List[str] = field(default_factory=list)
    bypass_techniques_used: List[str] = field(default_factory=list)
    unique_contexts: int = 0


@dataclass
class PerformanceMetrics:
    """Scan performance metrics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time: float = 0.0
    requests_per_second: float = 0.0
    total_payloads_tested: int = 0
    unique_parameters_found: int = 0
    scan_duration: float = 0.0


@dataclass
class QualityMetrics:
    """Scan quality and coverage metrics"""
    parameter_coverage: float = 0.0  # Percentage of parameters tested
    context_coverage: float = 0.0    # Percentage of contexts analyzed
    payload_diversity: float = 0.0   # Diversity of payloads used
    false_positive_rate: float = 0.0
    confidence_score: float = 0.0
    completeness_score: float = 0.0