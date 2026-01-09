#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 14:37:26 MSK
Status: Created
Telegram: https://t.me/EasyProTech

Reconnaissance module for target profiling.
Provides complete target intelligence before scanning.
"""

from .recon_types import (
    TargetProfile,
    DnsInfo,
    DnsRecord,
    IpInfo,
    GeoInfo,
    SslInfo,
    ServerInfo,
    SecurityHeaders,
    TechnologyInfo,
    WafInfo,
    FilterProfile,
    FilterStatus,
    CookieInfo,
    RiskAssessment,
    RiskLevel,
    ProtectionStrength,
    ParameterProfile,
    ReflectionPoint,
    ApplicationStructure,
)

from .target_profiler import TargetProfiler
from .dns_resolver import DnsResolver
from .ssl_analyzer import SslAnalyzer
from .technology_detector import TechnologyDetector
from .headers_analyzer import HeadersAnalyzer
from .filter_probe import FilterProbe
from .endpoint_discovery import EndpointDiscovery, DiscoveryResult

__all__ = [
    # Main profiler
    "TargetProfiler",
    # Sub-modules
    "DnsResolver",
    "SslAnalyzer",
    "TechnologyDetector",
    "HeadersAnalyzer",
    "FilterProbe",
    "EndpointDiscovery",
    "DiscoveryResult",
    # Data types
    "TargetProfile",
    "DnsInfo",
    "DnsRecord",
    "IpInfo",
    "GeoInfo",
    "SslInfo",
    "ServerInfo",
    "SecurityHeaders",
    "TechnologyInfo",
    "WafInfo",
    "FilterProfile",
    "FilterStatus",
    "CookieInfo",
    "RiskAssessment",
    "RiskLevel",
    "ProtectionStrength",
    "ParameterProfile",
    "ReflectionPoint",
    "ApplicationStructure",
]
