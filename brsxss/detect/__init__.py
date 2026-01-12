"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 10:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Detection Module - All detection functionality.

Structure:
    detect/
    ├── xss/           # XSS vulnerability detection
    │   ├── reflected/ # HTTP-based reflected XSS
    │   ├── dom/       # Browser-based DOM XSS
    │   └── stored/    # Stored XSS (future)
    ├── waf/           # WAF detection and bypass
    ├── crawler/       # URL and form discovery
    ├── recon/         # Target reconnaissance
    └── payloads/      # Payload management
"""

# XSS Detection - Reflected
from .xss.reflected.scanner import XSSScanner
from .xss.reflected.http_client import HTTPClient, HTTPResponse
from .xss.reflected.context_analyzer import ContextAnalyzer, ContextType, InjectionPoint
from .xss.reflected.payload_generator import PayloadGenerator, GeneratedPayload

# XSS Detection - DOM
from .xss.dom.headless_detector import HeadlessDOMDetector
from .xss.dom.dom_analyzer import DOMAnalyzer
from .xss.dom.detector import DOMXSSDetector

# WAF Detection
from .waf.detector import WAFDetector
# WAFDetectionResult removed - does not exist
from .waf.evasion_engine import EvasionEngine

# Crawler
from .crawler.engine import CrawlerEngine
from .crawler.form_extractor import FormExtractor
from .crawler.url_discovery import URLDiscovery

# Reconnaissance
from .recon.target_profiler import TargetProfiler
from .recon.technology_detector import TechnologyDetector
from .recon.headers_analyzer import HeadersAnalyzer

# Payloads
from .payloads.kb_adapter import KBAdapter, get_kb_adapter
from .payloads.payload_manager import PayloadManager

__all__ = [
    # XSS Reflected
    "XSSScanner",
    "HTTPClient",
    "HTTPResponse",
    "ContextAnalyzer",
    "ContextType",
    "InjectionPoint",
    "PayloadGenerator",
    "GeneratedPayload",
    # XSS DOM
    "HeadlessDOMDetector",
    "DOMAnalyzer",
    "DOMXSSDetector",
    # WAF
    "WAFDetector",
    "EvasionEngine",
    # Crawler
    "CrawlerEngine",
    "FormExtractor",
    "URLDiscovery",
    # Recon
    "TargetProfiler",
    "TechnologyDetector",
    "HeadersAnalyzer",
    # Payloads
    "KBAdapter",
    "get_kb_adapter",
    "PayloadManager",
]
