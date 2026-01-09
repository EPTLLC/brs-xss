#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 25 Dec 2025 13:30:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Pydantic models for Web UI API.
"""

from datetime import datetime
from typing import Optional, Any
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict
import uuid


class ScanMode(str, Enum):
    """Scan mode options"""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    STEALTH = "stealth"


class PerformanceMode(str, Enum):
    """Performance mode options"""

    LIGHT = "light"
    STANDARD = "standard"
    TURBO = "turbo"
    MAXIMUM = "maximum"


class ScanStatus(str, Enum):
    """Scan status"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, Enum):
    """Vulnerability severity"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============ Request Models ============


class ScanRequest(BaseModel):
    """New scan request"""

    target_url: str = Field(..., alias="url", description="Target URL to scan")
    mode: ScanMode = Field(default=ScanMode.STANDARD, description="Scan mode")
    performance_mode: PerformanceMode = Field(
        default=PerformanceMode.STANDARD, description="Performance mode"
    )
    follow_redirects: bool = Field(default=True)
    crawl_depth: int = Field(default=2, ge=0, le=10, alias="max_depth")
    include_subdomains: bool = Field(default=False)
    custom_headers: Optional[dict[str, str]] = None
    custom_cookies: Optional[dict[str, str]] = None
    excluded_paths: Optional[list[str]] = None
    blind_xss: bool = Field(default=False, alias="blind_xss_enabled")
    waf_bypass: bool = Field(default=True, alias="waf_bypass_enabled")
    dom_analysis: bool = Field(default=True)
    dom_analysis_enabled: bool = Field(default=True)

    model_config = ConfigDict(populate_by_name=True)


class ScanUpdateRequest(BaseModel):
    """Update scan settings"""

    status: Optional[ScanStatus] = None
    notes: Optional[str] = None


# ============ Response Models ============


class VulnerabilityInfo(BaseModel):
    """Single vulnerability finding (aggregated per parameter)"""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    url: str
    parameter: str
    context_type: str
    context: Optional[str] = None
    severity: SeverityLevel
    confidence: float = Field(ge=0, le=1)
    payload: str  # Primary payload

    # Evidence aggregation (Finding vs Evidence pattern)
    evidence_count: int = 1  # Number of confirmed payloads
    evidence_payloads: Optional[list[str]] = None  # Additional payloads that worked
    contexts: Optional[list[str]] = None  # All contexts where XSS was found
    early_stopped: bool = False  # True if stopped early after confirmation

    # KB metadata (KB is source of truth for severity and CVSS)
    payload_id: Optional[str] = None  # KB payload ID
    payload_name: Optional[str] = None  # Human-readable name
    payload_description: Optional[str] = None  # Description from KB
    payload_contexts: Optional[list[str]] = None  # Applicable contexts
    payload_tags: Optional[list[str]] = None  # Tags from KB
    cvss_score: Optional[float] = None  # CVSS score from KB (0.0-10.0)

    # Detection info
    evidence: Optional[str] = None
    waf_detected: Optional[str] = None
    bypass_used: Optional[str] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    payload_class: Optional[str] = None
    trigger: Optional[str] = None
    impact_scope: Optional[str] = None
    confidence_level: Optional[str] = None
    authorization_ref: Optional[str] = None
    test_mode: Optional[str] = None
    xss_type: Optional[str] = None
    reflection_type: Optional[str] = None
    sink: Optional[str] = None
    source: Optional[str] = None
    found_at: datetime = Field(default_factory=datetime.utcnow)


class WAFInfo(BaseModel):
    """Detected WAF information"""

    name: str
    type: str
    confidence: float
    bypass_available: bool = False


class ScanProgress(BaseModel):
    """Real-time scan progress"""

    scan_id: str
    status: ScanStatus
    progress_percent: float = Field(ge=0, le=100)
    urls_scanned: int = 0
    urls_total: int = 0
    vulnerabilities_found: int = 0
    current_url: Optional[str] = None
    current_phase: str = "initializing"
    elapsed_seconds: float = 0
    estimated_remaining_seconds: Optional[float] = None


class ScanResult(BaseModel):
    """Complete scan result"""

    id: str
    url: str
    mode: ScanMode
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None

    # Results
    vulnerabilities: list[VulnerabilityInfo] = Field(default_factory=list)
    waf_detected: Optional[WAFInfo] = None

    # Statistics
    urls_scanned: int = 0
    parameters_tested: int = 0
    payloads_sent: int = 0

    # Counts by severity
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    # Performance
    duration_seconds: float = 0
    performance_mode: Optional[PerformanceMode] = None

    # Notes
    notes: Optional[str] = None
    error_message: Optional[str] = None


class ProxyUsed(BaseModel):
    """Proxy info at scan time"""

    enabled: bool = False
    ip: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None


class ScanSummary(BaseModel):
    """Brief scan summary for list view"""

    id: str
    url: str
    mode: ScanMode
    performance_mode: str = "standard"
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0
    vulnerability_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    proxy_used: Optional[ProxyUsed] = None


class DashboardStats(BaseModel):
    """Dashboard statistics"""

    total_scans: int = 0
    scans_today: int = 0
    scans_this_week: int = 0
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    most_common_context: Optional[str] = None
    most_common_waf: Optional[str] = None
    avg_scan_duration_seconds: float = 0
    recent_scans: list[ScanSummary] = Field(default_factory=list)


class ProxyProtocolType(str, Enum):
    """Proxy protocol types"""

    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


class SavedProxy(BaseModel):
    """Saved proxy entry"""

    id: str  # Unique ID for this proxy
    name: str = ""  # User-friendly name
    host: str = ""
    port: int = 0
    username: Optional[str] = None
    password: Optional[str] = None
    protocol: ProxyProtocolType = ProxyProtocolType.SOCKS5
    proxy_string: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    last_tested: Optional[str] = None
    is_working: bool = True


class ProxySettings(BaseModel):
    """Proxy configuration with saved proxies list"""

    enabled: bool = False
    active_proxy_id: Optional[str] = None  # ID of currently active proxy

    # Current active proxy details (for backwards compatibility)
    host: str = ""
    port: int = 0
    username: Optional[str] = None
    password: Optional[str] = None
    protocol: ProxyProtocolType = ProxyProtocolType.SOCKS5
    proxy_string: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None

    # list of saved proxies (max 10 in MIT version)
    saved_proxies: list[SavedProxy] = Field(default_factory=list)


class ProxyTestResult(BaseModel):
    """Proxy connection test result"""

    success: bool
    ip: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class SettingsModel(BaseModel):
    """Application settings"""

    # Scanner settings
    default_mode: ScanMode = ScanMode.STANDARD
    default_max_depth: int = 2
    default_timeout_seconds: int = 30
    max_concurrent_scans: int = 3

    # Proxy settings
    proxy: ProxySettings = Field(default_factory=ProxySettings)

    # Blind XSS
    blind_xss_server_url: Optional[str] = None
    blind_xss_webhook_enabled: bool = False

    # Telegram Integration
    telegram_enabled: bool = False
    telegram_bot_token: Optional[str] = None
    telegram_channel_id: Optional[int] = None
    telegram_channel_input: Optional[str] = (
        None  # Original user input (link, @username, or ID)
    )
    telegram_discussion_group_id: Optional[int] = None
    telegram_notify_level: str = "critical"  # off, critical, high, all

    # UI preferences
    theme: str = "dark"
    language: str = "en"
    results_per_page: int = 20


# ============ WebSocket Messages ============


class WSMessage(BaseModel):
    """WebSocket message wrapper"""

    type: str
    data: dict[str, Any]


class WSScanProgress(BaseModel):
    """WebSocket scan progress update"""

    scan_id: str
    progress: ScanProgress


class WSScanComplete(BaseModel):
    """WebSocket scan completion notification"""

    scan_id: str
    result: ScanResult


class WSVulnerabilityFound(BaseModel):
    """WebSocket vulnerability found notification"""

    scan_id: str
    vulnerability: VulnerabilityInfo


# ============ Reconnaissance Models ============


class GeoInfoModel(BaseModel):
    """Geolocation information"""

    country: str = "Unknown"
    country_code: str = ""
    region: str = ""
    city: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: str = ""
    isp: str = ""
    organization: str = ""
    asn: str = ""
    asn_name: str = ""


class DnsRecordModel(BaseModel):
    """DNS record"""

    record_type: str
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None


class DnsInfoModel(BaseModel):
    """DNS information"""

    domain: str
    records: dict[str, list[DnsRecordModel]] = Field(default_factory=dict)
    nameservers: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    has_dnssec: bool = False


class IpInfoModel(BaseModel):
    """IP address information"""

    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    ptr_record: Optional[str] = None
    geo: Optional[GeoInfoModel] = None
    is_cloudflare: bool = False
    is_cdn: bool = False
    cdn_provider: Optional[str] = None
    hosting_provider: Optional[str] = None


class SslInfoModel(BaseModel):
    """SSL/TLS certificate information"""

    enabled: bool = False
    protocol: str = ""
    cipher_suite: str = ""
    subject: str = ""
    issuer: str = ""
    valid_from: str = ""
    valid_until: str = ""
    days_until_expiry: int = 0
    is_expired: bool = False
    is_self_signed: bool = False
    san_domains: list[str] = Field(default_factory=list)
    has_wildcard: bool = False
    grade: str = ""


class ServerInfoModel(BaseModel):
    """Web server information"""

    server_name: str = ""
    server_version: str = ""
    operating_system: str = ""
    powered_by: str = ""
    proxy_server: str = ""
    response_time_total_ms: float = 0
    compression_gzip: bool = False
    compression_brotli: bool = False
    http2_enabled: bool = False


class SecurityHeadersModel(BaseModel):
    """Security headers analysis"""

    csp_present: bool = False
    csp_policy: str = ""
    csp_has_unsafe_inline: bool = False
    csp_has_unsafe_eval: bool = False
    csp_analysis: str = ""
    x_frame_options: str = ""
    x_content_type_options: str = ""
    x_xss_protection: str = ""
    referrer_policy: str = ""
    hsts_enabled: bool = False
    hsts_max_age: int = 0
    cors_enabled: bool = False
    cors_allow_origin: str = ""
    cors_is_permissive: bool = False
    missing_headers: list[str] = Field(default_factory=list)
    score: int = 0
    grade: str = ""


class TechnologyInfoModel(BaseModel):
    """Detected technology stack"""

    backend_language: str = ""
    backend_version: str = ""
    backend_framework: str = ""
    framework_version: str = ""
    cms: str = ""
    cms_version: str = ""
    frontend_framework: str = ""
    frontend_version: str = ""
    cdn: str = ""
    analytics: list[str] = Field(default_factory=list)
    javascript_libraries: list[dict[str, str]] = Field(default_factory=list)


class WafInfoModel(BaseModel):
    """WAF detection information"""

    detected: bool = False
    name: str = ""
    vendor: str = ""
    waf_type: str = ""
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    known_bypasses: list[str] = Field(default_factory=list)


class FilterProfileModel(BaseModel):
    """Filter analysis profile"""

    filter_type: str = ""
    filter_strength: str = ""
    is_bypassable: bool = True
    bypass_techniques: list[str] = Field(default_factory=list)
    best_vector: str = ""
    best_encoding: str = ""
    blocked_tags: list[str] = Field(default_factory=list)
    allowed_tags: list[str] = Field(default_factory=list)
    blocked_events: list[str] = Field(default_factory=list)
    allowed_events: list[str] = Field(default_factory=list)


class CookieInfoModel(BaseModel):
    """Cookie analysis"""

    name: str
    secure: bool = False
    http_only: bool = False
    same_site: str = ""
    purpose: str = ""


class RiskAssessmentModel(BaseModel):
    """Overall risk assessment"""

    overall_score: float = 0.0
    risk_level: str = "medium"
    waf_bypass_chance: float = 0.0
    filter_bypass_chance: float = 0.0
    csp_bypass_chance: float = 0.0
    recommended_strategy: str = ""
    primary_vector: str = ""
    recommended_encoding: str = ""
    evasion_techniques: list[str] = Field(default_factory=list)
    estimated_payloads: int = 0


class TargetProfileModel(BaseModel):
    """Complete target reconnaissance profile"""

    url: str
    domain: str
    timestamp: str = ""
    scan_id: str = ""

    dns: Optional[DnsInfoModel] = None
    ip: Optional[IpInfoModel] = None
    ssl: Optional[SslInfoModel] = None
    server: Optional[ServerInfoModel] = None
    security_headers: Optional[SecurityHeadersModel] = None
    technology: Optional[TechnologyInfoModel] = None
    waf: Optional[WafInfoModel] = None
    filter_profile: Optional[FilterProfileModel] = None
    cookies: list[CookieInfoModel] = Field(default_factory=list)
    risk: Optional[RiskAssessmentModel] = None

    recon_duration_seconds: float = 0.0
    recon_errors: list[str] = Field(default_factory=list)


class WSReconProgress(BaseModel):
    """WebSocket reconnaissance progress update"""

    scan_id: str
    phase: str
    percent: int
    message: str = ""


class WSReconComplete(BaseModel):
    """WebSocket reconnaissance complete notification"""

    scan_id: str
    profile: TargetProfileModel
