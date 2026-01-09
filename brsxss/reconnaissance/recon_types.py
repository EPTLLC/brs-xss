#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 14:37:26 MSK
Status: Created
Telegram: https://t.me/EasyProTech

Reconnaissance data types and models.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum


class FilterStatus(Enum):
    """Filter status for character/tag testing"""

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    ENCODED = "encoded"
    STRIPPED = "stripped"
    MODIFIED = "modified"


class RiskLevel(Enum):
    """Risk level assessment"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ProtectionStrength(Enum):
    """Protection strength level"""

    NONE = "none"
    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"
    VERY_STRONG = "very_strong"


@dataclass
class DnsRecord:
    """Single DNS record"""

    record_type: str
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None


@dataclass
class DnsInfo:
    """DNS information for target"""

    domain: str
    records: Dict[str, List[DnsRecord]] = field(default_factory=dict)
    nameservers: List[str] = field(default_factory=list)
    mx_records: List[DnsRecord] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    has_dnssec: bool = False
    soa_record: Optional[str] = None


@dataclass
class GeoInfo:
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


@dataclass
class IpInfo:
    """IP address information"""

    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    ptr_record: Optional[str] = None
    geo: Optional[GeoInfo] = None
    is_cloudflare: bool = False
    is_cdn: bool = False
    cdn_provider: Optional[str] = None
    hosting_provider: Optional[str] = None


@dataclass
class SslInfo:
    """SSL/TLS certificate information"""

    enabled: bool = False
    protocol: str = ""
    cipher_suite: str = ""

    # Certificate info
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    valid_from: str = ""
    valid_until: str = ""
    days_until_expiry: int = 0
    is_expired: bool = False
    is_self_signed: bool = False

    # SAN (Subject Alternative Names)
    san_domains: List[str] = field(default_factory=list)
    has_wildcard: bool = False

    # Chain
    chain_length: int = 0
    chain_valid: bool = True

    # Features
    ocsp_stapling: bool = False
    ct_logs_present: bool = False

    # Grade
    grade: str = ""


@dataclass
class CookieInfo:
    """Cookie analysis"""

    name: str
    value_preview: str = ""
    domain: str = ""
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str = ""
    expires: Optional[str] = None
    purpose: str = ""


@dataclass
class SecurityHeaders:
    """Security headers analysis"""

    # CSP
    csp_present: bool = False
    csp_policy: str = ""
    csp_directives: Dict[str, str] = field(default_factory=dict)
    csp_has_unsafe_inline: bool = False
    csp_has_unsafe_eval: bool = False
    csp_analysis: str = ""

    # Other security headers
    x_frame_options: str = ""
    x_content_type_options: str = ""
    x_xss_protection: str = ""
    referrer_policy: str = ""
    permissions_policy: str = ""

    # HSTS
    hsts_enabled: bool = False
    hsts_max_age: int = 0
    hsts_include_subdomains: bool = False
    hsts_preload: bool = False

    # CORS
    cors_enabled: bool = False
    cors_allow_origin: str = ""
    cors_allow_methods: List[str] = field(default_factory=list)
    cors_allow_credentials: bool = False
    cors_is_permissive: bool = False

    # Missing headers
    missing_headers: List[str] = field(default_factory=list)

    # Overall score
    score: int = 0
    grade: str = ""


@dataclass
class ServerInfo:
    """Web server information"""

    server_name: str = ""
    server_version: str = ""
    operating_system: str = ""
    powered_by: str = ""
    proxy_server: str = ""

    # Response info
    response_time_dns_ms: float = 0
    response_time_connect_ms: float = 0
    response_time_tls_ms: float = 0
    response_time_ttfb_ms: float = 0
    response_time_total_ms: float = 0

    # Features
    compression_gzip: bool = False
    compression_brotli: bool = False
    compression_deflate: bool = False

    http2_enabled: bool = False
    http3_enabled: bool = False


@dataclass
class TechnologyInfo:
    """Detected technology stack"""

    # Backend
    backend_language: str = ""
    backend_version: str = ""
    backend_framework: str = ""
    framework_version: str = ""
    cms: str = ""
    cms_version: str = ""

    # Frontend
    frontend_framework: str = ""
    frontend_version: str = ""
    ui_library: str = ""
    bundler: str = ""
    javascript_libraries: List[Dict[str, str]] = field(default_factory=list)

    # Infrastructure
    cdn: str = ""
    dns_provider: str = ""
    hosting: str = ""
    container: str = ""
    reverse_proxy: str = ""

    # Analytics
    analytics: List[str] = field(default_factory=list)
    tracking_ids: Dict[str, str] = field(default_factory=dict)

    # Third-party services
    third_party_services: List[str] = field(default_factory=list)

    # Meta
    meta_generator: str = ""
    meta_language: str = ""

    # Detection confidence
    detection_confidence: float = 0.0


@dataclass
class WafInfo:
    """WAF detection information"""

    detected: bool = False
    name: str = ""
    vendor: str = ""
    waf_type: str = ""
    confidence: float = 0.0
    plan_tier: str = ""

    # Detection evidence
    evidence: List[str] = field(default_factory=list)

    # Behavior
    rate_limit_threshold: int = 0
    rate_limit_window_seconds: int = 0
    bot_detection_enabled: bool = False
    challenge_type: str = ""
    block_response_code: int = 0

    # Bypass info
    known_bypasses: List[str] = field(default_factory=list)
    bypass_difficulty: str = ""


@dataclass
class FilterTestResult:
    """Result of filter testing for a single item"""

    test_input: str
    status: FilterStatus
    output: str = ""
    transformation: str = ""


@dataclass
class FilterProfile:
    """Complete filter analysis profile"""

    # Character filtering
    char_less_than: FilterStatus = FilterStatus.ALLOWED
    char_greater_than: FilterStatus = FilterStatus.ALLOWED
    char_double_quote: FilterStatus = FilterStatus.ALLOWED
    char_single_quote: FilterStatus = FilterStatus.ALLOWED
    char_backtick: FilterStatus = FilterStatus.ALLOWED
    char_slash: FilterStatus = FilterStatus.ALLOWED
    char_backslash: FilterStatus = FilterStatus.ALLOWED
    char_parenthesis_open: FilterStatus = FilterStatus.ALLOWED
    char_parenthesis_close: FilterStatus = FilterStatus.ALLOWED
    char_curly_open: FilterStatus = FilterStatus.ALLOWED
    char_curly_close: FilterStatus = FilterStatus.ALLOWED

    # Tag filtering
    tag_script: FilterStatus = FilterStatus.ALLOWED
    tag_img: FilterStatus = FilterStatus.ALLOWED
    tag_svg: FilterStatus = FilterStatus.ALLOWED
    tag_iframe: FilterStatus = FilterStatus.ALLOWED
    tag_object: FilterStatus = FilterStatus.ALLOWED
    tag_embed: FilterStatus = FilterStatus.ALLOWED
    tag_form: FilterStatus = FilterStatus.ALLOWED
    tag_input: FilterStatus = FilterStatus.ALLOWED
    tag_body: FilterStatus = FilterStatus.ALLOWED
    tag_style: FilterStatus = FilterStatus.ALLOWED
    tag_link: FilterStatus = FilterStatus.ALLOWED
    tag_meta: FilterStatus = FilterStatus.ALLOWED
    tag_base: FilterStatus = FilterStatus.ALLOWED
    tag_math: FilterStatus = FilterStatus.ALLOWED
    tag_video: FilterStatus = FilterStatus.ALLOWED
    tag_audio: FilterStatus = FilterStatus.ALLOWED
    tag_details: FilterStatus = FilterStatus.ALLOWED
    tag_marquee: FilterStatus = FilterStatus.ALLOWED

    # Event handler filtering
    event_onerror: FilterStatus = FilterStatus.ALLOWED
    event_onload: FilterStatus = FilterStatus.ALLOWED
    event_onclick: FilterStatus = FilterStatus.ALLOWED
    event_onmouseover: FilterStatus = FilterStatus.ALLOWED
    event_onfocus: FilterStatus = FilterStatus.ALLOWED
    event_onblur: FilterStatus = FilterStatus.ALLOWED
    event_oninput: FilterStatus = FilterStatus.ALLOWED
    event_onchange: FilterStatus = FilterStatus.ALLOWED
    event_onsubmit: FilterStatus = FilterStatus.ALLOWED
    event_onanimationend: FilterStatus = FilterStatus.ALLOWED
    event_ontoggle: FilterStatus = FilterStatus.ALLOWED
    event_onpointerover: FilterStatus = FilterStatus.ALLOWED

    # Keyword filtering
    keyword_alert: FilterStatus = FilterStatus.ALLOWED
    keyword_prompt: FilterStatus = FilterStatus.ALLOWED
    keyword_confirm: FilterStatus = FilterStatus.ALLOWED
    keyword_eval: FilterStatus = FilterStatus.ALLOWED
    keyword_document: FilterStatus = FilterStatus.ALLOWED
    keyword_window: FilterStatus = FilterStatus.ALLOWED
    keyword_location: FilterStatus = FilterStatus.ALLOWED
    keyword_cookie: FilterStatus = FilterStatus.ALLOWED
    keyword_innerhtml: FilterStatus = FilterStatus.ALLOWED
    keyword_script: FilterStatus = FilterStatus.ALLOWED
    keyword_javascript: FilterStatus = FilterStatus.ALLOWED
    keyword_expression: FilterStatus = FilterStatus.ALLOWED

    # Protocol filtering
    protocol_javascript: FilterStatus = FilterStatus.ALLOWED
    protocol_data: FilterStatus = FilterStatus.ALLOWED
    protocol_vbscript: FilterStatus = FilterStatus.ALLOWED

    # Encoding acceptance
    encoding_url_decoded: bool = True
    encoding_double_url_decoded: bool = False
    encoding_html_entities_decoded: bool = True
    encoding_hex_entities_decoded: bool = True
    encoding_unicode_decoded: bool = False
    encoding_null_bytes_stripped: bool = True
    encoding_case_sensitive: bool = True

    # Analysis summary
    filter_type: str = ""
    filter_strength: ProtectionStrength = ProtectionStrength.NONE
    is_bypassable: bool = True
    bypass_techniques: List[str] = field(default_factory=list)
    best_vector: str = ""
    best_encoding: str = ""


@dataclass
class ReflectionPoint:
    """Single reflection point in response"""

    context: str
    position: int
    line_number: int
    surrounding_code: str
    is_encoded: bool = False
    encoding_type: str = ""
    quote_char: str = ""
    tag_name: str = ""
    attribute_name: str = ""


@dataclass
class ParameterProfile:
    """Profile for a single parameter"""

    name: str
    reflected: bool = False
    reflection_points: List[ReflectionPoint] = field(default_factory=list)
    best_context: str = ""
    filter_applied: bool = False
    encoding_applied: str = ""


@dataclass
class FormInfo:
    """Form information"""

    action: str
    method: str
    fields: List[Dict[str, str]] = field(default_factory=list)
    has_csrf: bool = False
    csrf_field_name: str = ""
    enctype: str = ""


@dataclass
class EndpointInfo:
    """API/Page endpoint information"""

    url: str
    method: str
    endpoint_type: str = ""
    requires_auth: bool = False
    parameters: List[ParameterProfile] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)


@dataclass
class ApplicationStructure:
    """Application structure from crawling"""

    pages_discovered: int = 0
    forms_found: int = 0
    input_fields: int = 0
    javascript_files: int = 0

    entry_points: List[EndpointInfo] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    websocket_endpoints: List[str] = field(default_factory=list)
    graphql_endpoints: List[str] = field(default_factory=list)

    robots_txt: str = ""
    sitemap_urls: int = 0
    exposed_files: List[str] = field(default_factory=list)


@dataclass
class RiskAssessment:
    """Overall risk assessment"""

    overall_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.INFO

    # Attack surface
    reflected_inputs: int = 0
    forms_without_csrf: int = 0
    weak_csp: bool = False
    api_exposure: str = ""
    websocket_present: bool = False

    # Protection level
    waf_strength: ProtectionStrength = ProtectionStrength.NONE
    filter_strength: ProtectionStrength = ProtectionStrength.NONE
    header_strength: ProtectionStrength = ProtectionStrength.NONE

    # Bypass potential
    waf_bypass_chance: float = 0.0
    filter_bypass_chance: float = 0.0
    csp_bypass_chance: float = 0.0

    # Recommendations
    recommended_strategy: str = ""
    primary_vector: str = ""
    recommended_encoding: str = ""
    evasion_techniques: List[str] = field(default_factory=list)
    estimated_payloads: int = 0


@dataclass
class TargetProfile:
    """Complete target reconnaissance profile"""

    # Basic info
    url: str
    domain: str
    timestamp: str = ""
    scan_id: str = ""

    # Network layer
    dns: Optional[DnsInfo] = None
    ip: Optional[IpInfo] = None

    # SSL/TLS
    ssl: Optional[SslInfo] = None

    # Server
    server: Optional[ServerInfo] = None

    # Security
    security_headers: Optional[SecurityHeaders] = None
    waf: Optional[WafInfo] = None
    cookies: List[CookieInfo] = field(default_factory=list)

    # Technology
    technology: Optional[TechnologyInfo] = None

    # Filter analysis
    filter_profile: Optional[FilterProfile] = None

    # Application structure
    structure: Optional[ApplicationStructure] = None

    # Discovered endpoints (from crawling)
    discovered_endpoints: Optional[Dict[str, Any]] = None

    # Risk assessment
    risk: Optional[RiskAssessment] = None

    # Reconnaissance metadata
    recon_duration_seconds: float = 0.0
    recon_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        from dataclasses import asdict

        def enum_to_value(obj):
            """Convert nested objects, handling Enums"""
            if isinstance(obj, Enum):
                return obj.value
            elif isinstance(obj, dict):
                return {k: enum_to_value(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [enum_to_value(item) for item in obj]
            elif hasattr(obj, "__dataclass_fields__"):
                return {k: enum_to_value(v) for k, v in asdict(obj).items()}
            return obj

        result = asdict(self)
        return enum_to_value(result)
