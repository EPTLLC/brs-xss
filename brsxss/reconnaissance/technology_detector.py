#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 14:37:26 MSK
Status: Created
Telegram: https://t.me/EasyProTech

Technology stack detector.
Detects backend languages, frameworks, CMS, frontend libraries, and infrastructure.
"""

import re
from typing import Any
from .recon_types import TechnologyInfo, ServerInfo, CookieInfo
from ..utils.logger import Logger

logger = Logger("recon.technology_detector")


# Technology signatures
BACKEND_SIGNATURES = {
    # PHP
    "php": {
        "headers": ["x-powered-by: php", "server:.*php"],
        "cookies": ["phpsessid", "php_sessid"],
        "content": [r'\.php(?:\?|"|\'|$)', r"<\?php"],
        "extensions": [".php", ".php3", ".php4", ".php5", ".phtml"],
    },
    # Python
    "python": {
        "headers": [
            "x-powered-by:.*python",
            "x-powered-by:.*gunicorn",
            "x-powered-by:.*uvicorn",
            "x-powered-by:.*uwsgi",
        ],
        "cookies": ["csrftoken", "sessionid"],  # Django defaults
        "content": [r'\.py(?:\?|"|\'|$)'],
    },
    # Node.js
    "nodejs": {
        "headers": ["x-powered-by: express", "x-powered-by:.*node"],
        "cookies": ["connect.sid", "express:sess"],
        "content": [],
    },
    # Ruby
    "ruby": {
        "headers": [
            "x-powered-by:.*passenger",
            "x-powered-by:.*puma",
            "x-powered-by:.*unicorn",
            "x-rack-cache",
        ],
        "cookies": ["_session_id", "_rails_session"],
        "content": [r'\.rb(?:\?|"|\'|$)'],
    },
    # Java
    "java": {
        "headers": [
            "x-powered-by:.*servlet",
            "x-powered-by:.*jsp",
            "x-powered-by:.*tomcat",
            "x-powered-by:.*jetty",
        ],
        "cookies": ["jsessionid", "jsession"],
        "content": [r'\.jsp(?:\?|"|\'|$)', r'\.do(?:\?|"|\'|$)'],
    },
    # .NET
    "dotnet": {
        "headers": ["x-powered-by: asp.net", "x-aspnet-version", "x-aspnetmvc-version"],
        "cookies": ["asp.net_sessionid", ".aspxauth", "__requestverificationtoken"],
        "content": [r'\.aspx(?:\?|"|\'|$)', r'\.ashx(?:\?|"|\'|$)'],
    },
    # Go
    "go": {
        "headers": [],
        "cookies": [],
        "content": [],
        # Go is hard to detect without specific patterns
    },
}

FRAMEWORK_SIGNATURES = {
    # PHP Frameworks
    "laravel": {
        "cookies": ["laravel_session", "xsrf-token"],
        "content": [r'<meta name="csrf-token"', r"_token"],
        "headers": [],
    },
    "symfony": {
        "cookies": ["symfony"],
        "content": [r"sf-toolbar", r"_sf2_"],
        "headers": ["x-debug-token"],
    },
    "codeigniter": {
        "cookies": ["ci_session", "csrf_cookie_name"],
        "content": [],
        "headers": [],
    },
    # Python Frameworks
    "django": {
        "cookies": ["csrftoken", "sessionid", "django_language"],
        "content": [r"csrfmiddlewaretoken", r"django\.contrib"],
        "headers": [],
    },
    "flask": {
        "cookies": ["session"],
        "content": [r"flask", r"werkzeug"],
        "headers": ["server:.*werkzeug"],
    },
    "fastapi": {
        "headers": [],
        "cookies": [],
        "content": [r"/openapi\.json", r"/docs", r"/redoc"],
    },
    # Node.js Frameworks
    "express": {
        "headers": ["x-powered-by: express"],
        "cookies": ["connect.sid"],
        "content": [],
    },
    "nextjs": {
        "content": [r"__NEXT_DATA__", r"/_next/", r"next/dist"],
        "cookies": ["__next"],
        "headers": ["x-nextjs-cache", "x-nextjs-matched-path"],
    },
    "nuxtjs": {
        "content": [r"__NUXT__", r"/_nuxt/", r"nuxt"],
        "cookies": [],
        "headers": [],
    },
    # Ruby Frameworks
    "rails": {
        "cookies": ["_session_id", "_rails_session"],
        "content": [r"rails", r"authenticity_token"],
        "headers": ["x-request-id", "x-runtime"],
    },
    # Java Frameworks
    "spring": {
        "cookies": ["jsessionid"],
        "content": [r"springframework", r"_csrf"],
        "headers": [],
    },
    # .NET Frameworks
    "aspnet_mvc": {
        "headers": ["x-aspnetmvc-version"],
        "cookies": ["__requestverificationtoken"],
        "content": [r"__doPostBack", r"aspnetForm"],
    },
    "blazor": {
        "content": [r"_blazor", r"blazor\.webassembly"],
        "cookies": [],
        "headers": [],
    },
}

CMS_SIGNATURES = {
    "wordpress": {
        "content": [
            r"/wp-content/",
            r"/wp-includes/",
            r"wp-json",
            r'<meta name="generator" content="WordPress',
        ],
        "cookies": ["wordpress_", "wp-settings"],
        "paths": ["/wp-login.php", "/wp-admin/", "/xmlrpc.php"],
    },
    "drupal": {
        "content": [
            r"Drupal\.settings",
            r"/sites/default/files/",
            r'<meta name="Generator" content="Drupal',
        ],
        "cookies": ["drupal", "has_js"],
        "headers": ["x-drupal-cache", "x-generator: drupal"],
    },
    "joomla": {
        "content": [
            r"/components/com_",
            r"/media/jui/",
            r'<meta name="generator" content="Joomla',
        ],
        "cookies": [],
        "paths": ["/administrator/"],
    },
    "magento": {
        "content": [r"Mage\.", r"/skin/frontend/", r"varien"],
        "cookies": ["frontend", "adminhtml"],
        "paths": ["/admin/", "/downloader/"],
    },
    "shopify": {
        "content": [r"cdn\.shopify\.com", r"shopify\.com", r"Shopify\."],
        "cookies": ["_shopify", "cart_currency"],
        "headers": ["x-shopify-stage"],
    },
    "wix": {
        "content": [r"wix\.com", r"static\.wixstatic\.com", r"_wix"],
        "cookies": [],
        "headers": [],
    },
    "squarespace": {
        "content": [r"squarespace\.com", r"static\.squarespace"],
        "cookies": ["crumb"],
        "headers": [],
    },
}

FRONTEND_SIGNATURES = {
    "react": {
        "content": [
            r"react",
            r"data-reactroot",
            r"data-reactid",
            r"_reactRootContainer",
            r"__REACT_DEVTOOLS",
        ],
        "scripts": ["react.js", "react.min.js", "react.production.min.js"],
    },
    "vue": {
        "content": [r"vue", r"data-v-", r"__VUE__", r"v-cloak"],
        "scripts": ["vue.js", "vue.min.js", "vue.global.js"],
    },
    "angular": {
        "content": [
            r"ng-version",
            r"ng-app",
            r"angular",
            r"\[ngClass\]",
            r"ng-controller",
            r"ng-model",
        ],
        "scripts": ["angular.js", "angular.min.js"],
    },
    "svelte": {
        "content": [r"svelte", r"__svelte"],
        "scripts": [],
    },
    "jquery": {
        "content": [r"jquery", r"\$\(document\)", r"\$\(function"],
        "scripts": ["jquery.js", "jquery.min.js", "jquery-"],
    },
    "bootstrap": {
        "content": [r"bootstrap", r'class=".*\b(btn|navbar|container|row|col-)'],
        "scripts": ["bootstrap.js", "bootstrap.min.js", "bootstrap.bundle"],
    },
    "tailwindcss": {
        "content": [r'class=".*\b(flex|grid|p-\d|m-\d|text-|bg-|rounded)'],
        "scripts": [],
    },
}

ANALYTICS_SIGNATURES = {
    "google_analytics": {
        "content": [
            r"google-analytics\.com",
            r"gtag\(",
            r"ga\(\'send",
            r"UA-\d+-\d+",
            r"G-[A-Z0-9]+",
        ],
    },
    "google_tag_manager": {
        "content": [r"googletagmanager\.com", r"GTM-[A-Z0-9]+"],
    },
    "facebook_pixel": {
        "content": [r"connect\.facebook\.net", r"fbq\(", r"facebook-pixel"],
    },
    "hotjar": {
        "content": [r"hotjar\.com", r"hj\(", r"_hjSettings"],
    },
    "mixpanel": {
        "content": [r"mixpanel\.com", r"mixpanel\.track"],
    },
    "segment": {
        "content": [r"segment\.com", r"analytics\.track"],
    },
    "heap": {
        "content": [r"heap\.io", r"heap\.track"],
    },
}

SERVER_SIGNATURES = {
    "nginx": {"server": [r"nginx/?(\d+\.[\d.]+)?"]},
    "apache": {"server": [r"apache/?(\d+\.[\d.]+)?", r"httpd"]},
    "iis": {"server": [r"microsoft-iis/?(\d+\.[\d.]+)?"]},
    "cloudflare": {"server": [r"cloudflare"]},
    "litespeed": {"server": [r"litespeed"]},
    "caddy": {"server": [r"caddy"]},
    "tomcat": {"server": [r"apache-coyote", r"tomcat"]},
    "gunicorn": {"via": [r"gunicorn"], "server": [r"gunicorn"]},
    "uvicorn": {"server": [r"uvicorn"]},
}


class TechnologyDetector:
    """
    Detects technology stack from HTTP response.
    """

    def __init__(self):
        pass

    def detect(
        self, headers: dict[str, str], content: str, cookies: list[CookieInfo]
    ) -> TechnologyInfo:
        """
        Detect technology stack from response.

        Args:
            headers: Response headers
            content: Response body content
            cookies: Parsed cookies

        Returns:
            TechnologyInfo with detected technologies
        """
        tech = TechnologyInfo()

        # Normalize headers for case-insensitive matching
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        headers_str = " ".join(f"{k}: {v}" for k, v in headers_lower.items())

        # Get cookie names
        cookie_names = [c.name.lower() for c in cookies]
        cookies_str = " ".join(cookie_names)

        # Limit content for performance
        content_preview = content[:50000] if content else ""
        content_lower = content_preview.lower()

        logger.debug("Starting technology detection")

        # Detect backend language
        tech.backend_language, tech.backend_version = self._detect_backend(
            headers_str, cookies_str, content_lower
        )

        # Detect framework
        tech.backend_framework, tech.framework_version = self._detect_framework(
            headers_str, cookies_str, content_lower, tech.backend_language
        )

        # Detect CMS
        tech.cms, tech.cms_version = self._detect_cms(
            headers_str, cookies_str, content_lower
        )

        # Detect frontend framework
        tech.frontend_framework, tech.frontend_version = self._detect_frontend(
            content_preview
        )

        # Detect JavaScript libraries
        tech.javascript_libraries = self._detect_js_libraries(content_preview)

        # Detect analytics
        tech.analytics, tech.tracking_ids = self._detect_analytics(content_preview)

        # Detect infrastructure
        tech.cdn = self._detect_cdn(headers_lower)
        tech.reverse_proxy = self._detect_proxy(headers_lower)

        # Meta info
        tech.meta_generator = self._extract_meta_generator(content_preview)
        tech.meta_language = self._extract_meta_language(content_preview)

        # Calculate confidence
        tech.detection_confidence = self._calculate_confidence(tech)

        logger.info(
            f"Technology detection complete: {tech.backend_framework or tech.backend_language or 'unknown'}"
        )

        return tech

    def detect_server(self, headers: dict[str, str]) -> ServerInfo:
        """Detect server information from headers"""
        server_info = ServerInfo()
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Server header
        server_header = headers_lower.get("server", "")
        if server_header:
            for server_name, patterns in SERVER_SIGNATURES.items():
                for pattern in patterns.get("server", []):
                    match = re.search(pattern, server_header, re.IGNORECASE)
                    if match:
                        server_info.server_name = server_name.title()
                        if match.groups():
                            server_info.server_version = match.group(1) or ""
                        break

        # X-Powered-By
        powered_by = headers_lower.get("x-powered-by", "")
        if powered_by:
            server_info.powered_by = powered_by

        # Via header (proxy)
        via = headers_lower.get("via", "")
        if via:
            server_info.proxy_server = via

        # Compression
        encoding = headers_lower.get("content-encoding", "")
        server_info.compression_gzip = "gzip" in encoding
        server_info.compression_brotli = "br" in encoding
        server_info.compression_deflate = "deflate" in encoding

        return server_info

    def _detect_backend(self, headers: str, cookies: str, content: str) -> tuple:
        """Detect backend language"""
        for lang, sigs in BACKEND_SIGNATURES.items():
            confidence = 0
            version = ""
            sigs_dict: dict[str, Any] = sigs if isinstance(sigs, dict) else {}

            # Check headers
            for pattern in sigs_dict.get("headers", []):
                if re.search(pattern, headers, re.IGNORECASE):
                    confidence += 3
                    # Try to extract version
                    version_match = re.search(
                        rf"{lang}[/\s]*([\d.]+)", headers, re.IGNORECASE
                    )
                    if version_match:
                        version = version_match.group(1)

            # Check cookies
            for cookie_pattern in sigs_dict.get("cookies", []):
                if cookie_pattern.lower() in cookies:
                    confidence += 2

            # Check content
            for pattern in sigs_dict.get("content", []):
                if re.search(pattern, content, re.IGNORECASE):
                    confidence += 1

            if confidence >= 2:
                return lang.upper(), version

        return "", ""

    def _detect_framework(
        self, headers: str, cookies: str, content: str, backend_lang: str
    ) -> tuple:
        """Detect web framework"""
        best_match = ("", "", 0)

        for framework, sigs in FRAMEWORK_SIGNATURES.items():
            confidence = 0
            version = ""

            # Check headers
            for pattern in sigs.get("headers", []):
                if re.search(pattern, headers, re.IGNORECASE):
                    confidence += 3
                    # Try to extract version
                    version_match = re.search(
                        rf"{framework}[/\s:-]*([\d.]+)", headers, re.IGNORECASE
                    )
                    if version_match:
                        version = version_match.group(1)

            # Check cookies
            for cookie_pattern in sigs.get("cookies", []):
                if cookie_pattern.lower() in cookies:
                    confidence += 2

            # Check content
            for pattern in sigs.get("content", []):
                if re.search(pattern, content, re.IGNORECASE):
                    confidence += 1

            if confidence > best_match[2]:
                best_match = (framework.title().replace("_", " "), version, confidence)

        if best_match[2] >= 2:
            return best_match[0], best_match[1]

        return "", ""

    def _detect_cms(self, headers: str, cookies: str, content: str) -> tuple:
        """Detect CMS"""
        for cms, sigs in CMS_SIGNATURES.items():
            confidence = 0
            version = ""

            # Check headers
            for pattern in sigs.get("headers", []):
                if re.search(pattern, headers, re.IGNORECASE):
                    confidence += 3

            # Check cookies
            for cookie_pattern in sigs.get("cookies", []):
                if cookie_pattern.lower() in cookies:
                    confidence += 2

            # Check content
            for pattern in sigs.get("content", []):
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    confidence += 2
                    # Try to extract version from generator meta
                    version_match = re.search(
                        rf"{cms}[\s/]*([\d.]+)", content, re.IGNORECASE
                    )
                    if version_match:
                        version = version_match.group(1)

            if confidence >= 2:
                return cms.title(), version

        return "", ""

    def _detect_frontend(self, content: str) -> tuple:
        """Detect frontend framework"""
        content_lower = content.lower()

        for framework, sigs in FRONTEND_SIGNATURES.items():
            confidence = 0
            version = ""

            # Check content patterns
            for pattern in sigs.get("content", []):
                if re.search(pattern, content_lower, re.IGNORECASE):
                    confidence += 1

            # Check script references
            for script in sigs.get("scripts", []):
                if script.lower() in content_lower:
                    confidence += 2
                    # Try to extract version
                    version_match = re.search(
                        rf"{framework}[.@/-]*([\d.]+)", content_lower, re.IGNORECASE
                    )
                    if version_match:
                        version = version_match.group(1)

            if confidence >= 2:
                return framework.title(), version

        return "", ""

    def _detect_js_libraries(self, content: str) -> list[dict[str, str]]:
        """Detect JavaScript libraries"""
        libraries = []
        content_lower = content.lower()

        # Common libraries and their patterns
        js_libs = {
            "jQuery": [r"jquery[.-]?([\d.]+)?\.(?:min\.)?js", r"\$\.fn\.jquery"],
            "Lodash": [r"lodash[.-]?([\d.]+)?\.(?:min\.)?js"],
            "Moment.js": [r"moment[.-]?([\d.]+)?\.(?:min\.)?js"],
            "Axios": [r"axios[.-]?([\d.]+)?\.(?:min\.)?js"],
            "D3.js": [r"d3[.-]?([\d.]+)?\.(?:min\.)?js"],
            "Chart.js": [r"chart[.-]?([\d.]+)?\.(?:min\.)?js"],
            "Three.js": [r"three[.-]?([\d.]+)?\.(?:min\.)?js"],
            "GSAP": [r"gsap[.-]?([\d.]+)?\.(?:min\.)?js"],
            "Swiper": [r"swiper[.-]?([\d.]+)?\.(?:min\.)?js"],
            "AOS": [r"aos[.-]?([\d.]+)?\.(?:min\.)?js"],
        }

        for lib_name, patterns in js_libs.items():
            for pattern in patterns:
                match = re.search(pattern, content_lower, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else ""
                    libraries.append(
                        {"name": lib_name, "version": version or "unknown"}
                    )
                    break

        return libraries

    def _detect_analytics(self, content: str) -> tuple:
        """Detect analytics tools"""
        analytics = []
        tracking_ids = {}

        for tool, sigs in ANALYTICS_SIGNATURES.items():
            for pattern in sigs.get("content", []):
                if re.search(pattern, content, re.IGNORECASE):
                    tool_name = tool.replace("_", " ").title()
                    if tool_name not in analytics:
                        analytics.append(tool_name)

                    # Extract tracking IDs
                    if "UA-" in pattern or "G-" in pattern:
                        id_match = re.search(r"(UA-\d+-\d+|G-[A-Z0-9]+)", content)
                        if id_match:
                            tracking_ids["google_analytics"] = id_match.group(1)
                    if "GTM-" in pattern:
                        id_match = re.search(r"GTM-[A-Z0-9]+", content)
                        if id_match:
                            tracking_ids["gtm"] = id_match.group(0)
                    break

        return analytics, tracking_ids

    def _detect_cdn(self, headers: dict[str, str]) -> str:
        """Detect CDN from headers"""
        cdn_indicators = {
            "cloudflare": ["cf-ray", "cf-cache-status"],
            "fastly": ["x-served-by", "x-cache", "fastly"],
            "akamai": ["x-akamai", "akamai"],
            "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
            "stackpath": ["x-hw"],
            "sucuri": ["x-sucuri-id"],
            "incapsula": ["x-iinfo", "incap_ses"],
            "varnish": ["x-varnish"],
        }

        for cdn, indicators in cdn_indicators.items():
            for indicator in indicators:
                if indicator in headers:
                    return cdn.title()
                for header_value in headers.values():
                    if indicator in header_value.lower():
                        return cdn.title()

        return ""

    def _detect_proxy(self, headers: dict[str, str]) -> str:
        """Detect reverse proxy"""
        if "via" in headers:
            return headers["via"]
        if "x-forwarded-for" in headers:
            return "Reverse Proxy (X-Forwarded-For present)"
        return ""

    def _extract_meta_generator(self, content: str) -> str:
        """Extract meta generator tag"""
        match = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
            content,
            re.IGNORECASE,
        )
        if match:
            return match.group(1)
        return ""

    def _extract_meta_language(self, content: str) -> str:
        """Extract language from HTML"""
        # Check html lang attribute
        match = re.search(r'<html[^>]+lang=["\']([^"\']+)["\']', content, re.IGNORECASE)
        if match:
            return match.group(1)

        # Check meta content-language
        match = re.search(
            r'<meta[^>]+http-equiv=["\']content-language["\'][^>]+content=["\']([^"\']+)["\']',
            content,
            re.IGNORECASE,
        )
        if match:
            return match.group(1)

        return ""

    def _calculate_confidence(self, tech: TechnologyInfo) -> float:
        """Calculate overall detection confidence"""
        confidence = 0.0
        factors = 0

        if tech.backend_language:
            confidence += 0.8
            factors += 1
        if tech.backend_framework:
            confidence += 0.9
            factors += 1
        if tech.cms:
            confidence += 0.9
            factors += 1
        if tech.frontend_framework:
            confidence += 0.7
            factors += 1
        if tech.cdn:
            confidence += 0.9
            factors += 1

        if factors == 0:
            return 0.1

        return confidence / factors
