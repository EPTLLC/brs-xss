#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 14:37:26 MSK
Status: Created
Telegram: https://t.me/EasyProTech

Security headers analyzer.
Analyzes CSP, HSTS, CORS, and other security-related headers.
"""

import re
from typing import Optional
from .recon_types import SecurityHeaders, CookieInfo
from ..utils.logger import Logger

logger = Logger("recon.headers_analyzer")


class HeadersAnalyzer:
    """
    Analyzes HTTP security headers.
    """

    # Required security headers
    REQUIRED_HEADERS = [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "strict-transport-security",
        "referrer-policy",
        "permissions-policy",
    ]

    # Recommended headers
    RECOMMENDED_HEADERS = [
        "x-permitted-cross-domain-policies",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
    ]

    def __init__(self):
        pass

    def analyze(self, headers: dict[str, str]) -> SecurityHeaders:
        """
        Analyze security headers.

        Args:
            headers: Response headers

        Returns:
            SecurityHeaders analysis
        """
        sec = SecurityHeaders()
        headers_lower = {k.lower(): v for k, v in headers.items()}

        logger.debug("Analyzing security headers")

        # CSP Analysis
        self._analyze_csp(headers_lower, sec)

        # X-Frame-Options
        sec.x_frame_options = headers_lower.get("x-frame-options", "")

        # X-Content-Type-Options
        sec.x_content_type_options = headers_lower.get("x-content-type-options", "")

        # X-XSS-Protection
        sec.x_xss_protection = headers_lower.get("x-xss-protection", "")

        # Referrer-Policy
        sec.referrer_policy = headers_lower.get("referrer-policy", "")

        # Permissions-Policy (formerly Feature-Policy)
        sec.permissions_policy = headers_lower.get(
            "permissions-policy", ""
        ) or headers_lower.get("feature-policy", "")

        # HSTS Analysis
        self._analyze_hsts(headers_lower, sec)

        # CORS Analysis
        self._analyze_cors(headers_lower, sec)

        # Find missing headers
        self._find_missing_headers(headers_lower, sec)

        # Calculate score and grade
        sec.score, sec.grade = self._calculate_score(sec)

        logger.info(f"Security headers analysis complete: Grade {sec.grade}")

        return sec

    def analyze_cookies(self, set_cookie_headers: list[str]) -> list[CookieInfo]:
        """
        Analyze set-Cookie headers.

        Args:
            set_cookie_headers: list of set-Cookie header values

        Returns:
            list of analyzed cookies
        """
        cookies = []

        for cookie_str in set_cookie_headers:
            cookie = self._parse_cookie(cookie_str)
            if cookie:
                cookies.append(cookie)

        return cookies

    def _analyze_csp(self, headers: dict[str, str], sec: SecurityHeaders):
        """Analyze Content-Security-Policy"""
        csp = headers.get("content-security-policy", "")
        csp_ro = headers.get("content-security-policy-report-only", "")

        # Use enforcing CSP if available, otherwise report-only
        csp_value = csp or csp_ro

        if not csp_value:
            sec.csp_present = False
            sec.csp_analysis = (
                "No CSP header found - XSS protection relies on output encoding only"
            )
            return

        sec.csp_present = True
        sec.csp_policy = csp_value

        # Parse directives
        directives = {}
        for part in csp_value.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directive_name = tokens[0].lower()
                directive_value = " ".join(tokens[1:]) if len(tokens) > 1 else ""
                directives[directive_name] = directive_value

        sec.csp_directives = directives

        # Check for unsafe patterns
        sec.csp_has_unsafe_inline = "'unsafe-inline'" in csp_value.lower()
        sec.csp_has_unsafe_eval = "'unsafe-eval'" in csp_value.lower()

        # Generate analysis
        issues = []
        strengths = []

        if sec.csp_has_unsafe_inline:
            issues.append(
                "'unsafe-inline' allows inline scripts - weakens XSS protection"
            )
        if sec.csp_has_unsafe_eval:
            issues.append("'unsafe-eval' allows eval() - potential XSS vector")

        # Check script-src
        script_src = directives.get("script-src", directives.get("default-src", ""))
        if "'none'" in script_src:
            strengths.append("script-src 'none' blocks all scripts")
        elif "'self'" in script_src and "'unsafe-inline'" not in script_src:
            strengths.append("script-src restricts to 'self' without unsafe-inline")
        elif "*" in script_src:
            issues.append("script-src allows wildcard (*) - very weak protection")

        # Check object-src
        if "object-src" not in directives and "'none'" not in directives.get(
            "default-src", ""
        ):
            issues.append("object-src not set - plugins could be loaded")
        elif "'none'" in directives.get("object-src", ""):
            strengths.append("object-src 'none' blocks plugins")

        # Check base-uri
        if "base-uri" not in directives:
            issues.append("base-uri not set - base tag injection possible")
        elif "'none'" in directives.get("base-uri", "") or "'self'" in directives.get(
            "base-uri", ""
        ):
            strengths.append("base-uri restricted")

        # Check frame-ancestors
        if "frame-ancestors" in directives:
            if "'none'" in directives["frame-ancestors"]:
                strengths.append("frame-ancestors 'none' prevents clickjacking")
            elif "'self'" in directives["frame-ancestors"]:
                strengths.append("frame-ancestors 'self' restricts framing")

        # Generate summary
        if not issues and strengths:
            sec.csp_analysis = f"Strong CSP: {'; '.join(strengths[:2])}"
        elif issues and not strengths:
            sec.csp_analysis = f"Weak CSP: {issues[0]}"
        elif issues:
            sec.csp_analysis = f"Moderate CSP: {issues[0]}"
        else:
            sec.csp_analysis = "CSP present but effectiveness unclear"

    def _analyze_hsts(self, headers: dict[str, str], sec: SecurityHeaders):
        """Analyze Strict-Transport-Security"""
        hsts = headers.get("strict-transport-security", "")

        if not hsts:
            sec.hsts_enabled = False
            return

        sec.hsts_enabled = True

        # Parse max-age
        max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if max_age_match:
            sec.hsts_max_age = int(max_age_match.group(1))

        # Check includeSubDomains
        sec.hsts_include_subdomains = "includesubdomains" in hsts.lower()

        # Check preload
        sec.hsts_preload = "preload" in hsts.lower()

    def _analyze_cors(self, headers: dict[str, str], sec: SecurityHeaders):
        """Analyze CORS headers"""
        acao = headers.get("access-control-allow-origin", "")

        if not acao:
            sec.cors_enabled = False
            return

        sec.cors_enabled = True
        sec.cors_allow_origin = acao

        # Check if permissive
        sec.cors_is_permissive = acao == "*"

        # Methods
        methods = headers.get("access-control-allow-methods", "")
        if methods:
            sec.cors_allow_methods = [m.strip() for m in methods.split(",")]

        # Credentials
        creds = headers.get("access-control-allow-credentials", "")
        sec.cors_allow_credentials = creds.lower() == "true"

        # Dangerous: credentials with wildcard or null origin
        if sec.cors_allow_credentials and (acao == "*" or acao == "null"):
            sec.cors_is_permissive = True

    def _find_missing_headers(self, headers: dict[str, str], sec: SecurityHeaders):
        """Find missing security headers"""
        missing = []

        for header in self.REQUIRED_HEADERS:
            if header not in headers:
                missing.append(header)

        for header in self.RECOMMENDED_HEADERS:
            if header not in headers:
                missing.append(f"{header} (recommended)")

        sec.missing_headers = missing

    def _calculate_score(self, sec: SecurityHeaders) -> tuple:
        """Calculate security score and grade"""
        score = 0

        # CSP (30 points)
        if sec.csp_present:
            score += 15
            if not sec.csp_has_unsafe_inline:
                score += 10
            if not sec.csp_has_unsafe_eval:
                score += 5

        # HSTS (20 points)
        if sec.hsts_enabled:
            score += 10
            if sec.hsts_max_age >= 31536000:  # 1 year
                score += 5
            if sec.hsts_include_subdomains:
                score += 3
            if sec.hsts_preload:
                score += 2

        # X-Frame-Options (10 points)
        if sec.x_frame_options:
            xfo_lower = sec.x_frame_options.lower()
            if xfo_lower in ["deny", "sameorigin"]:
                score += 10
            else:
                score += 5

        # X-Content-Type-Options (10 points)
        if sec.x_content_type_options.lower() == "nosniff":
            score += 10

        # Referrer-Policy (10 points)
        if sec.referrer_policy:
            rp = sec.referrer_policy.lower()
            if rp in [
                "no-referrer",
                "strict-origin",
                "strict-origin-when-cross-origin",
            ]:
                score += 10
            elif rp in ["same-origin", "origin"]:
                score += 7
            else:
                score += 3

        # Permissions-Policy (10 points)
        if sec.permissions_policy:
            score += 10

        # CORS (10 points) - deduct for insecure config
        if sec.cors_enabled:
            if not sec.cors_is_permissive:
                score += 10
            elif sec.cors_allow_credentials:
                score -= 10  # Very dangerous
        else:
            score += 10  # No CORS is often fine

        # Determine grade
        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 50:
            grade = "D"
        else:
            grade = "F"

        return score, grade

    def _parse_cookie(self, cookie_str: str) -> Optional[CookieInfo]:
        """Parse set-Cookie header value"""
        if not cookie_str:
            return None

        parts = cookie_str.split(";")
        if not parts:
            return None

        # First part is name=value
        name_value = parts[0].strip()
        if "=" not in name_value:
            return None

        name, value = name_value.split("=", 1)
        name = name.strip()
        value = value.strip()

        cookie = CookieInfo(
            name=name, value_preview=value[:20] + "..." if len(value) > 20 else value
        )

        # Parse attributes
        for part in parts[1:]:
            part = part.strip().lower()

            if part == "secure":
                cookie.secure = True
            elif part == "httponly":
                cookie.http_only = True
            elif part.startswith("samesite="):
                cookie.same_site = part.split("=", 1)[1]
            elif part.startswith("domain="):
                cookie.domain = part.split("=", 1)[1]
            elif part.startswith("path="):
                cookie.path = part.split("=", 1)[1]
            elif part.startswith("expires="):
                cookie.expires = part.split("=", 1)[1]

        # Determine purpose based on common patterns
        cookie.purpose = self._identify_cookie_purpose(name)

        return cookie

    def _identify_cookie_purpose(self, name: str) -> str:
        """Identify cookie purpose from name"""
        name_lower = name.lower()

        # Session cookies
        if any(
            p in name_lower
            for p in ["session", "sess", "sid", "phpsessid", "jsessionid"]
        ):
            return "Session"

        # CSRF tokens
        if any(p in name_lower for p in ["csrf", "xsrf", "_token", "authenticity"]):
            return "CSRF Protection"

        # Authentication
        if any(p in name_lower for p in ["auth", "login", "jwt", "access_token"]):
            return "Authentication"

        # Analytics
        if any(p in name_lower for p in ["_ga", "_gid", "_fbp", "analytics"]):
            return "Analytics"

        # Cloudflare
        if name_lower.startswith("__cf") or name_lower.startswith("cf_"):
            return "Cloudflare (Security)"

        # Preferences
        if any(p in name_lower for p in ["lang", "locale", "theme", "pref"]):
            return "Preferences"

        return "Unknown"
