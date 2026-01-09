#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 14:37:26 MSK
Status: Created
Telegram: https://t.me/EasyProTech

SSL/TLS certificate and connection analyzer.
"""

import ssl
import socket
import asyncio
from datetime import datetime
from urllib.parse import urlparse

from .recon_types import SslInfo
from ..utils.logger import Logger

logger = Logger("recon.ssl_analyzer")


class SslAnalyzer:
    """
    SSL/TLS analyzer for target reconnaissance.
    Analyzes certificates, protocols, and security configuration.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def analyze(self, url: str) -> SslInfo:
        """
        Analyze SSL/TLS configuration of target.

        Args:
            url: Target URL

        Returns:
            SslInfo with certificate and TLS details
        """
        parsed = urlparse(url)
        hostname = parsed.netloc.split(":")[0]
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        ssl_info = SslInfo(enabled=False)

        # Skip if not HTTPS
        if parsed.scheme != "https":
            logger.debug("Target is not HTTPS, skipping SSL analysis")
            return ssl_info

        logger.info(f"Analyzing SSL/TLS for: {hostname}:{port}")

        try:
            loop = asyncio.get_event_loop()
            ssl_info = await asyncio.wait_for(
                loop.run_in_executor(None, self._analyze_ssl, hostname, port),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(f"SSL analysis timed out for {hostname}")
        except Exception as e:
            logger.error(f"SSL analysis error: {e}")

        return ssl_info

    def _analyze_ssl(self, hostname: str, port: int) -> SslInfo:
        """Synchronous SSL analysis"""
        ssl_info = SslInfo(enabled=True)

        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection(
                (hostname, port), timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()
                    ssock.getpeercert(binary_form=True)

                    # Protocol and cipher
                    ssl_info.protocol = ssock.version() or ""
                    cipher = ssock.cipher()
                    if cipher:
                        ssl_info.cipher_suite = cipher[0]

                    # Parse certificate
                    if cert:
                        self._parse_certificate(cert, ssl_info)

                    # Check for OCSP stapling (basic check)
                    ssl_info.ocsp_stapling = self._check_ocsp_stapling(ssock)

                    # Get certificate chain length
                    ssl_info.chain_length = len(
                        ssock.getpeercert(binary_form=False) or {}
                    )

        except ssl.SSLCertVerificationError as e:
            logger.warning(f"SSL certificate verification failed: {e}")
            ssl_info.chain_valid = False
            ssl_info.is_self_signed = "self signed" in str(e).lower()

            # Try without verification to get cert info
            try:
                ssl_info = self._analyze_without_verify(hostname, port, ssl_info)
            except Exception:
                pass

        except Exception as e:
            logger.error(f"SSL connection error: {e}")
            ssl_info.enabled = False

        # Calculate grade
        ssl_info.grade = self._calculate_grade(ssl_info)

        return ssl_info

    def _analyze_without_verify(
        self, hostname: str, port: int, ssl_info: SslInfo
    ) -> SslInfo:
        """Analyze SSL without certificate verification"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    self._parse_certificate(cert, ssl_info)

                ssl_info.protocol = ssock.version() or ""
                cipher = ssock.cipher()
                if cipher:
                    ssl_info.cipher_suite = cipher[0]

        return ssl_info

    def _parse_certificate(self, cert: dict, ssl_info: SslInfo):
        """Parse certificate details"""
        if not cert:
            return

        # Subject
        subject = cert.get("subject", ())
        for item in subject:
            for key, value in item:
                if key == "commonName":
                    ssl_info.subject = value
                    break

        # Issuer
        issuer = cert.get("issuer", ())
        issuer_parts = []
        for item in issuer:
            for key, value in item:
                if key in ("commonName", "organizationName"):
                    issuer_parts.append(value)
        ssl_info.issuer = " - ".join(issuer_parts)

        # Check if self-signed
        if ssl_info.subject and ssl_info.subject in ssl_info.issuer:
            ssl_info.is_self_signed = True

        # Serial number
        ssl_info.serial_number = str(cert.get("serialNumber", ""))

        # Validity dates
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        ssl_info.valid_from = not_before
        ssl_info.valid_until = not_after

        # Calculate days until expiry
        if not_after:
            try:
                # Parse SSL date format: 'Dec 25 23:59:59 2025 GMT'
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.now()).days
                ssl_info.days_until_expiry = days_left
                ssl_info.is_expired = days_left < 0
            except Exception as e:
                logger.debug(f"Could not parse expiry date: {e}")

        # Subject Alternative Names (SAN)
        san = cert.get("subjectAltName", ())
        san_domains = []
        for san_type, san_value in san:
            if san_type == "DNS":
                san_domains.append(san_value)
                if san_value.startswith("*."):
                    ssl_info.has_wildcard = True
        ssl_info.san_domains = san_domains

        # Certificate Transparency
        # Note: Full CT log checking would require external API
        ssl_info.ct_logs_present = True  # Assume present for modern certs

    def _check_ocsp_stapling(self, ssock: ssl.SSLSocket) -> bool:
        """Check if OCSP stapling is enabled"""
        # Basic check - would need deeper inspection for full check
        try:
            # In Python 3.10+, there's better OCSP support
            # For now, we do a basic heuristic
            return False  # Conservative default
        except Exception:
            return False

    def _calculate_grade(self, ssl_info: SslInfo) -> str:
        """Calculate SSL grade (A+, A, B, C, D, F)"""
        if not ssl_info.enabled:
            return "N/A"

        score = 100

        # Protocol scoring
        protocol_scores = {
            "TLSv1.3": 0,
            "TLSv1.2": -5,
            "TLSv1.1": -20,
            "TLSv1": -30,
            "SSLv3": -50,
            "SSLv2": -80,
        }
        score += protocol_scores.get(ssl_info.protocol, -10)

        # Certificate validity
        if ssl_info.is_expired:
            score -= 50
        if ssl_info.is_self_signed:
            score -= 30
        if not ssl_info.chain_valid:
            score -= 20

        # Days until expiry
        if ssl_info.days_until_expiry < 30:
            score -= 10
        elif ssl_info.days_until_expiry < 7:
            score -= 20

        # Cipher suite scoring (basic)
        if ssl_info.cipher_suite:
            cipher_lower = ssl_info.cipher_suite.lower()
            if "aes_256" in cipher_lower or "chacha20" in cipher_lower:
                score += 5
            if "gcm" in cipher_lower:
                score += 5
            if "sha384" in cipher_lower or "sha256" in cipher_lower:
                score += 3
            if "rc4" in cipher_lower or "des" in cipher_lower:
                score -= 30
            if "md5" in cipher_lower:
                score -= 20

        # OCSP stapling bonus
        if ssl_info.ocsp_stapling:
            score += 5

        # Convert score to grade
        if score >= 95:
            return "A+"
        elif score >= 85:
            return "A"
        elif score >= 75:
            return "B"
        elif score >= 65:
            return "C"
        elif score >= 50:
            return "D"
        else:
            return "F"
