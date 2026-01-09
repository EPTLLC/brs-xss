#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 14:37:26 MSK
Status: Created
Telegram: https://t.me/EasyProTech

DNS resolver and IP/Geo information gatherer.
All data collection is done without external APIs - direct DNS queries only.
"""

import socket
import asyncio
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse

from .recon_types import DnsInfo, DnsRecord, IpInfo, GeoInfo
from ..utils.logger import Logger

logger = Logger("recon.dns_resolver")


# Known CDN/Hosting IP ranges (partial, for detection)
CDN_IP_RANGES = {
    "cloudflare": [
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "108.162.192.0/18",
        "131.0.72.0/22",
        "141.101.64.0/18",
        "162.158.0.0/15",
        "172.64.0.0/13",
        "173.245.48.0/20",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
    ],
    "aws_cloudfront": ["13.32.0.0/15", "13.35.0.0/16", "52.46.0.0/18"],
    "akamai": ["23.0.0.0/12", "104.64.0.0/10"],
    "fastly": ["151.101.0.0/16", "199.232.0.0/16"],
    "google_cloud": ["35.186.0.0/16", "35.190.0.0/16"],
}

# Known ASN names
ASN_PROVIDERS = {
    "cloudflare": ["AS13335", "CLOUDFLARENET"],
    "amazon": ["AS16509", "AMAZON-02", "AWS"],
    "google": ["AS15169", "GOOGLE"],
    "microsoft": ["AS8075", "MICROSOFT-CORP"],
    "akamai": ["AS20940", "AKAMAI"],
    "fastly": ["AS54113", "FASTLY"],
    "digitalocean": ["AS14061", "DIGITALOCEAN"],
    "ovh": ["AS16276", "OVH"],
    "hetzner": ["AS24940", "HETZNER"],
}


class DnsResolver:
    """
    DNS resolver for target reconnaissance.
    Uses system DNS resolver for queries.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._cache: Dict[str, DnsInfo] = {}

    async def resolve(self, url: str) -> Tuple[DnsInfo, IpInfo]:
        """
        Resolve DNS and gather IP information for target URL.

        Args:
            url: Target URL

        Returns:
            Tuple of (DnsInfo, IpInfo)
        """
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]

        logger.info(f"Resolving DNS for: {domain}")

        dns_info = DnsInfo(domain=domain)
        ip_info = IpInfo()

        try:
            # Resolve A records (IPv4)
            ipv4_addresses = await self._resolve_a_records(domain)
            if ipv4_addresses:
                dns_info.records["A"] = [
                    DnsRecord(record_type="A", value=ip) for ip in ipv4_addresses
                ]
                ip_info.ipv4 = ipv4_addresses[0]

                # Check if CDN
                cdn = self._detect_cdn_from_ip(ip_info.ipv4)
                if cdn:
                    ip_info.is_cdn = True
                    ip_info.cdn_provider = cdn
                    if cdn.lower() == "cloudflare":
                        ip_info.is_cloudflare = True

            # Resolve AAAA records (IPv6)
            ipv6_addresses = await self._resolve_aaaa_records(domain)
            if ipv6_addresses:
                dns_info.records["AAAA"] = [
                    DnsRecord(record_type="AAAA", value=ip) for ip in ipv6_addresses
                ]
                ip_info.ipv6 = ipv6_addresses[0]

            # Resolve NS records
            ns_records = await self._resolve_ns_records(domain)
            if ns_records:
                dns_info.nameservers = ns_records
                dns_info.records["NS"] = [
                    DnsRecord(record_type="NS", value=ns) for ns in ns_records
                ]

                # Detect DNS provider
                dns_provider = self._detect_dns_provider(ns_records)
                if dns_provider:
                    ip_info.hosting_provider = dns_provider

            # Resolve MX records
            mx_records = await self._resolve_mx_records(domain)
            if mx_records:
                dns_info.mx_records = mx_records
                dns_info.records["MX"] = mx_records

            # Resolve TXT records
            txt_records = await self._resolve_txt_records(domain)
            if txt_records:
                dns_info.txt_records = txt_records
                dns_info.records["TXT"] = [
                    DnsRecord(record_type="TXT", value=txt) for txt in txt_records
                ]

            # PTR record (reverse DNS)
            if ip_info.ipv4:
                ptr = await self._resolve_ptr_record(ip_info.ipv4)
                if ptr:
                    ip_info.ptr_record = ptr

            # Geo information (from IP - basic without external API)
            ip_info.geo = self._get_basic_geo_info(ip_info.ipv4, dns_info)

            logger.info(f"DNS resolution complete for {domain}")

        except Exception as e:
            logger.error(f"DNS resolution error: {e}")

        return dns_info, ip_info

    async def _resolve_a_records(self, domain: str) -> List[str]:
        """Resolve A records"""
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname_ex, domain),
                timeout=self.timeout,
            )
            return result[2]
        except Exception as e:
            logger.debug(f"A record resolution failed: {e}")
            return []

    async def _resolve_aaaa_records(self, domain: str) -> List[str]:
        """Resolve AAAA records (IPv6)"""
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None, lambda: socket.getaddrinfo(domain, None, socket.AF_INET6)
                ),
                timeout=self.timeout,
            )
            return list(set(str(addr[4][0]) for addr in result))
        except Exception as e:
            logger.debug(f"AAAA record resolution failed: {e}")
            return []

    async def _resolve_ns_records(self, domain: str) -> List[str]:
        """Resolve NS records using system resolver"""
        try:
            # Try using nslookup equivalent
            import subprocess

            loop = asyncio.get_event_loop()

            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        ["dig", "+short", "NS", domain],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    ),
                ),
                timeout=self.timeout,
            )

            if result.returncode == 0 and result.stdout:
                ns_records = [
                    ns.strip().rstrip(".")
                    for ns in result.stdout.strip().split("\n")
                    if ns.strip()
                ]
                return ns_records
        except Exception as e:
            logger.debug(f"NS record resolution failed: {e}")

        return []

    async def _resolve_mx_records(self, domain: str) -> List[DnsRecord]:
        """Resolve MX records"""
        try:
            import subprocess

            loop = asyncio.get_event_loop()

            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        ["dig", "+short", "MX", domain],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    ),
                ),
                timeout=self.timeout,
            )

            mx_records = []
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            priority = int(parts[0])
                            server = parts[1].rstrip(".")
                            mx_records.append(
                                DnsRecord(
                                    record_type="MX", value=server, priority=priority
                                )
                            )
            return mx_records
        except Exception as e:
            logger.debug(f"MX record resolution failed: {e}")
            return []

    async def _resolve_txt_records(self, domain: str) -> List[str]:
        """Resolve TXT records"""
        try:
            import subprocess

            loop = asyncio.get_event_loop()

            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        ["dig", "+short", "TXT", domain],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    ),
                ),
                timeout=self.timeout,
            )

            txt_records = []
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        # Remove surrounding quotes
                        txt = line.strip().strip('"')
                        txt_records.append(txt)
            return txt_records
        except Exception as e:
            logger.debug(f"TXT record resolution failed: {e}")
            return []

    async def _resolve_ptr_record(self, ip: str) -> Optional[str]:
        """Resolve PTR record (reverse DNS)"""
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=self.timeout,
            )
            return result[0]
        except Exception as e:
            logger.debug(f"PTR record resolution failed: {e}")
            return None

    def _detect_cdn_from_ip(self, ip: str) -> Optional[str]:
        """Detect CDN provider from IP address"""
        if not ip:
            return None

        try:
            ip_int = self._ip_to_int(ip)

            for cdn_name, ranges in CDN_IP_RANGES.items():
                for ip_range in ranges:
                    network, prefix = ip_range.split("/")
                    network_int = self._ip_to_int(network)
                    mask = (0xFFFFFFFF << (32 - int(prefix))) & 0xFFFFFFFF

                    if (ip_int & mask) == (network_int & mask):
                        return cdn_name.title()
        except Exception as e:
            logger.debug(f"CDN detection failed: {e}")

        return None

    def _ip_to_int(self, ip: str) -> int:
        """Convert IP address to integer"""
        parts = ip.split(".")
        return (
            (int(parts[0]) << 24)
            + (int(parts[1]) << 16)
            + (int(parts[2]) << 8)
            + int(parts[3])
        )

    def _detect_dns_provider(self, ns_records: List[str]) -> Optional[str]:
        """Detect DNS provider from nameservers"""
        ns_str = " ".join(ns_records).lower()

        providers = {
            "cloudflare": ["cloudflare.com", "ns.cloudflare"],
            "aws_route53": ["awsdns", "amazonaws.com"],
            "google_cloud_dns": ["googledomains", "google.com"],
            "godaddy": ["domaincontrol.com", "godaddy"],
            "namecheap": ["namecheap", "registrar-servers"],
            "digitalocean": ["digitalocean.com"],
            "dnsimple": ["dnsimple.com"],
            "dnsmadeeasy": ["dnsmadeeasy.com"],
        }

        for provider, patterns in providers.items():
            for pattern in patterns:
                if pattern in ns_str:
                    return provider.replace("_", " ").title()

        return None

    def _get_basic_geo_info(self, ip: Optional[str], dns_info: DnsInfo) -> GeoInfo:
        """
        Get basic geo information without external APIs.
        Uses heuristics from DNS/TXT records and known patterns.
        """
        geo = GeoInfo()

        if not ip:
            return geo

        # Detect from TXT records (SPF often contains hints)
        for txt in dns_info.txt_records:
            txt_lower = txt.lower()
            if "google" in txt_lower:
                geo.organization = "Google Workspace User"
            if "microsoft" in txt_lower or "outlook" in txt_lower:
                geo.organization = "Microsoft 365 User"

        # Detect ISP/Organization from NS patterns
        ns_str = " ".join(dns_info.nameservers).lower() if dns_info.nameservers else ""

        if "cloudflare" in ns_str:
            geo.isp = "Cloudflare, Inc."
            geo.organization = "Cloudflare"
        elif "aws" in ns_str or "amazon" in ns_str:
            geo.isp = "Amazon Web Services"
            geo.organization = "AWS"
        elif "google" in ns_str:
            geo.isp = "Google Cloud"
            geo.organization = "Google"

        # For more accurate geo, would need GeoIP database
        # This is a limitation without external APIs
        geo.country = "Unknown (requires GeoIP DB)"

        return geo
