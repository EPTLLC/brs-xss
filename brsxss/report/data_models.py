#!/usr/bin/env python3

"""
BRS-XSS Report Data Models

Data structures for vulnerability reporting and scan statistics.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class VulnerabilityData:
    """Vulnerability data for report"""
    id: str
    title: str
    description: str
    severity: str                         # critical, high, medium, low
    confidence: float                     # 0-1
    
    # Technical information
    url: str
    parameter: str
    payload: str
    context: str = "unknown"
    
    # Optional detailed fields
    cwe: Optional[str] = None
    
    # Context
    vulnerability_type: str = "reflected_xss"
    context_type: str = "html_content"
    
    # Proof
    proof_of_concept: str = ""
    evidence_request: str = ""
    evidence_response: str = ""
    
    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # Metadata
    discovered_at: str = ""
    scan_engine: str = "brsxss"
    
    def __post_init__(self):
        if not self.discovered_at:
            self.discovered_at = time.strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class ScanStatistics:
    """Scan statistics"""
    # Basic metrics
    total_urls_tested: int = 0
    total_parameters_tested: int = 0
    total_payloads_tested: int = 0
    total_requests_sent: int = 0
    
    # Time metrics
    scan_duration: float = 0.0
    start_time: str = ""
    end_time: str = ""
    
    # Results
    vulnerabilities_found: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    
    # Technical metrics
    success_rate: float = 0.0             # Percentage of successful requests
    average_response_time: float = 0.0
    waf_detected: bool = False
    waf_type: str = "none"
    
    # Crawling statistics
    pages_crawled: int = 0
    forms_found: int = 0
    links_found: int = 0
    
    @property
    def vulnerability_distribution(self) -> Dict[str, int]:
        """Vulnerability distribution by severity"""
        return {
            'critical': self.critical_vulnerabilities,
            'high': self.high_vulnerabilities,
            'medium': self.medium_vulnerabilities,
            'low': self.low_vulnerabilities
        }