#!/usr/bin/env python3

"""
BRS-XSS DOM Scan Result

Data structures for DOM XSS scan results and statistics.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional
from dataclasses import dataclass, field

from .data_models import DOMVulnerability
from .vulnerability_types import RiskLevel


@dataclass
class DOMScanResult:
    """DOM XSS scan result"""
    target_files: List[str]                    # Scanned files
    total_files: int                          # Total number of files
    vulnerabilities: List[DOMVulnerability]   # Found vulnerabilities
    scan_duration: float                      # Scan time
    
    # Statistics
    total_js_lines: int = 0                   # Total JS lines
    parsed_functions: int = 0                 # Parsed functions
    analyzed_data_flows: int = 0              # Analyzed data flows
    
    # Vulnerability summary
    critical_count: int = 0
    high_count: int = 0  
    medium_count: int = 0
    low_count: int = 0
    
    def __post_init__(self):
        """Automatic statistics calculation"""
        self.critical_count = sum(1 for v in self.vulnerabilities if v.risk_level == RiskLevel.CRITICAL)
        self.high_count = sum(1 for v in self.vulnerabilities if v.risk_level == RiskLevel.HIGH)
        self.medium_count = sum(1 for v in self.vulnerabilities if v.risk_level == RiskLevel.MEDIUM)
        self.low_count = sum(1 for v in self.vulnerabilities if v.risk_level == RiskLevel.LOW)
    
    @property
    def total_vulnerabilities(self) -> int:
        """Total number of vulnerabilities"""
        return len(self.vulnerabilities)
    
    @property
    def has_vulnerabilities(self) -> bool:
        """Are vulnerabilities found"""
        return len(self.vulnerabilities) > 0
    
    @property
    def risk_score(self) -> float:
        """Overall risk score (0-100)"""
        if not self.vulnerabilities:
            return 0.0
        
        # Weight coefficients for risk levels
        weights = {
            RiskLevel.CRITICAL: 25,
            RiskLevel.HIGH: 15,
            RiskLevel.MEDIUM: 8,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 1
        }
        
        total_score = sum(weights.get(v.risk_level, 0) for v in self.vulnerabilities)
        max_possible = len(self.vulnerabilities) * weights[RiskLevel.CRITICAL]
        
        return min(100.0, (total_score / max_possible) * 100) if max_possible > 0 else 0.0