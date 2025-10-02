#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 21:38:09 MSK
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import time
from typing import List, Optional
from dataclasses import dataclass, field
from enum import Enum


class ReportFormat(Enum):
    """Report formats"""
    HTML = "html"
    SARIF = "sarif"         # Static Analysis Results Interchange Format
    JUNIT = "junit"         # JUnit XML for CI/CD integration
    JSON = "json"           # Structured JSON
    CSV = "csv"             # Tabular format
    XML = "xml"             # General XML format
    MARKDOWN = "markdown"   # Markdown document


@dataclass
class ReportConfig:
    """Report configuration"""
    # Main settings
    title: str = "BRS-XSS Security Report"
    description: str = "Automated XSS vulnerability assessment"
    output_dir: str = "./reports"
    filename_template: str = "brsxss_report_{timestamp}"
    
    # Formats for generation
    formats: List[ReportFormat] = field(default_factory=lambda: [ReportFormat.HTML, ReportFormat.JSON])
    
    # Report content
    include_summary: bool = True
    include_vulnerabilities: bool = True
    include_statistics: bool = True
    include_recommendations: bool = True
    include_methodology: bool = True
    include_appendix: bool = True
    
    # Detail level
    show_payload_details: bool = True
    show_request_response: bool = False    # Can be large
    show_screenshots: bool = False         # Requires browser integration
    include_source_code: bool = True
    
    # Filtering
    min_severity: str = "low"             # low, medium, high, critical
    max_vulnerabilities: int = 1000       # Limit for large reports
    
    # Metadata
    company_name: str = "Security Assessment"
    assessor_name: str = "BRS-XSS Scanner"
    client_name: str = ""
    scan_date: Optional[str] = None
    
    # Customization
    custom_css: Optional[str] = None      # For HTML reports
    logo_path: Optional[str] = None       # Company logo
    
    def __post_init__(self):
        if self.scan_date is None:
            self.scan_date = time.strftime("%Y-%m-%d %H:%M:%S")