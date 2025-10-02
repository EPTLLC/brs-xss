#!/usr/bin/env python3

"""
BRS-XSS Metadata Exporter

Exports scan metadata in various formats.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from dataclasses import asdict
from .metadata_collector import ScanMetadataCollector

from ..utils.logger import Logger

logger = Logger("core.metadata_exporter")


class MetadataExporter:
    """
    Exports scan metadata in various formats.
    
    Supports:
    - JSON reports
    - CI/CD integration format
    - Human-readable summaries
    """
    
    def __init__(self, collector: ScanMetadataCollector):
        """Initialize metadata exporter"""
        self.collector = collector
        logger.debug("Metadata exporter initialized")
    
    def get_metadata_dict(self) -> Dict[str, Any]:
        """Get complete metadata as dictionary"""
        return {
            "scan_id": self.collector.scan_id,
            "environment": asdict(self.collector.environment),
            "target": asdict(self.collector.target),
            "configuration": asdict(self.collector.configuration),
            "findings": asdict(self.collector.findings),
            "performance": asdict(self.collector.performance),
            "quality": asdict(self.collector.quality),
            "generated_at": datetime.now().isoformat(),
        }
    
    def save_metadata(self, output_dir: str = "results/metadata") -> str:
        """Save metadata to JSON file"""
        
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        filename = f"scan_metadata_{self.collector.scan_id}.json"
        filepath = Path(output_dir) / filename
        
        metadata = self.get_metadata_dict()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Scan metadata saved: {filepath}")
        return str(filepath)
    
    def get_summary_report(self) -> str:
        """Generate human-readable summary report"""
        
        summary = f"""
BRS-XSS Scan Summary Report
==========================

Scan ID: {self.collector.scan_id}
Target: {self.collector.target.url}
Duration: {self.collector.performance.scan_duration:.2f} seconds
Completed: {datetime.fromtimestamp(self.collector.environment.end_time).strftime('%Y-%m-%d %H:%M:%S')}

SECURITY FINDINGS
-----------------
Total Vulnerabilities: {self.collector.findings.total_vulnerabilities}
├─ High Severity: {self.collector.findings.high_severity}
├─ Medium Severity: {self.collector.findings.medium_severity}
└─ Low Severity: {self.collector.findings.low_severity}

Contexts Tested: {', '.join(self.collector.findings.contexts_tested) if self.collector.findings.contexts_tested else 'None'}
WAF Detected: {', '.join(self.collector.findings.waf_detected) if self.collector.findings.waf_detected else 'None'}

PERFORMANCE METRICS
------------------
Total Requests: {self.collector.performance.total_requests}
Success Rate: {(self.collector.performance.successful_requests / max(1, self.collector.performance.total_requests) * 100):.1f}%
Avg Response Time: {self.collector.performance.average_response_time:.3f}s
Requests/Second: {self.collector.performance.requests_per_second:.2f}
Payloads Tested: {self.collector.performance.total_payloads_tested}

QUALITY METRICS
---------------
Parameter Coverage: {self.collector.quality.parameter_coverage:.1%}
Context Coverage: {self.collector.quality.context_coverage:.1%}
Payload Diversity: {self.collector.quality.payload_diversity:.1%}
Confidence Score: {self.collector.quality.confidence_score:.1%}
Completeness: {self.collector.quality.completeness_score:.1%}

CONFIGURATION
-------------
Scan Type: {self.collector.configuration.scan_type}
Timeout: {self.collector.configuration.timeout}s
Max Concurrent: {self.collector.configuration.max_concurrent}
Deep Scan: {'Yes' if self.collector.configuration.deep_scan else 'No'}
ML Mode: {'Yes' if self.collector.configuration.ml_mode else 'No'}
Blind XSS: {'Yes' if self.collector.configuration.blind_xss_enabled else 'No'}
"""
        
        return summary.strip()
    
    def export_for_ci(self) -> Dict[str, Any]:
        """Export metadata in CI/CD friendly format"""
        
        return {
            "scan_id": self.collector.scan_id,
            "target_url": self.collector.target.url,
            "vulnerabilities_found": self.collector.findings.total_vulnerabilities,
            "high_severity_count": self.collector.findings.high_severity,
            "scan_duration": self.collector.performance.scan_duration,
            "success_rate": self.collector.performance.successful_requests / max(1, self.collector.performance.total_requests),
            "confidence_score": self.collector.quality.confidence_score,
            "completeness_score": self.collector.quality.completeness_score,
            "waf_detected": self.collector.findings.waf_detected,
            "status": "completed",
            "timestamp": self.collector.environment.end_time
        }