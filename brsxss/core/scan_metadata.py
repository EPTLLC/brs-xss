#!/usr/bin/env python3

"""
BRS-XSS Scan Metadata

Main coordinator for scan metadata management.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Optional
from .metadata_collector import ScanMetadataCollector
from .metadata_exporter import MetadataExporter

from ..utils.logger import Logger

logger = Logger("core.scan_metadata")


class ScanMetadata:
    """
    Main coordinator for scan metadata management.
    
    Provides unified interface for:
    - Metadata collection
    - Data export
    - Report generation
    """
    
    def __init__(self, scan_id: Optional[str] = None):
        """Initialize scan metadata manager"""
        self.collector = ScanMetadataCollector(scan_id)
        self.exporter = MetadataExporter(self.collector)
        
        logger.info(f"Scan metadata manager initialized: {self.collector.scan_id}")
    
    @property
    def scan_id(self) -> str:
        """Get scan ID"""
        return self.collector.scan_id
    
    def set_target_info(self, url: str, **kwargs) -> None:
        """Set target information"""
        self.collector.set_target_info(url, **kwargs)
    
    def set_scan_config(self, **config_params) -> None:
        """Set scan configuration"""
        self.collector.set_scan_config(**config_params)
    
    def record_request(self, response_time: float, status_code: int, success: bool = True) -> None:
        """Record request metrics"""
        self.collector.record_request(response_time, status_code, success)
    
    def record_parameter_test(self, parameter: str, context: str = "unknown") -> None:
        """Record parameter testing"""
        self.collector.record_parameter_test(parameter, context)
    
    def record_payload_test(self, payload_type: str) -> None:
        """Record payload testing"""
        self.collector.record_payload_test(payload_type)
    
    def record_vulnerability(self, severity: str, context: str = "") -> None:
        """Record vulnerability"""
        self.collector.record_vulnerability(severity, context)
    
    def record_waf_detection(self, waf_name: str) -> None:
        """Record WAF detection"""
        self.collector.record_waf_detection(waf_name)
    
    def record_bypass_technique(self, technique: str) -> None:
        """Record bypass technique"""
        self.collector.record_bypass_technique(technique)
    
    def finalize_scan(self) -> None:
        """Finalize scan and calculate final metrics"""
        self.collector.finalize_scan()
    
    def save_metadata(self, output_dir: str = "results/metadata") -> str:
        """Save metadata to file"""
        return self.exporter.save_metadata(output_dir)
    
    def get_summary_report(self) -> str:
        """Get human-readable summary"""
        return self.exporter.get_summary_report()
    
    def export_for_ci(self) -> dict:
        """Export for CI/CD integration"""
        return self.exporter.export_for_ci()
    
    def get_metadata_dict(self) -> dict:
        """Get complete metadata dictionary"""
        return self.exporter.get_metadata_dict()