#!/usr/bin/env python3

"""
BRS-XSS Report Generator

Central report generation system with multiple format support.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sun 10 Aug 2025 21:38:09 MSK (modified)
Telegram: https://t.me/EasyProTech
"""

import time
from pathlib import Path
from typing import Dict, List, Any

from .report_types import ReportFormat, ReportConfig
from .data_models import VulnerabilityData, ScanStatistics
from .templates import HTMLTemplate, SARIFTemplate, JUnitTemplate, JSONTemplate
from .sarif_reporter import SARIFReporter
from ..utils.logger import Logger

logger = Logger("report.generator")


class ReportGenerator:
    """
    Report generator with multiple format support.
    
    Features:
    - Formats: HTML, SARIF, JUnit, JSON
    - Customizable templates
    - Customization and branding
    - CI/CD integration
    - Automated reporting
    """
    
    def __init__(self, config: ReportConfig = None):
        """
        Initialize generator.
        
        Args:
            config: Report configuration
        """
        self.config = config or ReportConfig()
        
        # Initialize templates
        self.templates = {
            ReportFormat.HTML: HTMLTemplate(),
            ReportFormat.SARIF: SARIFTemplate(),
            ReportFormat.JUNIT: JUnitTemplate(),
            ReportFormat.JSON: JSONTemplate(),
        }
        
        # Initialize SARIF 2.1.0 compliant reporter
        self.sarif_reporter = SARIFReporter()
        
        # Create reports directory
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Report generator initialized: {self.config.output_dir}")
    
    def generate_report(
        self,
        vulnerabilities: List[VulnerabilityData],
        statistics: ScanStatistics,
        target_info: Dict[str, Any] = None
    ) -> Dict[ReportFormat, str]:
        """
        Main report generation method.
        
        Args:
            vulnerabilities: List of found vulnerabilities
            statistics: Scan statistics
            target_info: Target scan information
            
        Returns:
            Dictionary {format: file_path}
        """
        logger.info(f"🔄 Generating report: {len(vulnerabilities)} vulnerabilities, {len(self.config.formats)} formats")
        
        if target_info is None:
            target_info = {}
        
        # Filter vulnerabilities by settings
        filtered_vulnerabilities = self._filter_vulnerabilities(vulnerabilities)
        
        # Prepare report data
        report_data = self._prepare_report_data(
            filtered_vulnerabilities, statistics, target_info
        )
        
        # Generate reports in all formats
        generated_files = {}
        
        for report_format in self.config.formats:
            try:
                file_path = self._generate_single_format(report_format, report_data)
                generated_files[report_format] = file_path
                logger.info(f"{report_format.value.upper()} report generated: {file_path}")
            except Exception as e:
                logger.error(f"Error generating {report_format.value} report: {e}")
        
        logger.success(f"🎉 Report generated in {len(generated_files)} formats")
        
        return generated_files
    
    def _filter_vulnerabilities(self, vulnerabilities: List[VulnerabilityData]) -> List[VulnerabilityData]:
        """Filter vulnerabilities by settings"""
        
        # Severity level mapping
        severity_levels = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        
        min_level = severity_levels.get(self.config.min_severity, 1)
        
        filtered = []
        
        for vuln in vulnerabilities:
            # Filter by severity
            vuln_level = severity_levels.get(vuln.severity, 1)
            if vuln_level < min_level:
                continue
            
            filtered.append(vuln)
            
            # Count limit
            if len(filtered) >= self.config.max_vulnerabilities:
                break
        
        if len(filtered) != len(vulnerabilities):
            logger.info(f"Filtered {len(filtered)} out of {len(vulnerabilities)} vulnerabilities")
        
        return filtered
    
    def _prepare_report_data(
        self,
        vulnerabilities: List[VulnerabilityData],
        statistics: ScanStatistics,
        target_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Prepare data for report"""
        
        # Group vulnerabilities by severity
        vulns_by_severity = {
            'critical': [v for v in vulnerabilities if v.severity == 'critical'],
            'high': [v for v in vulnerabilities if v.severity == 'high'],
            'medium': [v for v in vulnerabilities if v.severity == 'medium'],
            'low': [v for v in vulnerabilities if v.severity == 'low']
        }
        
        # Group by types
        vulns_by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.vulnerability_type
            if vuln_type not in vulns_by_type:
                vulns_by_type[vuln_type] = []
            vulns_by_type[vuln_type].append(vuln)
        
        # Top URLs with vulnerabilities
        url_counts = {}
        for vuln in vulnerabilities:
            url = vuln.url
            url_counts[url] = url_counts.get(url, 0) + 1
        
        top_vulnerable_urls = sorted(url_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Overall risk assessment
        risk_score = self._calculate_risk_score(vulns_by_severity)
        
        return {
            'config': self.config,
            'vulnerabilities': vulnerabilities,
            'vulns_by_severity': vulns_by_severity,
            'vulns_by_type': vulns_by_type,
            'statistics': statistics,
            'target_info': target_info,
            'policy': target_info.get('policy', {}),
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'critical_count': len(vulns_by_severity['critical']),
                'high_count': len(vulns_by_severity['high']),
                'medium_count': len(vulns_by_severity['medium']),
                'low_count': len(vulns_by_severity['low']),
                'risk_score': risk_score,
                'risk_level': self._get_risk_level(risk_score),
                'top_vulnerable_urls': top_vulnerable_urls
            },
            'recommendations': self._generate_recommendations(vulnerabilities),
            'methodology': self._get_methodology_info(),
            'timestamp': time.time(),
            'generation_date': time.strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def _generate_single_format(self, report_format: ReportFormat, report_data: Dict[str, Any]) -> str:
        """Generate report in single format"""
        
        # Form filename
        timestamp = int(time.time())
        filename = self.config.filename_template.format(timestamp=timestamp)
        
        # Add extension
        extensions = {
            ReportFormat.HTML: '.html',
            ReportFormat.SARIF: '.sarif',
            ReportFormat.JUNIT: '.xml',
            ReportFormat.JSON: '.json',
            ReportFormat.CSV: '.csv',
            ReportFormat.XML: '.xml',
            ReportFormat.MARKDOWN: '.md'
        }
        
        extension = extensions.get(report_format, '.txt')
        full_filename = f"{filename}{extension}"
        
        # Full file path
        file_path = Path(self.config.output_dir) / full_filename
        
        # Special handling for SARIF 2.1.0 compliant reports
        if report_format == ReportFormat.SARIF:
            # Use new SARIF reporter for GitHub Security integration
            vulnerabilities = report_data.get('vulnerabilities', [])
            scan_info = {
                'start_time': report_data.get('scan_info', {}).get('start_time'),
                'end_time': report_data.get('scan_info', {}).get('end_time'),
                'targets_scanned': report_data.get('scan_info', {}).get('targets_scanned', 0),
                'duration': report_data.get('scan_info', {}).get('duration', 'unknown'),
                'command_line': report_data.get('scan_info', {}).get('command_line', 'brs-xss scan'),
                'machine': report_data.get('scan_info', {}).get('machine', 'unknown')
            }
            
            self.sarif_reporter.save_sarif(vulnerabilities, scan_info, str(file_path))
        else:
            # Use template-based generation for other formats
            template = self.templates.get(report_format)
            if not template:
                raise ValueError(f"Template for format {report_format.value} not found")
            
            # Generate content
            content = template.generate(report_data)
            
            # Save file atomically
            from ..utils.paths import atomic_write
            atomic_write(str(file_path), content)
        
        return str(file_path)
    
    def _calculate_risk_score(self, vulns_by_severity: Dict[str, List]) -> int:
        """Calculate overall risk score (0-100)"""
        
        # Weights by severity
        weights = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3
        }
        
        total_score = 0
        for severity, vulns in vulns_by_severity.items():
            count = len(vulns)
            weight = weights.get(severity, 1)
            total_score += count * weight
        
        # Normalize to 0-100 scale
        # Maximum possible score with 100 critical vulnerabilities = 2500
        max_possible = 2500
        normalized_score = min(100, (total_score / max_possible) * 100)
        
        return int(normalized_score)
    
    def _get_risk_level(self, risk_score: int) -> str:
        """Determine risk level"""
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        elif risk_score >= 20:
            return "Low"
        else:
            return "Minimal"
    
    def _generate_recommendations(self, vulnerabilities: List[VulnerabilityData]) -> List[str]:
        """Generate general recommendations"""
        
        recommendations = [
            "Implement Content Security Policy (CSP) headers",
            "Validate and sanitize all user input",
            "Use parameterized queries and prepared statements",
            "Encode output appropriately for the context",
            "Implement proper authentication and authorization"
        ]
        
        # Specific recommendations based on found vulnerabilities
        vuln_types = set(vuln.vulnerability_type for vuln in vulnerabilities)
        
        if 'reflected_xss' in vuln_types:
            recommendations.append("Use textContent instead of innerHTML for dynamic content")
        
        if 'dom_xss' in vuln_types:
            recommendations.append("Avoid using dangerous DOM manipulation methods")
        
        if 'stored_xss' in vuln_types:
            recommendations.append("Implement server-side input validation and output encoding")
        
        return recommendations
    
    def _get_methodology_info(self) -> Dict[str, Any]:
        """Testing methodology information"""
        return {
            'scanner_name': 'BRS-XSS',
            'scanner_version': '1.0.0',
            'methodology': 'OWASP Testing Guide',
            'techniques_used': [
                'Reflected XSS Testing',
                'DOM-based XSS Testing', 
                'Stored XSS Testing',
                'Context Analysis',
                'WAF Detection and Bypass',
                'Payload Generation and Optimization'
            ],
            'coverage': 'All input vectors including forms, URLs parameters, and HTTP headers'
        }
    
    def generate_summary_report(self, scan_results: List[Dict[str, Any]]) -> str:
        """
        Generate summary report for multiple scans.
        
        Args:
            scan_results: List of scan results
            
        Returns:
            Path to summary report
        """
        logger.info(f"📋 Generating summary report for {len(scan_results)} scans")
        
        # Aggregate data
        total_vulns = 0
        all_targets = []
        severity_totals = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for result in scan_results:
            vulns = result.get('vulnerabilities', [])
            total_vulns += len(vulns)
            all_targets.append(result.get('target_info', {}).get('url', 'Unknown'))
            
            # Count by severity
            for vuln in vulns:
                severity = vuln.get('severity', 'low')
                if severity in severity_totals:
                    severity_totals[severity] += 1
        
        summary_data = {
            'total_scans': len(scan_results),
            'total_vulnerabilities': total_vulns,
            'severity_distribution': severity_totals,
            'targets_scanned': all_targets,
            'scan_date': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Generate HTML report
        template = self.templates[ReportFormat.HTML]
        content = template.generate_summary(summary_data)
        
        # Save
        timestamp = int(time.time())
        filename = f"brsxss_summary_report_{timestamp}.html"
        file_path = Path(self.config.output_dir) / filename
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"Summary report generated: {file_path}")
        
        return str(file_path)
    
    def get_generator_stats(self) -> Dict[str, Any]:
        """Generator statistics"""
        return {
            'output_directory': self.config.output_dir,
            'supported_formats': [fmt.value for fmt in ReportFormat],
            'configured_formats': [fmt.value for fmt in self.config.formats],
            'templates_loaded': list(self.templates.keys()),
            'config': {
                'include_summary': self.config.include_summary,
                'include_vulnerabilities': self.config.include_vulnerabilities,
                'include_statistics': self.config.include_statistics,
                'min_severity': self.config.min_severity,
                'max_vulnerabilities': self.config.max_vulnerabilities
            }
        }