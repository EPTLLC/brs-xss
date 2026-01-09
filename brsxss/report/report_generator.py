#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:20:00 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import time
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
from dataclasses import asdict, field

import brs_kb

from .report_types import ReportConfig, ReportFormat
from .data_models import VulnerabilityData, ScanStatistics
from .templates import HTMLTemplate, SARIFTemplate, JUnitTemplate, JSONTemplate
from .sarif_reporter import SARIFReporter
from ..core.finding_normalizer import prepare_findings_for_report
from ..utils.logger import Logger
from .. import __version__

get_vulnerability_details = brs_kb.get_vulnerability_details

logger = Logger("report.report_generator")


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

    def __init__(self, config: Optional[ReportConfig] = None):
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
        target_info: Dict[str, Any] = field(default_factory=dict),
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
        logger.info(
            f"Generating report: {len(vulnerabilities)} vulnerabilities, {len(self.config.formats)} formats"
        )

        if target_info is None:
            target_info = {}

        raw_findings: List[Dict[str, Any]] = [
            self._coerce_vuln_dict(v) for v in vulnerabilities
        ]
        normalized = prepare_findings_for_report(
            raw_findings, mode=target_info.get("mode", "standard")
        )
        confirmed_vulnerabilities = self._filter_vulnerabilities(
            normalized.get("confirmed", [])
        )
        potential_vulnerabilities = normalized.get("potential", [])

        # Prepare report data
        report_data = self._prepare_report_data(
            confirmed_vulnerabilities,
            potential_vulnerabilities,
            statistics,
            target_info,
        )

        # Generate reports in all formats
        generated_files = {}

        for report_format in self.config.formats:
            try:
                file_path = self._generate_single_format(report_format, report_data)
                generated_files[report_format] = file_path
                logger.info(
                    f"{report_format.value.upper()} report generated: {file_path}"
                )
            except Exception as e:
                logger.error(f"Error generating {report_format.value} report: {e}")

        logger.info(f"Report generated in {len(generated_files)} formats")

        return generated_files

    def _filter_vulnerabilities(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Filter vulnerabilities by settings"""

        # Severity level mapping
        severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        min_level = severity_levels.get(self.config.min_severity, 1)

        filtered = []

        for vuln in vulnerabilities:
            severity = str(vuln.get("severity", "low")).lower()
            vuln_level = severity_levels.get(severity, 1)
            if vuln_level < min_level:
                continue

            filtered.append(vuln)

            # Count limit
            if len(filtered) >= self.config.max_vulnerabilities:
                break

        if len(filtered) != len(vulnerabilities):
            logger.info(
                f"Filtered {len(filtered)} out of {len(vulnerabilities)} vulnerabilities"
            )

        return filtered

    def _prepare_report_data(
        self,
        confirmed_vulns: List[Dict[str, Any]],
        potential_vulns: List[Dict[str, Any]],
        scan_stats: ScanStatistics,
        target_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Prepare context for Jinja2 templates"""

        # Enhance vulnerability data with details from knowledge base
        enhanced_confirmed = []
        for vuln in confirmed_vulns:
            context_value = vuln.get("context", "")
            details = get_vulnerability_details(context_value)
            vuln_dict = dict(vuln)
            # Preserve original fields like title/description if already provided
            for k, v in (details or {}).items():
                if k not in vuln_dict or not vuln_dict.get(k):
                    vuln_dict[k] = v
            enhanced_confirmed.append(vuln_dict)

        enhanced_potential = []
        for vuln in potential_vulns:
            context_value = vuln.get("context", "")
            details = get_vulnerability_details(context_value)
            vuln_dict = dict(vuln)
            for k, v in (details or {}).items():
                if k not in vuln_dict or not vuln_dict.get(k):
                    vuln_dict[k] = v
            enhanced_potential.append(vuln_dict)

        context = {
            "report_title": target_info.get("title", "BRS-XSS Scan Report"),
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_name": target_info.get("scanner_name", "BRS-XSS"),
            "scanner_version": __version__,
            "target_url": target_info.get("url", ""),
            "vulnerabilities": enhanced_confirmed + enhanced_potential,
            "confirmed_vulnerabilities": enhanced_confirmed,
            "potential_vulnerabilities": enhanced_potential,
            "vulnerabilities_raw": confirmed_vulns + potential_vulns,
            "total_vulnerabilities": len(confirmed_vulns),
            "potential_vulnerabilities_count": len(potential_vulns),
            "scan_stats": asdict(scan_stats),
            "statistics": asdict(scan_stats),
            "severity_counts": self._count_severities(confirmed_vulns),
            "policy": target_info.get("policy", {}),
            "summary": {
                "total_vulnerabilities": len(confirmed_vulns),
                "critical_count": self._count_severities(confirmed_vulns)["critical"],
                "high_count": self._count_severities(confirmed_vulns)["high"],
                "medium_count": self._count_severities(confirmed_vulns)["medium"],
                "low_count": self._count_severities(confirmed_vulns)["low"],
                "risk_score": self._calculate_risk_score(
                    self._count_severities(confirmed_vulns)
                ),
                "risk_level": self._get_risk_level(
                    self._calculate_risk_score(self._count_severities(confirmed_vulns))
                ),
                "top_vulnerable_urls": self._get_top_vulnerable_urls(confirmed_vulns),
            },
            "recommendations": self._generate_recommendations(confirmed_vulns),
            "methodology": self._get_methodology_info(),
            "timestamp": time.time(),
            "generation_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        return context

    def _generate_single_format(
        self, report_format: ReportFormat, report_data: Dict[str, Any]
    ) -> str:
        """Generate report in single format"""

        # Form filename
        timestamp = int(time.time())
        filename = self.config.filename_template.format(timestamp=timestamp)

        # Add extension
        extensions = {
            ReportFormat.HTML: ".html",
            ReportFormat.SARIF: ".sarif",
            ReportFormat.JUNIT: ".xml",
            ReportFormat.JSON: ".json",
            ReportFormat.CSV: ".csv",
            ReportFormat.XML: ".xml",
            ReportFormat.MARKDOWN: ".md",
        }

        extension = extensions.get(report_format, ".txt")
        full_filename = f"{filename}{extension}"

        # Full file path
        file_path = Path(self.config.output_dir) / full_filename

        # Special handling for SARIF 2.1.0 compliant reports
        if report_format == ReportFormat.SARIF:
            # Use new SARIF reporter for GitHub Security integration
            raw_vulns = report_data.get(
                "confirmed_vulnerabilities", report_data.get("vulnerabilities", [])
            )
            sarif_vulns: List[VulnerabilityData] = []
            for idx, vuln in enumerate(raw_vulns, 1):
                if isinstance(vuln, VulnerabilityData):
                    sarif_vulns.append(vuln)
                else:
                    sarif_vulns.append(
                        VulnerabilityData(
                            id=str(vuln.get("id", f"xss_{idx}")),
                            title=vuln.get("title", f"Confirmed finding {idx}"),
                            description=vuln.get(
                                "description", "XSS vulnerability detected."
                            ),
                            severity=str(vuln.get("severity", "low")),
                            confidence=float(vuln.get("confidence", 0.5)),
                            url=vuln.get("url", ""),
                            parameter=vuln.get("parameter", ""),
                            payload=vuln.get("payload", ""),
                            context=vuln.get("context", "unknown"),
                            vulnerability_type=vuln.get(
                                "vulnerability_type", "reflected_xss"
                            ),
                            context_type=vuln.get(
                                "context_type", vuln.get("context", "html_content")
                            ),
                        )
                    )
            scan_info = {
                "start_time": report_data.get("scan_info", {}).get("start_time"),
                "end_time": report_data.get("scan_info", {}).get("end_time"),
                "targets_scanned": report_data.get("scan_info", {}).get(
                    "targets_scanned", 0
                ),
                "duration": report_data.get("scan_info", {}).get("duration", "unknown"),
                "command_line": report_data.get("scan_info", {}).get(
                    "command_line", "brs-xss scan"
                ),
                "machine": report_data.get("scan_info", {}).get("machine", "unknown"),
            }

            self.sarif_reporter.save_sarif(sarif_vulns, scan_info, str(file_path))
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

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> int:
        """Calculate overall risk score (0-100)"""

        # Weights by severity
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}

        total_score = 0
        for severity, count in severity_counts.items():
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

    def _generate_recommendations(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate general recommendations"""

        recommendations = [
            "Implement Content Security Policy (CSP) headers",
            "Validate and sanitize all user input",
            "Use parameterized queries and prepared statements",
            "Encode output appropriately for the context",
            "Implement proper authentication and authorization",
        ]

        # Specific recommendations based on found vulnerabilities
        vuln_types = set()
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                vuln_types.add(str(vuln.get("vulnerability_type", "")).lower())
            else:
                vuln_types.add(str(getattr(vuln, "vulnerability_type", "")).lower())

        if "reflected" in vuln_types or "reflected_xss" in vuln_types:
            recommendations.append(
                "Use textContent instead of innerHTML for dynamic content"
            )

        if "dom" in " ".join(vuln_types):
            recommendations.append("Avoid using dangerous DOM manipulation methods")

        if "stored" in vuln_types or "stored_xss" in vuln_types:
            recommendations.append(
                "Implement server-side input validation and output encoding"
            )

        return recommendations

    def _get_methodology_info(self) -> Dict[str, Any]:
        """Testing methodology information"""
        return {
            "scanner_name": "BRS-XSS",
            "scanner_version": __version__,
            "methodology": "OWASP Testing Guide",
            "techniques_used": [
                "Reflected XSS Testing",
                "DOM-based XSS Testing",
                "Stored XSS Testing",
                "Context Analysis",
                "WAF Detection and Bypass",
                "Payload Generation and Optimization",
            ],
            "coverage": "All input vectors including forms, URLs parameters, and HTTP headers",
        }

    def _count_severities(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in vulnerabilities:
            severity = str(vuln.get("severity", "low")).lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        return severity_counts

    def _get_top_vulnerable_urls(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Tuple[str, int]]:
        """Get top 10 URLs with the most vulnerabilities"""
        url_counts: Dict[str, int] = {}
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                url = vuln.get("url", "unknown")
            else:
                url = getattr(vuln, "url", "unknown")
            url_counts[url] = url_counts.get(url, 0) + 1
        return sorted(url_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    def _coerce_vuln_dict(self, vuln: Any) -> Dict[str, Any]:
        """Convert any supported vulnerability representation into dict form."""
        if isinstance(vuln, dict):
            return dict(vuln)
        if isinstance(vuln, VulnerabilityData):
            return asdict(vuln)
        if hasattr(vuln, "model_dump"):
            return vuln.model_dump()
        if hasattr(vuln, "__dict__"):
            return dict(vuln.__dict__)
        return {"severity": getattr(vuln, "severity", "low")}

    def generate_summary_report(self, scan_results: List[Dict[str, Any]]) -> str:
        """
        Generate summary report for multiple scans.

        Args:
            scan_results: List of scan results

        Returns:
            Path to summary report
        """
        logger.info(f"Generating summary report for {len(scan_results)} scans")

        # Aggregate data
        total_vulns = 0
        all_targets = []
        severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for result in scan_results:
            vulns = result.get("vulnerabilities", [])
            total_vulns += len(vulns)
            all_targets.append(result.get("target_info", {}).get("url", "Unknown"))

            # Count by severity
            for vuln in vulns:
                severity = vuln.get("severity", "low")
                if severity in severity_totals:
                    severity_totals[severity] += 1

        summary_data = {
            "total_scans": len(scan_results),
            "total_vulnerabilities": total_vulns,
            "severity_distribution": severity_totals,
            "targets_scanned": all_targets,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Generate HTML report
        template = self.templates[ReportFormat.HTML]
        content = template.generate_summary(summary_data)

        # Save
        timestamp = int(time.time())
        filename = f"brsxss_summary_report_{timestamp}.html"
        file_path = Path(self.config.output_dir) / filename

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"Summary report generated: {file_path}")

        return str(file_path)

    def get_generator_stats(self) -> Dict[str, Any]:
        """Generator statistics"""
        return {
            "output_directory": self.config.output_dir,
            "supported_formats": [fmt.value for fmt in ReportFormat],
            "configured_formats": [fmt.value for fmt in self.config.formats],
            "templates_loaded": list(self.templates.keys()),
            "config": {
                "include_summary": self.config.include_summary,
                "include_vulnerabilities": self.config.include_vulnerabilities,
                "include_statistics": self.config.include_statistics,
                "min_severity": self.config.min_severity,
                "max_vulnerabilities": self.config.max_vulnerabilities,
            },
        }
