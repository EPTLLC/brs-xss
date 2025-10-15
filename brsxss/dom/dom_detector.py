#!/usr/bin/env python3

"""
BRS-XSS DOM XSS Detector

Main DOM XSS detector integrating all DOM module components.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import time
from typing import Dict, List, Any, Optional
from pathlib import Path

from .scan_result import DOMScanResult
from .javascript_extractor import JavaScriptExtractor
from .dom_analyzer import DOMAnalyzer
from .vulnerability_types import VulnerabilityType, RiskLevel
from ..utils.logger import Logger

logger = Logger("dom.dom_detector")


class DOMXSSDetector:
    """
    Main DOM XSS detector for BRS-XSS.
    
    Functions:
    - Single file scanning
    - Batch directory scanning  
    - JS extraction from HTML
    - Integration of all DOM components
    - Detailed reporting
    """
    
    def __init__(self):
        """Initialize detector"""
        self.dom_analyzer = DOMAnalyzer()
        self.js_extractor = JavaScriptExtractor()
        
        # Statistics
        self.total_files_scanned = 0
        self.total_js_lines = 0
        self.scan_start_time = 0.0
    
    def scan_file(self, file_path: str) -> DOMScanResult:
        """
        Scan single file.
        
        Args:
            file_path: File path
            
        Returns:
            Scan result
        """
        logger.info(f"Scanning file: {file_path}")
        
        self.scan_start_time = time.time()
        vulnerabilities = []
        
        # Extract JavaScript code
        js_blocks = self.js_extractor.extract_from_file(file_path)
        
        if not js_blocks:
            logger.info("JavaScript code not found")
            return DOMScanResult(
                target_files=[file_path],
                total_files=1,
                vulnerabilities=[],
                scan_duration=time.time() - self.scan_start_time
            )
        
        total_lines = 0
        
        # Analyze each JS block
        for js_code, context in js_blocks:
            if not js_code.strip():
                continue
            
            lines_count = len(js_code.split('\n'))
            total_lines += lines_count
            
            logger.debug(f"Analyzing {context} block ({lines_count} lines)")
            
            # DOM XSS analysis
            block_vulnerabilities = self.dom_analyzer.analyze_javascript(js_code, file_path)
            
            # Add context to vulnerabilities
            for vuln in block_vulnerabilities:
                if not vuln.function_context:
                    vuln.function_context = context
                vulnerabilities.append(vuln)
        
        scan_duration = time.time() - self.scan_start_time
        
        result = DOMScanResult(
            target_files=[file_path],
            total_files=1,
            vulnerabilities=vulnerabilities,
            scan_duration=scan_duration,
            total_js_lines=total_lines
        )
        
        logger.success(f"Found {len(vulnerabilities)} DOM XSS vulnerabilities in {file_path}")
        
        return result
    
    def scan_directory(
        self, 
        directory_path: str, 
        recursive: bool = True,
        file_patterns: Optional[List[str]] = None
    ) -> DOMScanResult:
        """
        Scan directory.
        
        Args:
            directory_path: Directory path
            recursive: Recursive scanning
            file_patterns: File patterns for scanning
            
        Returns:
            Scan result
        """
        if file_patterns is None:
            file_patterns = ['*.js', '*.html', '*.htm', '*.php', '*.asp', '*.aspx', '*.jsp']
        
        logger.info(f"Scanning directory: {directory_path}")
        self.scan_start_time = time.time()
        
        # Find files
        directory = Path(directory_path)
        files_to_scan = []
        
        for pattern in file_patterns:
            if recursive:
                found_files = list(directory.rglob(pattern))
            else:
                found_files = list(directory.glob(pattern))
            
            files_to_scan.extend(found_files)
        
        # Remove duplicates
        files_to_scan = list(set(files_to_scan))
        
        logger.info(f"Found {len(files_to_scan)} files for scanning")
        
        all_vulnerabilities = []
        total_js_lines = 0
        scanned_files = []
        
        # Scan each file
        for file_path in files_to_scan:
            try:
                file_result = self.scan_file(str(file_path))
                all_vulnerabilities.extend(file_result.vulnerabilities)
                total_js_lines += file_result.total_js_lines
                scanned_files.append(str(file_path))
                
            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")
                continue
        
        scan_duration = time.time() - self.scan_start_time
        
        result = DOMScanResult(
            target_files=scanned_files,
            total_files=len(files_to_scan),
            vulnerabilities=all_vulnerabilities,
            scan_duration=scan_duration,
            total_js_lines=total_js_lines
        )
        
        logger.success(f"Scan completed: {len(all_vulnerabilities)} vulnerabilities in {len(scanned_files)} files")
        
        return result
    
    def scan_javascript_code(self, js_code: str, source_name: str = "inline") -> DOMScanResult:
        """
        Scan JavaScript code directly.
        
        Args:
            js_code: JavaScript code
            source_name: Source name
            
        Returns:
            Scan result
        """
        logger.info(f"Scanning JavaScript code ({len(js_code)} characters)")
        
        self.scan_start_time = time.time()
        
        # DOM XSS analysis
        vulnerabilities = self.dom_analyzer.analyze_javascript(js_code, source_name)
        
        scan_duration = time.time() - self.scan_start_time
        
        result = DOMScanResult(
            target_files=[source_name],
            total_files=1,
            vulnerabilities=vulnerabilities,
            scan_duration=scan_duration,
            total_js_lines=len(js_code.split('\n'))
        )
        
        return result
    
    def get_vulnerability_summary(self, result: DOMScanResult) -> Dict[str, Any]:
        """
        Get vulnerability summary.
        
        Args:
            result: Scan result
            
        Returns:
            Vulnerability summary
        """
        if not result.vulnerabilities:
            return {
                'status': 'clean',
                'message': 'DOM XSS vulnerabilities not found',
                'recommendations': [
                    'Continue following secure development principles',
                    'Regularly conduct security audits'
                ]
            }
        
        # Group by types
        vuln_by_type: Dict[str, List[Any]] = {}
        for vuln in result.vulnerabilities:
            vuln_type = vuln.vulnerability_type.value
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # Group by files
        vuln_by_file: Dict[str, List[Any]] = {}
        for vuln in result.vulnerabilities:
            file_path = vuln.file_path or 'unknown'
            if file_path not in vuln_by_file:
                vuln_by_file[file_path] = []
            vuln_by_file[file_path].append(vuln)
        
        # Top recommendations
        recommendations = []
        
        if result.critical_count > 0:
            recommendations.append(f"CRITICAL: Found {result.critical_count} critical vulnerabilities - require immediate fix")
        
        if result.high_count > 0:
            recommendations.append(f"HIGH: {result.high_count} high-risk vulnerabilities")
        
        # Specific recommendations by types
        type_recommendations = {
            VulnerabilityType.DIRECT_ASSIGNMENT: "Use textContent instead of innerHTML",
            VulnerabilityType.PROPERTY_INJECTION: "Apply sanitization with DOMPurify",
            VulnerabilityType.EVENT_HANDLER: "Avoid inline event handlers",
            VulnerabilityType.URL_MANIPULATION: "Validate URLs before use",
            VulnerabilityType.POSTMESSAGE_XSS: "Check PostMessage origins",
            VulnerabilityType.STORAGE_XSS: "Sanitize data from storage"
        }
        
        for vuln_type in vuln_by_type.keys():
            try:
                vuln_enum = VulnerabilityType(vuln_type)
                if vuln_enum in type_recommendations:
                    recommendations.append(type_recommendations[vuln_enum])
            except ValueError:
                pass
        
        return {
            'status': 'vulnerable' if result.has_vulnerabilities else 'clean',
            'total_vulnerabilities': result.total_vulnerabilities,
            'risk_score': result.risk_score,
            'risk_distribution': {
                'critical': result.critical_count,
                'high': result.high_count,
                'medium': result.medium_count,
                'low': result.low_count
            },
            'vulnerability_types': vuln_by_type,
            'affected_files': list(vuln_by_file.keys()),
            'most_vulnerable_file': max(vuln_by_file.items(), key=lambda x: len(x[1]))[0] if vuln_by_file else None,
            'recommendations': recommendations,
            'scan_stats': {
                'files_scanned': result.total_files,
                'js_lines_analyzed': result.total_js_lines,
                'scan_duration': result.scan_duration
            }
        }
    
    def filter_vulnerabilities(
        self, 
        result: DOMScanResult, 
        min_risk: RiskLevel = RiskLevel.LOW,
        min_confidence: float = 0.5,
        vuln_types: Optional[List[VulnerabilityType]] = None
    ) -> DOMScanResult:
        """
        Filter vulnerabilities.
        
        Args:
            result: Scan result
            min_risk: Minimum risk level
            min_confidence: Minimum confidence
            vuln_types: Vulnerability types to include
            
        Returns:
            Filtered result
        """
        
        # Risk level mapping to numbers
        risk_levels = {
            RiskLevel.INFO: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4
        }
        
        min_risk_level = risk_levels[min_risk]
        
        filtered_vulns = []
        
        for vuln in result.vulnerabilities:
            # Risk filter
            if risk_levels[vuln.risk_level] < min_risk_level:
                continue
            
            # Confidence filter
            if vuln.confidence < min_confidence:
                continue
            
            # Type filter
            if vuln_types and vuln.vulnerability_type not in vuln_types:
                continue
            
            filtered_vulns.append(vuln)
        
        # Create new result with filtered vulnerabilities
        filtered_result = DOMScanResult(
            target_files=result.target_files,
            total_files=result.total_files,
            vulnerabilities=filtered_vulns,
            scan_duration=result.scan_duration,
            total_js_lines=result.total_js_lines
        )
        
        return filtered_result
    
    def get_detector_stats(self) -> Dict[str, Any]:
        """Detector statistics"""
        return {
            'dom_analyzer_stats': self.dom_analyzer.get_analysis_summary(),
            'total_files_scanned': self.total_files_scanned,
            'total_js_lines': self.total_js_lines,
            'supported_file_types': ['.js', '.html', '.htm', '.php', '.asp', '.aspx', '.jsp'],
            'vulnerability_types_detected': [vuln_type.value for vuln_type in VulnerabilityType],
            'risk_levels': [risk.value for risk in RiskLevel]
        }