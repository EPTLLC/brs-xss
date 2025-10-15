#!/usr/bin/env python3

"""
BRS-XSS DOM Analyzer

Main DOM XSS vulnerability analyzer with AST-based analysis.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, List, Optional, Any

from .vulnerability_types import VulnerabilityType, RiskLevel
from .data_models import DataFlow, DOMVulnerability
from .sanitization_analyzer import SanitizationAnalyzer
from .vulnerability_classifier import VulnerabilityClassifier
from .payload_generator import PayloadGenerator
from .parser import JavaScriptParser, ASTNode, SourceSinkMapping
from ..utils.logger import Logger

logger = Logger("dom.analyzer")


class DOMAnalyzer:
    """
    DOM XSS vulnerability analyzer.
    
    Features:
    - AST analysis of JavaScript code
    - Data flow tracking
    - Sanitization analysis
    - Vulnerability classification
    - Payload generation
    """
    
    def __init__(self):
        """Initialize analyzer"""
        self.js_parser = JavaScriptParser()
        self.sanitization_analyzer = SanitizationAnalyzer()
        self.vulnerability_classifier = VulnerabilityClassifier()
        self.payload_generator = PayloadGenerator()
        
        # Analysis results
        self.vulnerabilities: List[DOMVulnerability] = []
        self.data_flows: List[DataFlow] = []
    
    def analyze_javascript(self, js_code: str, file_path: Optional[str] = None) -> List[DOMVulnerability]:
        """
        Main JavaScript code analysis method.
        
        Args:
            js_code: JavaScript code
            file_path: File path (optional)
            
        Returns:
            List of found vulnerabilities
        """
        logger.info(f"Starting DOM XSS analysis ({len(js_code)} chars)")
        
        self.vulnerabilities = []
        self.data_flows = []
        
        # 1. JavaScript code parsing
        ast_nodes = self.js_parser.parse_javascript(js_code)
        
        if not ast_nodes:
            logger.warning("No AST nodes found")
            return []
        
        # 2. Find data flows
        source_sink_mappings = self.js_parser.find_data_flows()
        
        if not source_sink_mappings:
            logger.info("No data flows found")
            return []
        
        # 3. Analyze each data flow
        for mapping in source_sink_mappings:
            vulnerability = self._analyze_source_sink_mapping(mapping, js_code, file_path or "")
            
            if vulnerability:
                self.vulnerabilities.append(vulnerability)
        
        logger.info(f"Found {len(self.vulnerabilities)} DOM XSS vulnerabilities")
        
        return self.vulnerabilities
    
    def _analyze_source_sink_mapping(
        self, 
        mapping: SourceSinkMapping, 
        js_code: str, 
        file_path: str
    ) -> Optional[DOMVulnerability]:
        """Analyze source-sink mapping"""
        
        source_node = mapping.source_node
        sink_node = mapping.sink_node
        
        # Create DataFlow object
        data_flow = self._create_data_flow(mapping, js_code)
        
        # Classify vulnerability
        vuln_type, risk_level = self.vulnerability_classifier.classify_vulnerability(
            source_node, sink_node, data_flow
        )
        
        # Create vulnerability
        vulnerability = DOMVulnerability(
            vulnerability_type=vuln_type,
            risk_level=risk_level,
            confidence=mapping.vulnerability_confidence,
            file_path=file_path,
            line_number=sink_node.line_number,
            column=sink_node.column,
            source_code=self._extract_source_code(js_code, source_node, sink_node),
            vulnerable_code=sink_node.value,
            data_flow=data_flow,
            function_context=self._extract_function_context(source_node, sink_node),
            variable_context=self._extract_variable_context(mapping)
        )
        
        # Generate payload
        vulnerability.sample_payload = self.payload_generator.generate_payload(vulnerability)
        
        # Add recommendations
        vulnerability.fix_recommendation = self._generate_fix_recommendation(vulnerability)
        vulnerability.exploitation_notes = self._generate_exploitation_notes(vulnerability)
        
        return vulnerability
    
    def _create_data_flow(self, mapping: SourceSinkMapping, js_code: str) -> DataFlow:
        """Create DataFlow object"""
        
        source_node = mapping.source_node
        sink_node = mapping.sink_node
        
        # Extract code between source and sink
        flow_code = self._extract_flow_code(js_code, source_node, sink_node)
        
        # Analyze sanitization
        has_sanitization, bypasses_sanitization, sanitization_functions = \
            self.sanitization_analyzer.analyze_sanitization(flow_code)
        
        data_flow = DataFlow(
            source_type=source_node.function_name or source_node.value,
            source_location=f"{source_node.line_number}:{source_node.column}",
            sink_type=sink_node.function_name or sink_node.value,
            sink_location=f"{sink_node.line_number}:{sink_node.column}",
            flow_path=[node.value for node in mapping.data_path],
            transformation_functions=sanitization_functions,
            has_sanitization=has_sanitization,
            bypasses_sanitization=bypasses_sanitization
        )
        
        return data_flow
    
    def _extract_source_code(self, js_code: str, source_node: ASTNode, sink_node: ASTNode) -> str:
        """Extract vulnerability source code"""
        
        lines = js_code.split('\n')
        start_line = min(source_node.line_number, sink_node.line_number) - 1
        end_line = max(source_node.line_number, sink_node.line_number) - 1
        
        # Add context (2 lines on each side)
        start_line = max(0, start_line - 2)
        end_line = min(len(lines) - 1, end_line + 2)
        
        return '\n'.join(lines[start_line:end_line + 1])
    
    def _extract_flow_code(self, js_code: str, source_node: ASTNode, sink_node: ASTNode) -> str:
        """Extract data flow code"""
        
        lines = js_code.split('\n')
        start_line = min(source_node.line_number, sink_node.line_number) - 1
        end_line = max(source_node.line_number, sink_node.line_number) - 1
        
        return '\n'.join(lines[start_line:end_line + 1])
    
    def _extract_function_context(self, source_node: ASTNode, sink_node: ASTNode) -> Optional[str]:
        """Extract function context"""
        
        # Find enclosing function
        for node in self.js_parser.ast_nodes:
            if (node.node_type.value == 'function_declaration' and 
                node.line_number <= source_node.line_number):
                return node.function_name
        
        return None
    
    def _extract_variable_context(self, mapping: SourceSinkMapping) -> List[str]:
        """Extract variable context"""
        
        variables = []
        
        # Extract variables from data path
        for node in mapping.data_path:
            if node.variable_name:
                variables.append(node.variable_name)
            if node.object_name:
                variables.append(node.object_name)
        
        return list(set(variables))  # Remove duplicates
    
    def _generate_fix_recommendation(self, vulnerability: DOMVulnerability) -> str:
        """Generate fix recommendations"""
        
        vuln_type = vulnerability.vulnerability_type
        
        recommendations = {
            VulnerabilityType.DIRECT_ASSIGNMENT: 
                "Use textContent instead of innerHTML. Apply sanitization with DOMPurify.",
            
            VulnerabilityType.PROPERTY_INJECTION:
                "Sanitize user input. Use Content Security Policy (CSP).",
            
            VulnerabilityType.EVENT_HANDLER:
                "Avoid inline event handlers. Use addEventListener with validation.",
            
            VulnerabilityType.URL_MANIPULATION:
                "Validate URLs before use. Use whitelist of allowed domains.",
            
            VulnerabilityType.POSTMESSAGE_XSS:
                "Check message origins. Validate data structure.",
            
            VulnerabilityType.STORAGE_XSS:
                "Sanitize data before saving and after retrieving from storage."
        }
        
        return recommendations.get(vuln_type, "Apply general security principles and sanitization.")
    
    def _generate_exploitation_notes(self, vulnerability: DOMVulnerability) -> str:
        """Generate exploitation notes"""
        
        risk_level = vulnerability.risk_level
        
        if risk_level == RiskLevel.CRITICAL:
            return "Vulnerability allows execution of arbitrary JavaScript code. Immediate fix critical."
        elif risk_level == RiskLevel.HIGH:
            return "Vulnerability may lead to data theft or session hijacking. Requires priority fix."
        elif risk_level == RiskLevel.MEDIUM:
            return "Vulnerability may be exploited under certain conditions."
        else:
            return "Low exploitation risk, but fix recommended."
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Analysis summary"""
        
        if not self.vulnerabilities:
            return {
                'total_vulnerabilities': 0,
                'risk_distribution': {},
                'vulnerability_types': {},
                'recommendations': ['No vulnerabilities found']
            }
        
        # Risk distribution
        risk_distribution: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            risk = vuln.risk_level.value
            risk_distribution[risk] = risk_distribution.get(risk, 0) + 1
        
        # Type distribution
        vuln_types: Dict[str, int] = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.vulnerability_type.value
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        # General recommendations
        recommendations = [
            "Use Content Security Policy (CSP)",
            "Apply user input sanitization",
            "Avoid innerHTML for dynamic content",
            "Validate all data sources",
            "Use sanitization libraries (DOMPurify)"
        ]
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'risk_distribution': risk_distribution,
            'vulnerability_types': vuln_types,
            'high_confidence_vulns': sum(1 for v in self.vulnerabilities if v.confidence >= 0.8),
            'critical_vulns': sum(1 for v in self.vulnerabilities if v.risk_level == RiskLevel.CRITICAL),
            'recommendations': recommendations,
            'js_parser_stats': self.js_parser.get_parsing_stats()
        }