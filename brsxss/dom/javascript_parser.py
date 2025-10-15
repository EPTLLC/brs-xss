#!/usr/bin/env python3

"""
BRS-XSS JavaScript Parser

JavaScript parser with AST-based approach for DOM XSS analysis.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, List, Any, Optional

from .ast_types import ASTNode, SourceSinkMapping
from .ast_extractor import ASTExtractor
from .data_flow_analyzer import DataFlowAnalyzer
from ..utils.logger import Logger

logger = Logger("dom.javascript_parser")


class JavaScriptParser:
    """
    JavaScript parser with AST approach.
    
    Capabilities compared to XSStrike:
    - AST analysis instead of regex
    - Data flow tracking
    - Scope analysis
    - Pattern recognition
    """
    
    def __init__(self):
        """Initialize parser"""
        self.ast_nodes: List[ASTNode] = []
        self.source_nodes: List[ASTNode] = []
        self.sink_nodes: List[ASTNode] = []
        self.variable_assignments: Dict[str, ASTNode] = {}
        self.function_declarations: Dict[str, ASTNode] = {}
        
    def parse_javascript(self, js_code: str) -> List[ASTNode]:
        """
        Main JavaScript code parsing method.
        
        Args:
            js_code: JavaScript code for analysis
            
        Returns:
            List of AST nodes
        """
        logger.info(f"Parsing JavaScript code ({len(js_code)} chars)")
        
        self.ast_nodes = []
        self.source_nodes = []
        self.sink_nodes = []
        self.variable_assignments = {}
        self.function_declarations = {}
        
        # Split code into lines
        lines = js_code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            
            # Parse line
            nodes = ASTExtractor.parse_line(line, line_num)
            self.ast_nodes.extend(nodes)
            
            # Store variable assignments
            for node in nodes:
                if node.variable_name and node.node_type.value == 'variable_assignment':
                    self.variable_assignments[node.variable_name] = node
        
        # Classify nodes
        self._classify_nodes()
        
        logger.success(f"Found {len(self.ast_nodes)} AST nodes, {len(self.source_nodes)} sources, {len(self.sink_nodes)} sinks")
        
        return self.ast_nodes
    
    def find_data_flows(self) -> List[SourceSinkMapping]:
        """
        Find data flows from sources to sinks.
        
        Returns:
            List of found data flows
        """
        analyzer = DataFlowAnalyzer(self.ast_nodes, self.variable_assignments)
        analyzer.source_nodes = self.source_nodes
        analyzer.sink_nodes = self.sink_nodes
        
        return analyzer.find_data_flows()
    
    def _classify_nodes(self):
        """Classify nodes as sources and sinks"""
        analyzer = DataFlowAnalyzer(self.ast_nodes, self.variable_assignments)
        analyzer.classify_nodes()
        
        self.source_nodes = analyzer.source_nodes
        self.sink_nodes = analyzer.sink_nodes
    
    def get_parsing_stats(self) -> Dict[str, Any]:
        """Parsing statistics"""
        return {
            'total_nodes': len(self.ast_nodes),
            'source_nodes': len(self.source_nodes),
            'sink_nodes': len(self.sink_nodes),
            'variable_assignments': len(self.variable_assignments),
            'function_declarations': len(self.function_declarations),
            'nodes_by_type': {
                node_type.value: sum(1 for node in self.ast_nodes if node.node_type == node_type)
                for node_type in list(set(node.node_type for node in self.ast_nodes))
            }
        }