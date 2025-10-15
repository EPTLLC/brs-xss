#!/usr/bin/env python3

"""
BRS-XSS Data Flow Analyzer

Analysis of data flows between sources and sinks for vulnerability detection.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from typing import List, Tuple, Set, Dict, Optional

from .ast_types import ASTNode, SourceSinkMapping, NodeType
from .dom_sources_sinks import DOM_SOURCES, DOM_SINKS
from ..utils.logger import Logger

logger = Logger("dom.data_flow_analyzer")


class DataFlowAnalyzer:
    """Data flow analyzer for XSS vulnerability detection"""
    
    def __init__(self, ast_nodes: List[ASTNode], variable_assignments: Dict[str, ASTNode]):
        self.ast_nodes = ast_nodes
        self.variable_assignments = variable_assignments
        self.source_nodes: List[ASTNode] = []
        self.sink_nodes: List[ASTNode] = []
    
    def classify_nodes(self):
        """Classify nodes as sources and sinks"""
        
        for node in self.ast_nodes:
            # Check sources
            if self._is_source_node(node):
                self.source_nodes.append(node)
            
            # Check sinks
            if self._is_sink_node(node):
                self.sink_nodes.append(node)
    
    def find_data_flows(self) -> List[SourceSinkMapping]:
        """
        Find data flows from sources to sinks.
        
        Returns:
            List of found data flows
        """
        data_flows = []
        
        logger.info(f"Data flow analysis: {len(self.source_nodes)} sources -> {len(self.sink_nodes)} sinks")
        
        for source in self.source_nodes:
            for sink in self.sink_nodes:
                # Check if there's a connection between source and sink
                confidence, risk_factors = self._analyze_data_flow(source, sink)
                
                if confidence > 0.3:  # Minimum threshold
                    # Build data path (simplified)
                    data_path = self._build_data_path(source, sink)
                    
                    mapping = SourceSinkMapping(
                        source_node=source,
                        sink_node=sink,
                        data_path=data_path,
                        vulnerability_confidence=confidence,
                        risk_factors=risk_factors
                    )
                    
                    data_flows.append(mapping)
        
        logger.success(f"Found {len(data_flows)} data flows")
        
        return data_flows
    
    def _is_source_node(self, node: ASTNode) -> bool:
        """Check if node is a data source"""
        
        node_value = node.value.lower()
        
        # Check function calls
        if node.node_type == NodeType.FUNCTION_CALL and node.function_name:
            func_name = node.function_name.lower()
            
            for source in DOM_SOURCES:
                if source.lower() in func_name or func_name in source.lower():
                    return True
        
        # Check property access
        if node.node_type == NodeType.PROPERTY_ACCESS:
            if node.object_name and node.property_name:
                full_name = f"{node.object_name}.{node.property_name}".lower()
                
                for source in DOM_SOURCES:
                    if source.lower() in full_name:
                        return True
        
        # Check by full node value
        for source in DOM_SOURCES:
            if source.lower() in node_value:
                return True
        
        return False
    
    def _is_sink_node(self, node: ASTNode) -> bool:
        """Check if node is a data sink"""
        
        node_value = node.value.lower()
        
        # Check function calls
        if node.node_type == NodeType.FUNCTION_CALL and node.function_name:
            func_name = node.function_name.lower()
            
            for sink in DOM_SINKS:
                if sink.lower() in func_name or func_name in sink.lower():
                    return True
        
        # Check assignments to dangerous properties
        if node.node_type == NodeType.VARIABLE_ASSIGNMENT:
            if node.variable_name:
                var_name = node.variable_name.lower()
                
                for sink in DOM_SINKS:
                    if sink.lower() in var_name:
                        return True
        
        # Check property access
        if node.node_type == NodeType.PROPERTY_ACCESS:
            if node.property_name:
                prop_name = node.property_name.lower()
                
                for sink in DOM_SINKS:
                    if sink.lower() in prop_name:
                        return True
        
        # Check by full node value
        for sink in DOM_SINKS:
            if sink.lower() in node_value:
                return True
        
        return False
    
    def _analyze_data_flow(self, source: ASTNode, sink: ASTNode) -> Tuple[float, List[str]]:
        """Analyze data flow between source and sink"""
        
        confidence = 0.0
        risk_factors = []
        
        # Basic assessment based on distance
        line_distance = abs(sink.line_number - source.line_number)
        
        if line_distance <= 1:
            confidence += 0.8  # Very close
            risk_factors.append("adjacent_lines")
        elif line_distance <= 5:
            confidence += 0.6  # Close
            risk_factors.append("nearby_lines")
        elif line_distance <= 20:
            confidence += 0.4  # Medium
            risk_factors.append("same_function")
        else:
            confidence += 0.2  # Far
            risk_factors.append("distant_lines")
        
        # Check variable usage
        if self._shares_variables(source, sink):
            confidence += 0.3
            risk_factors.append("shared_variables")
        
        # Check dangerous combinations
        if self._is_dangerous_combination(source, sink):
            confidence += 0.4
            risk_factors.append("dangerous_combination")
        
        # Check direct assignment
        if self._is_direct_assignment(source, sink):
            confidence += 0.5
            risk_factors.append("direct_assignment")
        
        return min(1.0, confidence), risk_factors
    
    def _shares_variables(self, source: ASTNode, sink: ASTNode) -> bool:
        """Check shared variables between source and sink"""
        
        # Extract variables from nodes
        source_vars = self._extract_variables_from_node(source)
        sink_vars = self._extract_variables_from_node(sink)
        
        return bool(source_vars.intersection(sink_vars))
    
    def _extract_variables_from_node(self, node: ASTNode) -> Set[str]:
        """Extract variables from node"""
        variables = set()
        
        # From function arguments
        if node.arguments:
            for arg in node.arguments:
                # Simple identifier extraction
                vars_in_arg = re.findall(r'\b[a-zA-Z_]\w*\b', arg)
                variables.update(vars_in_arg)
        
        # From variable name
        if node.variable_name:
            variables.add(node.variable_name)
        
        # From object name
        if node.object_name:
            variables.add(node.object_name)
        
        return variables
    
    def _is_dangerous_combination(self, source: ASTNode, sink: ASTNode) -> bool:
        """Check dangerous source-sink combination"""
        
        dangerous_combinations = [
            # URL sources -> code execution sinks
            (['location.href', 'location.search', 'location.hash'], 
             ['eval', 'function', 'settimeout', 'setinterval']),
            
            # User input -> DOM manipulation
            (['document.cookie', 'window.name'], 
             ['innerhtml', 'outerhtml', 'document.write']),
            
            # PostMessage -> dangerous operations
            (['postmessage', 'event.data'], 
             ['eval', 'innerhtml', 'location.href']),
        ]
        
        source_value = source.value.lower()
        sink_value = sink.value.lower()
        
        for source_patterns, sink_patterns in dangerous_combinations:
            source_match = any(pattern in source_value for pattern in source_patterns)
            sink_match = any(pattern in sink_value for pattern in sink_patterns)
            
            if source_match and sink_match:
                return True
        
        return False
    
    def _is_direct_assignment(self, source: ASTNode, sink: ASTNode) -> bool:
        """Check direct assignment from source to sink"""
        
        # Check if in the same line assignment from source to sink
        if source.line_number == sink.line_number:
            return True
        
        # Check through intermediate variables
        if sink.line_number > source.line_number:
            for line_num in range(source.line_number + 1, sink.line_number + 1):
                # Look for assignments in intermediate lines
                line_assignments = [
                    node for node in self.ast_nodes 
                    if node.line_number == line_num and node.node_type == NodeType.VARIABLE_ASSIGNMENT
                ]
                
                if line_assignments:
                    return True
        
        return False
    
    def _build_data_path(self, source: ASTNode, sink: ASTNode) -> List[ASTNode]:
        """Build data path between source and sink"""
        
        path = [source]
        
        # Simple algorithm - add intermediate nodes
        start_line = min(source.line_number, sink.line_number)
        end_line = max(source.line_number, sink.line_number)
        
        intermediate_nodes = [
            node for node in self.ast_nodes
            if start_line < node.line_number < end_line
        ]
        
        # Sort by line number
        intermediate_nodes.sort(key=lambda x: x.line_number)
        path.extend(intermediate_nodes)
        path.append(sink)
        
        return path