#!/usr/bin/env python3

"""
BRS-XSS AST Extractor

Extraction of AST nodes from JavaScript code lines.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from typing import List, Optional

from .ast_types import ASTNode, NodeType


class ASTExtractor:
    """AST node extractor from JavaScript code"""
    
    @staticmethod
    def parse_line(line: str, line_num: int) -> List[ASTNode]:
        """Parse single JavaScript line"""
        nodes = []
        
        # Function calls
        func_calls = ASTExtractor._extract_function_calls(line, line_num)
        nodes.extend(func_calls)
        
        # Variable assignments
        assignments = ASTExtractor._extract_variable_assignments(line, line_num)
        nodes.extend(assignments)
        
        # Property access
        property_accesses = ASTExtractor._extract_property_accesses(line, line_num)
        nodes.extend(property_accesses)
        
        # Event listeners
        event_listeners = ASTExtractor._extract_event_listeners(line, line_num)
        nodes.extend(event_listeners)
        
        return nodes
    
    @staticmethod
    def _extract_function_calls(line: str, line_num: int) -> List[ASTNode]:
        """Extract function calls"""
        nodes = []
        
        # Pattern for function calls: func_name(args)
        func_pattern = r'(\w+(?:\.\w+)*)\s*\(\s*([^)]*)\s*\)'
        
        for match in re.finditer(func_pattern, line):
            func_name = match.group(1)
            args_str = match.group(2)
            
            # Parse arguments
            arguments = ASTExtractor._parse_arguments(args_str)
            
            node = ASTNode(
                node_type=NodeType.FUNCTION_CALL,
                value=match.group(0),
                children=[],
                line_number=line_num,
                column=match.start(),
                function_name=func_name,
                arguments=arguments
            )
            
            nodes.append(node)
        
        return nodes
    
    @staticmethod
    def _extract_variable_assignments(line: str, line_num: int) -> List[ASTNode]:
        """Extract variable assignments"""
        nodes = []
        
        # Assignment patterns
        assignment_patterns = [
            r'(?:var|let|const)\s+(\w+)\s*=\s*(.+?)(?:;|$)',  # var x = value
            r'(\w+)\s*=\s*(.+?)(?:;|$)',  # x = value
            r'(\w+(?:\.\w+)+)\s*=\s*(.+?)(?:;|$)',  # obj.prop = value
        ]
        
        for pattern in assignment_patterns:
            for match in re.finditer(pattern, line):
                var_name = match.group(1)
                match.group(2).strip()
                
                node = ASTNode(
                    node_type=NodeType.VARIABLE_ASSIGNMENT,
                    value=match.group(0),
                    children=[],
                    line_number=line_num,
                    column=match.start(),
                    variable_name=var_name
                )
                
                nodes.append(node)
        
        return nodes
    
    @staticmethod
    def _extract_property_accesses(line: str, line_num: int) -> List[ASTNode]:
        """Extract property access"""
        nodes = []
        
        # Property access patterns: obj.prop or obj['prop']
        property_patterns = [
            r'(\w+)\.(\w+(?:\.\w+)*)',  # obj.prop.subprop
            r'(\w+)\[([\'"]?)(\w+)\2\]',  # obj['prop'] or obj["prop"]
        ]
        
        for pattern in property_patterns:
            for match in re.finditer(pattern, line):
                if len(match.groups()) >= 2:
                    obj_name = match.group(1)
                    prop_name = match.group(2) if pattern.endswith(r')\.(\w+(?:\.\w+)*)') else match.group(3)
                    
                    node = ASTNode(
                        node_type=NodeType.PROPERTY_ACCESS,
                        value=match.group(0),
                        children=[],
                        line_number=line_num,
                        column=match.start(),
                        object_name=obj_name,
                        property_name=prop_name
                    )
                    
                    nodes.append(node)
        
        return nodes
    
    @staticmethod
    def _extract_event_listeners(line: str, line_num: int) -> List[ASTNode]:
        """Extract event listeners"""
        nodes = []
        
        # addEventListener pattern
        event_pattern = r'(\w+)\.addEventListener\s*\(\s*[\'"](\w+)[\'"]\s*,\s*(.+?)\s*\)'
        
        for match in re.finditer(event_pattern, line):
            element = match.group(1)
            event_type = match.group(2)
            handler = match.group(3)
            
            node = ASTNode(
                node_type=NodeType.FUNCTION_CALL,
                value=match.group(0),
                children=[],
                line_number=line_num,
                column=match.start(),
                function_name="addEventListener",
                arguments=[f"'{event_type}'", handler],
                object_name=element
            )
            
            nodes.append(node)
        
        return nodes
    
    @staticmethod
    def _parse_arguments(args_str: str) -> List[str]:
        """Parse function arguments"""
        if not args_str.strip():
            return []
        
        # Simple comma separation (doesn't handle nested calls)
        args = []
        current_arg = ""
        paren_depth = 0
        quote_char = None
        
        for char in args_str:
            if quote_char:
                current_arg += char
                if char == quote_char and (not current_arg.endswith('\\' + quote_char)):
                    quote_char = None
            elif char in ['"', "'"]:
                quote_char = char
                current_arg += char
            elif char == '(':
                paren_depth += 1
                current_arg += char
            elif char == ')':
                paren_depth -= 1
                current_arg += char
            elif char == ',' and paren_depth == 0:
                args.append(current_arg.strip())
                current_arg = ""
            else:
                current_arg += char
        
        if current_arg.strip():
            args.append(current_arg.strip())
        
        return args