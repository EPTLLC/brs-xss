#!/usr/bin/env python3

"""
BRS-XSS AST Types

Abstract Syntax Tree node types and data structures for JavaScript parsing.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional
from dataclasses import dataclass, field
from enum import Enum


class NodeType(Enum):
    """AST node types"""
    FUNCTION_CALL = "function_call"
    VARIABLE_ASSIGNMENT = "variable_assignment"
    PROPERTY_ACCESS = "property_access"
    ARRAY_ACCESS = "array_access"
    STRING_LITERAL = "string_literal"
    IDENTIFIER = "identifier"
    BINARY_OPERATION = "binary_operation"
    CONDITIONAL = "conditional"
    LOOP = "loop"
    FUNCTION_DECLARATION = "function_declaration"


@dataclass
class ASTNode:
    """Abstract Syntax Tree node"""
    node_type: NodeType
    value: str
    children: List['ASTNode']
    line_number: int
    column: int
    
    # JavaScript-specific fields
    function_name: Optional[str] = None
    arguments: List[str] = field(default_factory=list)
    object_name: Optional[str] = None
    property_name: Optional[str] = None
    variable_name: Optional[str] = None
    
    # Context information
    scope: Optional[str] = None
    is_global: bool = False
    
    def __post_init__(self):
        if self.arguments is None:
            self.arguments = []


@dataclass
class SourceSinkMapping:
    """Mapping of data sources and sinks"""
    source_node: ASTNode
    sink_node: ASTNode
    data_path: List[ASTNode]
    vulnerability_confidence: float
    risk_factors: List[str]