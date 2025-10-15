#!/usr/bin/env python3

"""
BRS-XSS DOM Data Models

Data structures for DOM XSS analysis results.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional
from dataclasses import dataclass, field

from .vulnerability_types import VulnerabilityType, RiskLevel


@dataclass
class DataFlow:
    """Data flow from source to sink"""
    source_type: str                    # Source type
    source_location: str               # Source location
    sink_type: str                     # Sink type
    sink_location: str                 # Sink location
    flow_path: List[str]              # Data flow path
    transformation_functions: List[str] # Transformation functions
    
    # Security analysis
    has_sanitization: bool = False     # Has sanitization
    bypasses_sanitization: bool = False # Bypasses sanitization
    encoding_applied: List[str] = field(default_factory=list)  # Applied encodings
    
    def __post_init__(self):
        if self.encoding_applied is None:
            self.encoding_applied = []


@dataclass
class DOMVulnerability:
    """DOM XSS vulnerability"""
    vulnerability_type: VulnerabilityType
    risk_level: RiskLevel
    confidence: float                   # Detection confidence (0-1)
    
    # Location
    file_path: Optional[str] = None
    line_number: int = 0
    column: int = 0
    
    # Vulnerability details
    source_code: str = ""              # Source code
    vulnerable_code: str = ""          # Vulnerable code
    data_flow: Optional[DataFlow] = None
    
    # Context
    function_context: Optional[str] = None  # Function context
    variable_context: List[str] = field(default_factory=list)      # Variable context
    
    # Exploitation
    sample_payload: str = ""           # Sample payload
    exploitation_notes: str = ""       # Exploitation notes
    
    # Recommendations
    fix_recommendation: str = ""       # Fix recommendations
    prevention_notes: str = ""         # Prevention notes
    
    def __post_init__(self):
        if self.variable_context is None:
            self.variable_context = []