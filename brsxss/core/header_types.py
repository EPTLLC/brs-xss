#!/usr/bin/env python3

"""
BRS-XSS Header Security Types

Data types and enums for HTTP security header analysis.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class SecurityLevel(Enum):
    """Security level assessment"""
    SECURE = "secure"
    MODERATE = "moderate"
    WEAK = "weak"
    VULNERABLE = "vulnerable"


@dataclass
class HeaderAnalysis:
    """Analysis result for a security header"""
    header_name: str
    value: str
    security_level: SecurityLevel
    vulnerabilities: List[str]
    recommendations: List[str]
    bypass_techniques: List[str] = field(default_factory=list)


@dataclass
class CSPAnalysis:
    """Detailed CSP analysis"""
    policy: str
    directives: Dict[str, List[str]]
    security_level: SecurityLevel
    vulnerabilities: List[str]
    bypass_opportunities: List[str]
    unsafe_sources: List[str]