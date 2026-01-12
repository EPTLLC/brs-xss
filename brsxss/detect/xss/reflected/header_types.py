#!/usr/bin/env python3

"""
BRS-XSS Header Security Types

Data types and enums for HTTP security header analysis.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

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
    vulnerabilities: list[str]
    recommendations: list[str]
    bypass_techniques: list[str] = field(default_factory=list)


@dataclass
class CSPAnalysis:
    """Detailed CSP analysis"""

    policy: str
    directives: dict[str, list[str]]
    security_level: SecurityLevel
    vulnerabilities: list[str]
    bypass_opportunities: list[str]
    unsafe_sources: list[str]
