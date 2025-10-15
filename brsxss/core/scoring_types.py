#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 21:38:09 MSK
Status: Modified
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional
from dataclasses import dataclass, field
from enum import Enum


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"     # 9.0-10.0
    HIGH = "high"            # 7.0-8.9
    MEDIUM = "medium"        # 4.0-6.9
    LOW = "low"             # 1.0-3.9
    INFO = "info"           # 0.1-0.9
    NONE = "none"           # 0.0


@dataclass
class ScoringResult:
    """Vulnerability scoring result"""
    score: float                    # Overall detection score (0-10)
    severity: SeverityLevel        # Severity level
    confidence: float              # Detection score confidence (0-1)
    exploitation_likelihood: float = 0.0  # Likelihood of real exploitation (0-1)
    
    # Scoring components
    impact_score: float = 0.0      # Impact assessment
    exploitability_score: float = 0.0  # Exploitability assessment
    context_score: float = 0.0     # Context-based score
    reflection_score: float = 0.0  # Reflection quality score
    
    # Risk factors
    risk_factors: List[str] = field(default_factory=list)
    mitigating_factors: List[str] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if self.risk_factors is None:
            self.risk_factors = []
        if self.mitigating_factors is None:
            self.mitigating_factors = []
        if self.recommendations is None:
            self.recommendations = []


@dataclass
class ScoringWeights:
    """Scoring component weights"""
    impact: float = 0.4
    exploitability: float = 0.3
    context: float = 0.2
    reflection: float = 0.1
    
    def __post_init__(self):
        """Validate weights sum to 1.0"""
        total = self.impact + self.exploitability + self.context + self.reflection
        if abs(total - 1.0) > 0.01:
            raise ValueError(f"Scoring weights must sum to 1.0, got {total}")


@dataclass
class ContextInfo:
    """Context information for scoring"""
    context_type: str = "unknown"
    tag_name: str = ""
    attribute_name: str = ""
    filters_detected: List[str] = field(default_factory=list)
    encoding_detected: str = "none"
    position: str = "unknown"
    page_sensitive: bool = False
    user_controllable: bool = True
    
    def __post_init__(self):
        if self.filters_detected is None:
            self.filters_detected = []