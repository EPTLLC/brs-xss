#!/usr/bin/env python3

"""
BRS-XSS Prediction Types

Data structures for ML prediction results and confidence levels.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class ConfidenceLevel(Enum):
    """Confidence levels"""
    VERY_HIGH = "very_high"    # 0.9+
    HIGH = "high"             # 0.7+
    MEDIUM = "medium"         # 0.5+
    LOW = "low"              # 0.3+
    VERY_LOW = "very_low"    # <0.3


@dataclass
class PredictionResult:
    """Prediction result"""
    prediction: str
    confidence: float
    confidence_level: ConfidenceLevel
    model_used: str
    prediction_time: float
    
    # Additional data
    alternatives: List[Tuple[str, float]] = field(default_factory=list)  # Alternative predictions
    features_used: List[str] = field(default_factory=list)              # Used features
    explanation: str = ""                        # Prediction explanation
    
    def __post_init__(self):
        if self.alternatives is None:
            self.alternatives = []
        if self.features_used is None:
            self.features_used = []
        
        # Auto-determine confidence level
        if self.confidence >= 0.9:
            self.confidence_level = ConfidenceLevel.VERY_HIGH
        elif self.confidence >= 0.7:
            self.confidence_level = ConfidenceLevel.HIGH
        elif self.confidence >= 0.5:
            self.confidence_level = ConfidenceLevel.MEDIUM
        elif self.confidence >= 0.3:
            self.confidence_level = ConfidenceLevel.LOW
        else:
            self.confidence_level = ConfidenceLevel.VERY_LOW
    
    @property
    def is_reliable(self) -> bool:
        """Is result reliable"""
        return self.confidence >= 0.7
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'prediction': self.prediction,
            'confidence': self.confidence,
            'confidence_level': self.confidence_level.value,
            'model_used': self.model_used,
            'prediction_time': self.prediction_time,
            'is_reliable': self.is_reliable,
            'alternatives': self.alternatives,
            'features_used': self.features_used,
            'explanation': self.explanation
        }