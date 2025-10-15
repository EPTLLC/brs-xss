#!/usr/bin/env python3

"""
BRS-XSS ML Model Types

Data structures and enums for machine learning models.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class ModelType(Enum):
    """ML model types"""
    RANDOM_FOREST = "random_forest"
    NAIVE_BAYES = "naive_bayes"
    SVM = "svm"
    NEURAL_NETWORK = "neural_network"


@dataclass
class FeatureVector:
    """Feature vector"""
    features: Dict[str, Any]
    label: Optional[str] = None
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'features': self.features,
            'label': self.label,
            'confidence': self.confidence
        }