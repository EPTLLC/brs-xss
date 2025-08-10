#!/usr/bin/env python3

"""
BRS-XSS ML Module

Machine learning integration for XSS analysis with sklearn support.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from .model_types import ModelType, FeatureVector
from .feature_extractor import FeatureExtractor
from .context_classifier import ContextClassifier
from .payload_classifier import PayloadClassifier
from .vulnerability_classifier import VulnerabilityClassifier
from .predictor import ConfidenceLevel, PredictionResult, PredictionCache, MLPredictor

__all__ = [
    "ModelType",
    "FeatureVector",
    "FeatureExtractor",
    "ContextClassifier",
    "PayloadClassifier", 
    "VulnerabilityClassifier",
    "ConfidenceLevel",
    "PredictionResult",
    "PredictionCache",
    "MLPredictor"
]