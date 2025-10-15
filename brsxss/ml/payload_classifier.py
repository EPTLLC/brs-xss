#!/usr/bin/env python3

"""
BRS-XSS Payload Classifier

ML classifier for payload effectiveness and categorization.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Tuple, Optional

from .feature_extractor import FeatureExtractor
from ..utils.logger import Logger

logger = Logger("ml.payload_classifier")

try:
    from sklearn.ensemble import RandomForestRegressor
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import mean_squared_error
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class PayloadClassifier:
    """
    ML payload classifier.
    
    Determines payload effectiveness and category.
    """
    
    def __init__(self):
        """Initialize payload classifier"""
        self.effectiveness_model = None
        self.category_model = None
        self.is_trained = False
    
    def train_effectiveness(self, training_data: List[Tuple[str, float]]) -> float:
        """
        Train effectiveness model.
        
        Args:
            training_data: List[(payload, effectiveness_score)]
            
        Returns:
            Model accuracy
        """
        if not SKLEARN_AVAILABLE:
            return 0.0
        
        logger.info(f"Training effectiveness model on {len(training_data)} examples")
        
        # Extract features
        features = []
        scores = []
        
        for payload, effectiveness in training_data:
            feature_vector = FeatureExtractor.extract_payload_features(payload)
            features.append(feature_vector)
            scores.append(effectiveness)
        
        # Create regression model
        self.effectiveness_model = RandomForestRegressor(n_estimators=100, random_state=42)
        
        # Convert features
        feature_names = list(features[0].keys())
        X = [[f.get(name, 0) for name in feature_names] for f in features]
        y = scores
        
        # Train
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.effectiveness_model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.effectiveness_model.predict(X_test)
        mse = mean_squared_error(y_test, y_pred)
        
        logger.success(f"Effectiveness model trained with MSE: {mse:.4f}")
        return 1.0 - mse  # Simple accuracy metric
    
    def predict_effectiveness(self, payload: str) -> float:
        """
        Predict payload effectiveness.
        
        Args:
            payload: Payload to evaluate
            
        Returns:
            Effectiveness score (0-1)
        """
        if not self.effectiveness_model:
            return self._fallback_effectiveness(payload)
        
        features = FeatureExtractor.extract_payload_features(payload)
        feature_names = list(features.keys())
        X = [[features.get(name, 0) for name in feature_names]]
        
        prediction = self.effectiveness_model.predict(X)[0]
        return max(0.0, min(1.0, prediction))  # Limit to 0-1
    
    def _fallback_effectiveness(self, payload: str) -> float:
        """Fallback effectiveness evaluation"""
        features = FeatureExtractor.extract_payload_features(payload)
        
        score = 0.5  # Base score
        
        # Bonuses for effective techniques
        if features.get('has_script_tag'):
            score += 0.2
        if features.get('has_alert') or features.get('has_confirm'):
            score += 0.15
        if features.get('has_onerror') or features.get('has_onload'):
            score += 0.1
        
        # Penalties for complexity
        if features.get('length', 0) > 200:
            score -= 0.1
        if features.get('has_url_encoding') or features.get('has_html_entities'):
            score -= 0.05
        
        return max(0.1, min(1.0, score))