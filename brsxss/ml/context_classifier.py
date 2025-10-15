#!/usr/bin/env python3

"""
BRS-XSS Context Classifier

ML classifier for payload reflection contexts.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import pickle
from typing import List, Tuple, Optional

from .model_types import ModelType
from .feature_extractor import FeatureExtractor
from ..utils.logger import Logger

logger = Logger("ml.context_classifier")

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.svm import SVC
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class ContextClassifier:
    """
    ML context classifier.
    
    Modifies payload reflection context detection.
    """
    
    def __init__(self, model_type: ModelType = ModelType.RANDOM_FOREST):
        """
        Initialize classifier.
        
        Args:
            model_type: ML model type
        """
        self.model_type = model_type
        self.model = None
        self.vectorizer = None
        self.is_trained = False
        
        if not SKLEARN_AVAILABLE:
            logger.warning("scikit-learn unavailable, ML functions limited")
    
    def train(self, training_data: List[Tuple[str, int, str]]) -> float:
        """
        Train classifier.
        
        Args:
            training_data: List[(html_content, marker_position, context_label)]
            
        Returns:
            Model accuracy
        """
        if not SKLEARN_AVAILABLE:
            logger.error("scikit-learn required for training")
            return 0.0
        
        logger.info(f"Training context classifier on {len(training_data)} examples")
        
        # Extract features
        features = []
        labels = []
        
        for html_content, marker_pos, context_label in training_data:
            feature_vector = FeatureExtractor.extract_context_features(html_content, marker_pos)
            features.append(feature_vector)
            labels.append(context_label)
        
        # Create model
        if self.model_type == ModelType.RANDOM_FOREST:
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        elif self.model_type == ModelType.NAIVE_BAYES:
            self.model = MultinomialNB()
        elif self.model_type == ModelType.SVM:
            self.model = SVC(probability=True, random_state=42)
        
        # Convert features to numeric format
        feature_names = list(features[0].keys())
        X = [[f.get(name, 0) for name in feature_names] for f in features]
        y = labels
        
        # Split train/test
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train model
        self.model.fit(X_train, y_train)  # type: ignore
        
        # Evaluate accuracy
        y_pred = self.model.predict(X_test)  # type: ignore
        accuracy = accuracy_score(y_test, y_pred)
        
        self.is_trained = True
        logger.success(f"Model trained with accuracy: {accuracy:.2%}")
        
        return accuracy
    
    def predict(self, html_content: str, marker_position: int) -> Tuple[str, float]:
        """
        Predict context.
        
        Args:
            html_content: HTML content
            marker_position: Marker position
            
        Returns:
            Tuple[predicted_context, confidence]
        """
        if not self.is_trained or self.model is None:
            logger.warning("Model not trained, using fallback")
            return self._fallback_prediction(html_content, marker_position)
        
        # Extract features
        features = FeatureExtractor.extract_context_features(html_content, marker_position)
        
        # Convert to model format
        feature_names = list(features.keys())
        X = [[features.get(name, 0) for name in feature_names]]
        
        # Prediction
        prediction = self.model.predict(X)[0]
        
        # Confidence (if model supports)
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(X)[0]
            confidence = max(probabilities)
        else:
            confidence = 0.8  # Default confidence
        
        return prediction, confidence
    
    def _fallback_prediction(self, html_content: str, marker_position: int) -> Tuple[str, float]:
        """Fallback prediction without ML"""
        features = FeatureExtractor.extract_context_features(html_content, marker_position)
        
        # Simple heuristics
        if features.get('has_script_tag'):
            return 'javascript', 0.7
        elif features.get('in_href_attr') or features.get('in_src_attr'):
            return 'html_attribute', 0.6
        elif features.get('in_html_comment'):
            return 'html_comment', 0.8
        else:
            return 'html_content', 0.5
    
    def save_model(self, file_path: str):
        """Save model"""
        if self.model:
            with open(file_path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'model_type': self.model_type,
                    'is_trained': self.is_trained
                }, f)
            logger.info(f"Model saved: {file_path}")
    
    def load_model(self, file_path: str):
        """Load model"""
        try:
            with open(file_path, 'rb') as f:
                data = pickle.load(f)
            
            self.model = data['model']
            self.model_type = data['model_type']
            self.is_trained = data['is_trained']
            
            logger.info(f"Model loaded: {file_path}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")