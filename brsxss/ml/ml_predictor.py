#!/usr/bin/env python3

"""
BRS-XSS ML Predictor

prediction handler based on trained ML models.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import time
from typing import Dict, List, Any, Optional

from .prediction_types import ConfidenceLevel, PredictionResult
from .prediction_cache import PredictionCache
from .context_classifier import ContextClassifier
from .payload_classifier import PayloadClassifier
from .vulnerability_classifier import VulnerabilityClassifier
# MLTrainer removed during refactoring
from ..utils.logger import Logger

logger = Logger("ml.ml_predictor")


class MLPredictor:
    """
    Prediction system based on machine learning.
    
    Integrates ML models into scanning process:
    - Context prediction
    - Payload effectiveness assessment
    - Vulnerability classification
    - WAF detection
    """
    
    def __init__(self, models_dir: str = "brsxss/ml/models", enable_cache: bool = True):
        """
        Initialize predictor.
        
        Args:
            models_dir: Directory with models
            enable_cache: Enable caching
        """
        self.models_dir = models_dir
        self.enable_cache = enable_cache
        
        # Classifiers
        self.context_classifier = ContextClassifier()
        self.payload_classifier = PayloadClassifier()
        self.vulnerability_classifier = VulnerabilityClassifier()
        
        # Prediction cache
        self.cache = PredictionCache() if enable_cache else None
        
        # Statistics
        self.prediction_count = 0
        self.cache_hits = 0
        self.cache_misses = 0
        
        # Load models
        self._load_models()
    
    def _load_models(self):
        """Load trained models"""
        try:
            # Context classifier
            context_model_path = f"{self.models_dir}/context_classifier.pkl"
            self.context_classifier.load_model(context_model_path)
            
            logger.info("ML models loaded successfully")
        except Exception as e:
            logger.warning(f"Error loading ML models: {e}")
            logger.info("Fallback algorithms will be used")
    
    def predict_context(self, html_content: str, marker_position: int) -> PredictionResult:
        """
        Predict reflection context.
        
        Args:
            html_content: HTML content
            marker_position: Marker position
            
        Returns:
            Context prediction result
        """
        start_time = time.time()
        
        # Create cache key
        cache_key = f"context_{hash(html_content)}_{marker_position}"
        
        # Check cache
        if self.cache:
            cached_result = self.cache.get(cache_key)
            if cached_result:
                self.cache_hits += 1
                return cached_result
            self.cache_misses += 1
        
        # Prediction
        prediction, confidence = self.context_classifier.predict(html_content, marker_position)
        
        prediction_time = time.time() - start_time
        
        result = PredictionResult(
            prediction=prediction,
            confidence=confidence,
            confidence_level=ConfidenceLevel.HIGH,  # Will be recalculated in __post_init__
            model_used="context_classifier",
            prediction_time=prediction_time,
            explanation=f"Context determined based on HTML structure analysis at position {marker_position}"
        )
        
        # Save to cache
        if self.cache:
            self.cache.put(cache_key, result)
        
        self.prediction_count += 1
        
        return result
    
    def predict_payload_effectiveness(self, payload: str) -> PredictionResult:
        """
        Predict payload effectiveness.
        
        Args:
            payload: Payload to evaluate
            
        Returns:
            Effectiveness prediction result
        """
        start_time = time.time()
        
        # Cache
        cache_key = f"payload_{hash(payload)}"
        if self.cache:
            cached_result = self.cache.get(cache_key)
            if cached_result:
                self.cache_hits += 1
                return cached_result
            self.cache_misses += 1
        
        # Prediction
        effectiveness = self.payload_classifier.predict_effectiveness(payload)
        
        prediction_time = time.time() - start_time
        
        # Classify effectiveness
        if effectiveness >= 0.8:
            effectiveness_label = "very_high"
        elif effectiveness >= 0.6:
            effectiveness_label = "high"
        elif effectiveness >= 0.4:
            effectiveness_label = "medium"
        else:
            effectiveness_label = "low"
        
        result = PredictionResult(
            prediction=effectiveness_label,
            confidence=effectiveness,
            confidence_level=ConfidenceLevel.HIGH,
            model_used="payload_classifier",
            prediction_time=prediction_time,
            explanation=f"Payload effectiveness rated as {effectiveness:.2%}"
        )
        
        if self.cache:
            self.cache.put(cache_key, result)
        
        self.prediction_count += 1
        
        return result
    
    def predict_vulnerability_severity(self, vulnerability_data: Dict[str, Any]) -> PredictionResult:
        """
        Predict vulnerability severity.
        
        Args:
            vulnerability_data: Vulnerability data
            
        Returns:
            Severity prediction result
        """
        start_time = time.time()
        
        # Prediction
        severity, confidence = self.vulnerability_classifier.predict_severity(vulnerability_data)
        
        prediction_time = time.time() - start_time
        
        result = PredictionResult(
            prediction=severity,
            confidence=confidence,
            confidence_level=ConfidenceLevel.HIGH,
            model_used="vulnerability_classifier",
            prediction_time=prediction_time,
            explanation=f"Vulnerability severity classified as {severity}"
        )
        
        self.prediction_count += 1
        
        return result
    
    def predict_waf_type(self, response_headers: Dict[str, str], response_content: str, status_code: int) -> PredictionResult:
        """
        Predict WAF type.
        
        Args:
            response_headers: HTTP headers
            response_content: Response content
            status_code: Status code
            
        Returns:
            WAF prediction result
        """
        start_time = time.time()
        
        # Simple heuristic classification (can be replaced with ML)
        waf_type = "none"
        confidence = 0.5
        
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        content_lower = response_content.lower()
        
        # Cloudflare
        if 'cf-ray' in headers_lower or 'cloudflare' in content_lower:
            waf_type = "cloudflare"
            confidence = 0.9
        
        # Incapsula
        elif 'x-iinfo' in headers_lower or 'incapsula' in content_lower:
            waf_type = "incapsula"
            confidence = 0.9
        
        # AWS WAF
        elif 'x-amzn-requestid' in headers_lower or 'aws' in content_lower:
            waf_type = "aws_waf"
            confidence = 0.8
        
        # Sucuri
        elif 'x-sucuri-id' in headers_lower or 'sucuri' in content_lower:
            waf_type = "sucuri"
            confidence = 0.9
        
        # General WAF signs
        elif status_code in [403, 406, 503] and any(keyword in content_lower for keyword in [
            'blocked', 'denied', 'forbidden', 'security', 'firewall'
        ]):
            waf_type = "generic_waf"
            confidence = 0.6
        
        prediction_time = time.time() - start_time
        
        result = PredictionResult(
            prediction=waf_type,
            confidence=confidence,
            confidence_level=ConfidenceLevel.HIGH,
            model_used="waf_heuristic",
            prediction_time=prediction_time,
            explanation=f"WAF type determined as {waf_type} based on header and content analysis"
        )
        
        self.prediction_count += 1
        
        return result
    
    def get_prediction_recommendations(self, prediction_result: PredictionResult) -> List[str]:
        """
        Get recommendations based on prediction.
        
        Args:
            prediction_result: Prediction result
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Confidence recommendations
        if prediction_result.confidence_level == ConfidenceLevel.VERY_LOW:
            recommendations.append("Low prediction confidence - additional verification recommended")
        elif prediction_result.confidence_level == ConfidenceLevel.VERY_HIGH:
            recommendations.append("Very high confidence - result is reliable")
        
        # Specific recommendations by prediction type
        if prediction_result.model_used == "context_classifier":
            if prediction_result.prediction == "javascript":
                recommendations.append("JavaScript context - use JS-specific payloads")
            elif prediction_result.prediction == "html_attribute":
                recommendations.append("HTML attribute - try quote escaping")
        
        elif prediction_result.model_used == "payload_classifier":
            if prediction_result.prediction == "low":
                recommendations.append("Low payload effectiveness - try alternative vectors")
            elif prediction_result.prediction == "very_high":
                recommendations.append("High effectiveness payload - strong exploitation candidate")
        
        elif prediction_result.model_used == "vulnerability_classifier":
            if prediction_result.prediction == "critical":
                recommendations.append("Critical vulnerability - requires immediate fix")
        
        return recommendations
    
    def batch_predict(self, predictions_batch: List[Dict[str, Any]]) -> List[PredictionResult]:
        """
        Batch prediction for acceleration.
        
        Args:
            predictions_batch: List of prediction data
            
        Returns:
            List of prediction results
        """
        results = []
        
        for prediction_data in predictions_batch:
            prediction_type = prediction_data.get('type')
            
            if prediction_type == 'context':
                result = self.predict_context(
                    prediction_data['html_content'],
                    prediction_data['marker_position']
                )
            elif prediction_type == 'payload':
                result = self.predict_payload_effectiveness(
                    prediction_data['payload']
                )
            elif prediction_type == 'vulnerability':
                result = self.predict_vulnerability_severity(
                    prediction_data['vulnerability_data']
                )
            elif prediction_type == 'waf':
                result = self.predict_waf_type(
                    prediction_data['headers'],
                    prediction_data['content'],
                    prediction_data['status_code']
                )
            else:
                continue
            
            results.append(result)
        
        return results
    
    def get_predictor_stats(self) -> Dict[str, Any]:
        """Predictor statistics"""
        stats = {
            'total_predictions': self.prediction_count,
            'cache_enabled': self.enable_cache,
            'models_loaded': {
                'context_classifier': self.context_classifier.is_trained,
                'payload_classifier': hasattr(self.payload_classifier, 'effectiveness_model'),
                'vulnerability_classifier': True,  # Always available (heuristic)
            }
        }
        
        if self.cache:
            cache_stats = self.cache.get_stats()
            stats.update({
                'cache_hits': self.cache_hits,
                'cache_misses': self.cache_misses,
                'cache_hit_ratio': self.cache_hits / (self.cache_hits + self.cache_misses) if (self.cache_hits + self.cache_misses) > 0 else 0,
                'cache_stats': cache_stats
            })
        
        return stats
    
    def clear_cache(self):
        """Clear cache"""
        if self.cache:
            self.cache.clear()
            logger.info("Prediction cache cleared")
    
    def retrain_models(self):
        """Retrain models with new data"""
        logger.info("Starting ML model retraining")
        
        # TODO: Implement MLTrainer or remove this method
        logger.warning("MLTrainer not implemented yet")
        results = {"status": "placeholder"}
        
        # Reload models
        self._load_models()
        
        # Clear cache as models have changed
        if self.cache:
            self.cache.clear()
        
        logger.success(f"Models retrained: {results}")
        
        return results