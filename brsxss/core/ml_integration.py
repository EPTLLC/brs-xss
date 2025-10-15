#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 15 Oct 2025 02:10:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech

ML Integration Layer for XSS Scanner

Provides seamless integration of ML predictions into the core scanning engine.
"""

from typing import Dict, Any, Optional, List
from ..utils.logger import Logger

logger = Logger("core.ml_integration")

# Try to import ML modules
try:
    from ..ml import MLPredictor, PredictionResult, ConfidenceLevel
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("ML module not available - predictions will use heuristics")


class MLIntegration:
    """
    ML Integration layer for XSS scanner.
    
    Features:
    - Context prediction enhancement
    - Payload effectiveness scoring
    - Vulnerability severity assessment
    - Confidence boosting for detections
    """
    
    def __init__(self, enable_ml: bool = True, models_dir: str = "brsxss/ml/models"):
        """
        Initialize ML integration.
        
        Args:
            enable_ml: Enable ML predictions
            models_dir: Path to ML models
        """
        self.enable_ml = enable_ml and ML_AVAILABLE
        self.models_dir = models_dir
        self.predictor: Optional[Any] = None
        
        # Statistics
        self.predictions_made = 0
        self.ml_enhancements = 0
        self.fallback_count = 0
        
        if self.enable_ml:
            self._initialize_predictor()
    
    def _initialize_predictor(self):
        """Initialize ML predictor"""
        try:
            self.predictor = MLPredictor(
                models_dir=self.models_dir,
                enable_cache=True
            )
            logger.info("ML predictor initialized successfully")
        except Exception as e:
            logger.warning(f"Could not initialize ML predictor: {e}")
            self.enable_ml = False
    
    def enhance_context_detection(
        self,
        html_content: str,
        marker_position: int,
        heuristic_context: str,
        heuristic_confidence: float
    ) -> Dict[str, Any]:
        """
        Enhance context detection with ML predictions.
        
        Args:
            html_content: HTML response content
            marker_position: Position of reflection
            heuristic_context: Context from heuristic analysis
            heuristic_confidence: Confidence from heuristics
            
        Returns:
            Enhanced context analysis with ML predictions
        """
        if not self.enable_ml or not self.predictor:
            self.fallback_count += 1
            return {
                "context": heuristic_context,
                "confidence": heuristic_confidence,
                "ml_enhanced": False,
                "prediction_source": "heuristic"
            }
        
        try:
            # Get ML prediction
            ml_result = self.predictor.predict_context(html_content, marker_position)
            self.predictions_made += 1
            
            # Compare with heuristic
            if ml_result.prediction == heuristic_context:
                # ML agrees - boost confidence
                enhanced_confidence = min(1.0, (heuristic_confidence + ml_result.confidence) / 2 + 0.1)
                self.ml_enhancements += 1
                
                return {
                    "context": ml_result.prediction,
                    "confidence": enhanced_confidence,
                    "ml_enhanced": True,
                    "prediction_source": "ml_boosted",
                    "ml_confidence": ml_result.confidence,
                    "heuristic_confidence": heuristic_confidence,
                    "confidence_level": ml_result.confidence_level.value
                }
            else:
                # ML disagrees - use higher confidence source
                if ml_result.confidence > heuristic_confidence:
                    logger.info(f"ML override: {heuristic_context} -> {ml_result.prediction}")
                    return {
                        "context": ml_result.prediction,
                        "confidence": ml_result.confidence,
                        "ml_enhanced": True,
                        "prediction_source": "ml_override",
                        "original_context": heuristic_context,
                        "confidence_level": ml_result.confidence_level.value
                    }
                else:
                    return {
                        "context": heuristic_context,
                        "confidence": heuristic_confidence,
                        "ml_enhanced": True,
                        "prediction_source": "heuristic_override",
                        "ml_suggestion": ml_result.prediction,
                        "ml_confidence": ml_result.confidence
                    }
        
        except Exception as e:
            logger.error(f"ML context prediction failed: {e}")
            self.fallback_count += 1
            return {
                "context": heuristic_context,
                "confidence": heuristic_confidence,
                "ml_enhanced": False,
                "prediction_source": "heuristic_fallback",
                "error": str(e)
            }
    
    def score_payload_effectiveness(
        self,
        payload: str,
        context: str,
        base_score: float = 0.5
    ) -> Dict[str, Any]:
        """
        Score payload effectiveness using ML.
        
        Args:
            payload: XSS payload
            context: Injection context
            base_score: Base heuristic score
            
        Returns:
            Enhanced effectiveness score
        """
        if not self.enable_ml or not self.predictor:
            return {
                "effectiveness": base_score,
                "ml_enhanced": False,
                "confidence": 0.6
            }
        
        try:
            ml_result = self.predictor.predict_payload_effectiveness(payload)
            self.predictions_made += 1
            
            # Parse effectiveness
            effectiveness_map = {
                "very_high": 0.95,
                "high": 0.75,
                "medium": 0.55,
                "low": 0.35
            }
            
            ml_score = effectiveness_map.get(ml_result.prediction, base_score)
            
            # Combine with base score (weighted average)
            combined_score = (ml_score * 0.7) + (base_score * 0.3)
            
            return {
                "effectiveness": combined_score,
                "ml_enhanced": True,
                "ml_score": ml_score,
                "base_score": base_score,
                "confidence": ml_result.confidence,
                "effectiveness_level": ml_result.prediction
            }
        
        except Exception as e:
            logger.error(f"ML payload scoring failed: {e}")
            return {
                "effectiveness": base_score,
                "ml_enhanced": False,
                "confidence": 0.6,
                "error": str(e)
            }
    
    def assess_vulnerability_severity(
        self,
        vulnerability_data: Dict[str, Any],
        heuristic_severity: str,
        heuristic_score: float
    ) -> Dict[str, Any]:
        """
        Assess vulnerability severity with ML.
        
        Args:
            vulnerability_data: Vulnerability details
            heuristic_severity: Severity from heuristics
            heuristic_score: Score from heuristics
            
        Returns:
            Enhanced severity assessment
        """
        if not self.enable_ml or not self.predictor:
            return {
                "severity": heuristic_severity,
                "score": heuristic_score,
                "ml_enhanced": False
            }
        
        try:
            ml_result = self.predictor.predict_vulnerability_severity(vulnerability_data)
            self.predictions_made += 1
            
            # Get ML severity and confidence
            ml_severity = ml_result.prediction
            ml_confidence = ml_result.confidence
            
            # Severity priority (for disagreements)
            severity_rank = {
                "critical": 4,
                "high": 3,
                "medium": 2,
                "low": 1
            }
            
            heuristic_rank = severity_rank.get(heuristic_severity, 1)
            ml_rank = severity_rank.get(ml_severity, 1)
            
            # Use higher severity if both confident
            if ml_confidence > 0.7 and heuristic_score > 0.7:
                final_severity = heuristic_severity if heuristic_rank >= ml_rank else ml_severity
                final_score = max(heuristic_score, ml_confidence)
            elif ml_confidence > heuristic_score:
                final_severity = ml_severity
                final_score = ml_confidence
            else:
                final_severity = heuristic_severity
                final_score = heuristic_score
            
            return {
                "severity": final_severity,
                "score": final_score,
                "ml_enhanced": True,
                "ml_severity": ml_severity,
                "ml_confidence": ml_confidence,
                "heuristic_severity": heuristic_severity,
                "heuristic_score": heuristic_score
            }
        
        except Exception as e:
            logger.error(f"ML severity assessment failed: {e}")
            return {
                "severity": heuristic_severity,
                "score": heuristic_score,
                "ml_enhanced": False,
                "error": str(e)
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get ML integration statistics"""
        return {
            "ml_enabled": self.enable_ml,
            "predictions_made": self.predictions_made,
            "ml_enhancements": self.ml_enhancements,
            "fallback_count": self.fallback_count,
            "enhancement_rate": (
                self.ml_enhancements / self.predictions_made 
                if self.predictions_made > 0 else 0
            )
        }
    
    def close(self):
        """Cleanup ML resources"""
        if self.predictor:
            # Cleanup predictor resources if needed
            pass
        logger.info("ML integration closed")

