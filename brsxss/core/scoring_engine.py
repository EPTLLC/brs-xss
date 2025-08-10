#!/usr/bin/env python3

"""
BRS-XSS Scoring Engine

Main orchestrator for vulnerability scoring system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, Any

from .scoring_types import ScoringResult, ScoringWeights, SeverityLevel
from .impact_calculator import ImpactCalculator
from .exploitability_calculator import ExploitabilityCalculator
from .context_calculator import ContextCalculator
from .reflection_calculator import ReflectionCalculator
from .confidence_calculator import ConfidenceCalculator
from .risk_analyzer import RiskAnalyzer
from ..utils.logger import Logger

logger = Logger("core.scoring_engine")


class ScoringEngine:
    """
    Main vulnerability scoring and risk assessment engine.
    
    Orchestrates multiple specialized calculators to provide
    comprehensive vulnerability assessment.
    """
    
    def __init__(self, weights: ScoringWeights = None):
        """
        Initialize scoring engine.
        
        Args:
            weights: Custom scoring weights
        """
        self.weights = weights or ScoringWeights()
        
        # Initialize calculators
        self.impact_calculator = ImpactCalculator()
        self.exploitability_calculator = ExploitabilityCalculator()
        self.context_calculator = ContextCalculator()
        self.reflection_calculator = ReflectionCalculator()
        self.confidence_calculator = ConfidenceCalculator()
        self.risk_analyzer = RiskAnalyzer()
        
        # Statistics
        self.total_assessments = 0
        self.vulnerability_counts = {level: 0 for level in SeverityLevel}
        
        logger.info("Scoring engine initialized")
    
    def score_vulnerability(
        self,
        payload: str,
        reflection_result: Any,
        context_info: Dict[str, Any],
        response: Any = None
    ) -> ScoringResult:
        """
        Score vulnerability based on multiple factors.
        
        Args:
            payload: XSS payload
            reflection_result: Reflection analysis result
            context_info: Context information
            response: HTTP response (optional)
            
        Returns:
            Comprehensive scoring result
        """
        self.total_assessments += 1
        
        logger.debug(f"Scoring vulnerability for payload: {payload[:50]}...")
        
        # Calculate component scores
        impact_score = self.impact_calculator.calculate_impact_score(
            context_info, payload
        )
        
        exploitability_score = self.exploitability_calculator.calculate_exploitability_score(
            payload, reflection_result, context_info
        )
        
        context_score = self.context_calculator.calculate_context_score(context_info)
        
        reflection_score = self.reflection_calculator.calculate_reflection_score(
            reflection_result
        )
        
        # Calculate overall score using weights
        overall_score = (
            impact_score * self.weights.impact +
            exploitability_score * self.weights.exploitability +
            context_score * self.weights.context +
            reflection_score * self.weights.reflection
        )
        
        # Determine severity level
        severity = self._determine_severity(overall_score)
        
        # Calculate confidence
        confidence = self.confidence_calculator.calculate_confidence(
            reflection_result, context_info, payload
        )
        
        # Analyze risks and generate recommendations
        risk_factors = self.risk_analyzer.identify_risk_factors(
            context_info, payload, reflection_result
        )
        
        mitigating_factors = self.risk_analyzer.identify_mitigating_factors(
            context_info, response
        )
        
        recommendations = self.risk_analyzer.generate_recommendations(
            severity, context_info, risk_factors, mitigating_factors
        )
        
        # Create comprehensive result
        result = ScoringResult(
            score=round(overall_score, 2),
            severity=severity,
            confidence=round(confidence, 3),
            impact_score=round(impact_score, 2),
            exploitability_score=round(exploitability_score, 2),
            context_score=round(context_score, 2),
            reflection_score=round(reflection_score, 2),
            risk_factors=risk_factors,
            mitigating_factors=mitigating_factors,
            recommendations=recommendations
        )
        
        # Update statistics
        self.vulnerability_counts[severity] += 1
        
        logger.info(f"Vulnerability scored: {overall_score:.2f} ({severity.value})")
        
        return result
    
    def _determine_severity(self, score: float) -> SeverityLevel:
        """
        Determine severity level based on score.
        
        Args:
            score: Overall vulnerability score (0-10)
            
        Returns:
            Severity level
        """
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        elif score >= 7.0:
            return SeverityLevel.HIGH
        elif score >= 4.0:
            return SeverityLevel.MEDIUM
        elif score >= 1.0:
            return SeverityLevel.LOW
        elif score > 0.0:
            return SeverityLevel.INFO
        else:
            return SeverityLevel.NONE
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get scoring engine statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            'total_assessments': self.total_assessments,
            'vulnerability_counts': {
                level.value: count 
                for level, count in self.vulnerability_counts.items()
            },
            'weights': {
                'impact': self.weights.impact,
                'exploitability': self.weights.exploitability,
                'context': self.weights.context,
                'reflection': self.weights.reflection
            }
        }
    
    def reset_statistics(self):
        """Reset scoring statistics"""
        self.total_assessments = 0
        self.vulnerability_counts = {level: 0 for level in SeverityLevel}
        logger.info("Scoring statistics reset")
    
    def update_weights(self, weights: ScoringWeights):
        """
        Update scoring weights.
        
        Args:
            weights: New scoring weights
        """
        self.weights = weights
        logger.info(f"Scoring weights updated: {weights}")
    
    def bulk_score_vulnerabilities(
        self, 
        vulnerability_data: list
    ) -> list:
        """
        Score multiple vulnerabilities efficiently.
        
        Args:
            vulnerability_data: List of vulnerability data dicts
            
        Returns:
            List of scoring results
        """
        results = []
        
        logger.info(f"Bulk scoring {len(vulnerability_data)} vulnerabilities")
        
        for i, vuln_data in enumerate(vulnerability_data):
            try:
                result = self.score_vulnerability(
                    payload=vuln_data['payload'],
                    reflection_result=vuln_data['reflection_result'],
                    context_info=vuln_data['context_info'],
                    response=vuln_data.get('response')
                )
                results.append(result)
                
                if (i + 1) % 10 == 0:
                    logger.debug(f"Processed {i + 1}/{len(vulnerability_data)} vulnerabilities")
                    
            except Exception as e:
                logger.error(f"Error scoring vulnerability {i}: {e}")
                # Continue with next vulnerability
                continue
        
        logger.info(f"Bulk scoring completed: {len(results)} results")
        return results