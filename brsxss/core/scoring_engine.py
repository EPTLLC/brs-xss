#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 13:11:55 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, Any, Optional, List
from dataclasses import asdict

from .scoring_types import ScoringResult, SeverityLevel, ScoringWeights
from .impact_calculator import ImpactCalculator
from .exploitability_calculator import ExploitabilityCalculator
from .context_calculator import ContextCalculator
from .confidence_calculator import ConfidenceCalculator
from .risk_analyzer import RiskAnalyzer
from ..utils.logger import Logger
from .config_manager import ConfigManager

logger = Logger("core.scoring_engine")


class ScoringEngine:
    """Calculates vulnerability score based on multiple factors"""
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """Initialize scoring engine"""
        self.config = config or ConfigManager()
        
        # Component calculators
        self.impact_calculator = ImpactCalculator(self.config)
        self.exploitability_calculator = ExploitabilityCalculator(self.config)
        self.context_calculator = ContextCalculator(self.config)
        self.confidence_calculator = ConfidenceCalculator(self.config)

        # Define the weights for combining component scores (validated dataclass)
        default_weights = {
            'impact': 0.4,
            'exploitability': 0.4,
            'context': 0.2,
            'reflection': 0.0,
        }
        configured = self.config.get('scoring.weights', default_weights)
        if isinstance(configured, dict):
            merged = {**default_weights, **configured}
            self.weights = ScoringWeights(
                impact=float(merged.get('impact', 0.4)),
                exploitability=float(merged.get('exploitability', 0.4)),
                context=float(merged.get('context', 0.2)),
                reflection=float(merged.get('reflection', 0.0)),
            )
        elif isinstance(configured, ScoringWeights):
            self.weights = configured
        else:
            self.weights = ScoringWeights(**default_weights)
        
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
        Calculates a score by combining assessments from specialized calculators.
        """
        self.total_assessments += 1
        logger.debug(f"Scoring vulnerability for payload: {payload[:50]}...")

        # 1. Component Scores (all scaled 0.0 - 1.0)
        impact = self.impact_calculator.calculate_impact_score(context_info, payload)
        exploitability = self.exploitability_calculator.calculate_exploitability_score(reflection_result)
        context = self.context_calculator.calculate_context_score(context_info)

        # 2. Weighted Average
        w = self.weights
        score = (
            (impact * w.impact) +
            (exploitability * w.exploitability) +
            (context * w.context)
        )
        
        # 3. Final Score & Severity (scaled to 0-10)
        final_score = min(score * 10.0, 10.0)
        severity = self._determine_severity(final_score)

        # 4. Confidence Score
        confidence = self.confidence_calculator.calculate_confidence(
            reflection_result, context_info, payload
        )

        logger.info(f"Vulnerability scored: {final_score:.2f} ({severity.value})")
        
        return ScoringResult(
            score=round(final_score, 2),
            severity=severity,
            confidence=round(confidence, 3),
            exploitation_likelihood=round(exploitability, 3),
            impact_score=round(impact, 2),
            context_score=round(context, 2),
            recommendations=self._get_recommendations(severity)
        )

    def _get_recommendations(self, severity: SeverityLevel) -> List[str]:
        """Get remediation advice based on severity."""
        if severity == SeverityLevel.CRITICAL:
            return [
                "Review and fix vulnerable code immediately",
                "Implement immediate input validation and sanitization",
                "Deploy Content Security Policy (CSP) with strict directives"
            ]
        elif severity == SeverityLevel.HIGH:
            return [
                "Prioritize fixing this vulnerability within the next sprint",
                "Apply context-specific output encoding (e.g., HTML, URL, JavaScript)",
                "Use a trusted, well-maintained library for sanitization"
            ]
        elif severity == SeverityLevel.MEDIUM:
            return [
                "Schedule a code review to identify similar issues",
                "Validate and sanitize all user input",
                "Implement proper HTML entity encoding"
            ]
        else: # LOW
            return [
                "Keep web application frameworks updated",
                "Perform regular security testing and code reviews",
                "Train developers on secure coding practices"
            ]
            
    def _determine_severity(self, score: float) -> SeverityLevel:
        """Determine severity level from a score (0-10)"""
        if score >= 9.5:
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