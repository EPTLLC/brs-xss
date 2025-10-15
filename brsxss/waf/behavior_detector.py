#!/usr/bin/env python3

"""
BRS-XSS WAF Behavior Detector

WAF detection based on behavioral analysis.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Dict, Any, Optional
from .waf_types import WAFType, WAFInfo
from ..utils.logger import Logger

logger = Logger("waf.behavior_detector")


class BehaviorDetector:
    """Detects WAF based on behavioral patterns"""
    
    def __init__(self):
        """Initialize behavior detector"""
        self.request_history = []
        self.timing_history = []
        
    def analyze_response_behavior(
        self,
        responses: List[Any],
        timing_data: List[float]
    ) -> Optional[WAFInfo]:
        """
        Analyze behavioral patterns in responses.
        
        Args:
            responses: List of HTTP responses
            timing_data: List of response times
            
        Returns:
            WAF information if behavioral patterns detected
        """
        if len(responses) < 3:
            return None
        
        behavior_analysis = {
            'consistent_blocking': self._analyze_consistent_blocking(responses),
            'rate_limiting': self._analyze_rate_limiting(responses, timing_data),
            'response_time_patterns': self._analyze_timing_patterns(timing_data),
            'status_code_patterns': self._analyze_status_patterns(responses),
            'content_length_patterns': self._analyze_content_patterns(responses)
        }
        
        # Determine if behavior indicates WAF presence
        confidence = self._calculate_behavior_confidence(behavior_analysis)
        
        if confidence > 0.6:
            return WAFInfo(
                waf_type=WAFType.UNKNOWN,
                name="Behavioral WAF Detection",
                confidence=confidence,
                detection_method="behavioral_analysis",
                detected_features=self._extract_behavioral_features(behavior_analysis),
                # additional_info removed - not supported by WAFInfo
            )
        
        return None
    
    def _analyze_consistent_blocking(self, responses: List[Any]) -> Dict[str, Any]:
        """Analyze consistent blocking patterns"""
        status_codes = [response.status_code for response in responses]
        
        blocking_codes = [403, 406, 409, 501, 503]
        blocking_count = sum(1 for code in status_codes if code in blocking_codes)
        
        return {
            'blocking_rate': blocking_count / len(responses),
            'common_blocking_code': max(set(status_codes), key=status_codes.count),
            'is_consistent': blocking_count > len(responses) * 0.7
        }
    
    def _analyze_rate_limiting(self, responses: List[Any], timing_data: List[float]) -> Dict[str, Any]:
        """Analyze rate limiting patterns"""
        status_codes = [response.status_code for response in responses]
        
        # Check for 429 (Too Many Requests) or similar
        rate_limit_codes = [429, 503, 509]
        rate_limit_count = sum(1 for code in status_codes if code in rate_limit_codes)
        
        # Analyze timing patterns
        avg_response_time = sum(timing_data) / len(timing_data) if timing_data else 0
        time_variance = self._calculate_variance(timing_data) if len(timing_data) > 1 else 0
        
        return {
            'rate_limit_detected': rate_limit_count > 0,
            'rate_limit_percentage': rate_limit_count / len(responses),
            'avg_response_time': avg_response_time,
            'timing_variance': time_variance,
            'suspicious_delays': avg_response_time > 2.0  # Artificial delays
        }
    
    def _analyze_timing_patterns(self, timing_data: List[float]) -> Dict[str, Any]:
        """Analyze response timing patterns"""
        if not timing_data:
            return {}
        
        avg_time = sum(timing_data) / len(timing_data)
        min_time = min(timing_data)
        max_time = max(timing_data)
        
        # Check for artificial delays
        artificial_delay_threshold = 1.0
        artificial_delays = sum(1 for t in timing_data if t > artificial_delay_threshold)
        
        return {
            'avg_response_time': avg_time,
            'min_response_time': min_time,
            'max_response_time': max_time,
            'timing_variance': self._calculate_variance(timing_data),
            'artificial_delays_count': artificial_delays,
            'has_artificial_delays': artificial_delays > 0
        }
    
    def _analyze_status_patterns(self, responses: List[Any]) -> Dict[str, Any]:
        """Analyze HTTP status code patterns"""
        status_codes = [response.status_code for response in responses]
        status_distribution: Dict[int, int] = {}
        
        for code in status_codes:
            status_distribution[code] = status_distribution.get(code, 0) + 1
        
        # Analyze patterns
        unique_codes = len(set(status_codes))
        most_common_code = max(set(status_codes), key=status_codes.count)
        
        return {
            'status_distribution': status_distribution,
            'unique_status_codes': unique_codes,
            'most_common_status': most_common_code,
            'has_blocking_codes': any(code in [403, 406, 409, 501] for code in status_codes),
            'status_consistency': status_distribution[most_common_code] / len(status_codes)
        }
    
    def _analyze_content_patterns(self, responses: List[Any]) -> Dict[str, Any]:
        """Analyze response content patterns"""
        content_lengths = []
        content_types = []
        
        for response in responses:
            if hasattr(response, 'content'):
                content_lengths.append(len(response.content))
            
            content_type = response.headers.get('content-type', '').lower()
            content_types.append(content_type)
        
        return {
            'content_lengths': content_lengths,
            'avg_content_length': sum(content_lengths) / len(content_lengths) if content_lengths else 0,
            'content_types': list(set(content_types)),
            'consistent_content_type': len(set(content_types)) == 1,
            'has_empty_responses': 0 in content_lengths
        }
    
    def _calculate_variance(self, data: List[float]) -> float:
        """Calculate variance of timing data"""
        if len(data) < 2:
            return 0.0
        
        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        return variance
    
    def _calculate_behavior_confidence(self, behavior_analysis: Dict[str, Any]) -> float:
        """Calculate confidence based on behavioral analysis"""
        confidence = 0.0
        
        # Consistent blocking increases confidence
        blocking_data = behavior_analysis.get('consistent_blocking', {})
        if blocking_data.get('is_consistent', False):
            confidence += 0.3
        
        # Rate limiting detection
        rate_limit_data = behavior_analysis.get('rate_limiting', {})
        if rate_limit_data.get('rate_limit_detected', False):
            confidence += 0.4
        
        # Artificial delays
        timing_data = behavior_analysis.get('response_time_patterns', {})
        if timing_data.get('has_artificial_delays', False):
            confidence += 0.2
        
        # Status code patterns
        status_data = behavior_analysis.get('status_code_patterns', {})
        if status_data.get('has_blocking_codes', False):
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _extract_behavioral_features(self, behavior_analysis: Dict[str, Any]) -> List[str]:
        """Extract behavioral features for detection"""
        features = []
        
        blocking_data = behavior_analysis.get('consistent_blocking', {})
        if blocking_data.get('is_consistent', False):
            features.append("consistent_blocking")
        
        rate_limit_data = behavior_analysis.get('rate_limiting', {})
        if rate_limit_data.get('rate_limit_detected', False):
            features.append("rate_limiting")
        
        timing_data = behavior_analysis.get('response_time_patterns', {})
        if timing_data.get('has_artificial_delays', False):
            features.append("artificial_delays")
        
        status_data = behavior_analysis.get('status_code_patterns', {})
        if status_data.get('has_blocking_codes', False):
            features.append("blocking_status_codes")
        
        return features
    
    def detect_geo_blocking(self, responses: List[Any]) -> Dict[str, Any]:
        """Detect geographical blocking patterns"""
        geo_analysis: Dict[str, Any] = {
            'likely_geo_blocked': False,
            'geo_indicators': [],
            'confidence': 0.0
        }
        
        for response in responses:
            content = getattr(response, 'text', '').lower()
            
            # Check for geo-blocking indicators
            geo_indicators = [
                'location', 'country', 'region', 'geographic',
                'not available in your', 'restricted region',
                'blocked in your country', 'geo-restricted'
            ]
            
            for indicator in geo_indicators:
                if indicator in content:
                    geo_analysis['geo_indicators'].append(indicator)
                    geo_analysis['likely_geo_blocked'] = True
        
        if geo_analysis['likely_geo_blocked']:
            geo_analysis['confidence'] = min(len(geo_analysis['geo_indicators']) * 0.3, 1.0)
        
        return geo_analysis
    
    def analyze_progressive_blocking(self, responses: List[Any]) -> Dict[str, Any]:
        """Analyze progressive blocking patterns"""
        progressive_analysis: Dict[str, Any] = {
            'has_progressive_blocking': False,
            'blocking_escalation': [],
            'pattern_detected': False
        }
        
        status_codes = [response.status_code for response in responses]
        
        # Look for escalating blocking pattern
        # e.g., 200 -> 403 -> 503 or similar escalation
        escalation_patterns = [
            [200, 403],  # Normal -> Forbidden
            [200, 503],  # Normal -> Service Unavailable
            [403, 503],  # Forbidden -> Service Unavailable
            [200, 429],  # Normal -> Rate Limited
        ]
        
        for i in range(len(status_codes) - 1):
            current_code = status_codes[i]
            next_code = status_codes[i + 1]
            
            for pattern in escalation_patterns:
                if [current_code, next_code] == pattern:
                    progressive_analysis['blocking_escalation'].append((current_code, next_code))
                    progressive_analysis['has_progressive_blocking'] = True
        
        progressive_analysis['pattern_detected'] = len(progressive_analysis['blocking_escalation']) > 0
        
        return progressive_analysis