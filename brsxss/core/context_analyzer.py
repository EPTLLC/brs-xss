#!/usr/bin/env python3

"""
BRS-XSS Context Analyzer

Main orchestrator for context analysis system.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, List, Optional, Any

from .context_types import ContextType, InjectionPoint, ContextAnalysisResult
from .html_context_detector import HTMLContextDetector
from .javascript_context_detector import JavaScriptContextDetector
from .css_context_detector import CSSContextDetector
from .filter_detector import FilterDetector
from ..utils.logger import Logger

logger = Logger("core.context_analyzer")


class ContextAnalyzer:
    """
    Main context analyzer for XSS vulnerability detection.
    
    Orchestrates multiple specialized detectors to provide
    context analysis.
    """
    
    def __init__(self):
        """Initialize context analyzer"""
        # Initialize specialized detectors
        self.html_detector = HTMLContextDetector()
        self.js_detector = JavaScriptContextDetector()
        self.css_detector = CSSContextDetector()
        self.filter_detector = FilterDetector()
        
        # Analysis cache
        self.analyzed_contexts = {}
        
        # Statistics
        self.analysis_count = 0
        self.context_stats = {context.value: 0 for context in ContextType}
        
        logger.info("Context analyzer initialized")
    
    def analyze_context(
        self,
        parameter_name: str,
        parameter_value: str,
        html_response: str,
        original_request: Optional[str] = None
    ) -> ContextAnalysisResult:
        """
        Analyze injection context for given parameter.
        
        Args:
            parameter_name: Name of the parameter
            parameter_value: Value of the parameter (marker)
            html_response: HTML response content
            original_request: Original request (optional)
            
        Returns:
            context analysis result
        """
        self.analysis_count += 1
        
        logger.debug(f"Analyzing context for parameter: {parameter_name}")
        
        # Find all injection points
        injection_points = self._find_injection_points(
            parameter_name, parameter_value, html_response
        )
        
        if not injection_points:
            logger.info(f"No injection points found for {parameter_name}")
            return self._create_empty_result(parameter_name, parameter_value)
        
        # Determine primary context
        primary_context = self._determine_primary_context(injection_points)
        
        # Generate recommendations
        payload_recommendations = self._generate_payload_recommendations(injection_points)
        bypass_recommendations = self._generate_bypass_recommendations(injection_points)
        
        # Create result
        result = ContextAnalysisResult(
            parameter_name=parameter_name,
            parameter_value=parameter_value,
            injection_points=injection_points,
            primary_context=primary_context,
            payload_recommendations=payload_recommendations,
            bypass_recommendations=bypass_recommendations
        )
        
        # Update statistics
        self._update_statistics(injection_points)
        
        logger.info(f"Analysis complete: {len(injection_points)} injection points found")
        return result
    
    def _find_injection_points(
        self,
        param_name: str,
        param_value: str,
        html_content: str
    ) -> List[InjectionPoint]:
        """Find all injection points for the parameter value"""
        injection_points = []
        
        # Find all occurrences of the parameter value
        search_pos = 0
        while True:
            marker_pos = html_content.find(param_value, search_pos)
            if marker_pos == -1:
                break
            
            # Analyze context at this position
            injection_point = self._analyze_single_injection_point(
                param_name, param_value, html_content, marker_pos
            )
            
            if injection_point:
                injection_points.append(injection_point)
            
            search_pos = marker_pos + len(param_value)
        
        logger.debug(f"Found {len(injection_points)} injection points")
        return injection_points
    
    def _analyze_single_injection_point(
        self,
        param_name: str,
        param_value: str,
        html_content: str,
        marker_pos: int
    ) -> Optional[InjectionPoint]:
        """Analyze a single injection point"""
        
        # Determine context type using specialized detectors
        context_type = self._determine_context_type(html_content, marker_pos, param_value)
        
        # Extract context-specific information
        context_info = self._extract_context_info(
            html_content, marker_pos, param_value, context_type
        )
        
        # Detect filters and encoding
        surrounding_content = self._get_surrounding_content(
            html_content, marker_pos, param_value
        )
        
        filters = self.filter_detector.detect_filters(param_value, surrounding_content)
        encoding = self.filter_detector.detect_encoding(surrounding_content)
        
        # Create injection point
        injection_point = InjectionPoint(
            parameter_name=param_name,
            parameter_value=param_value,
            context_type=context_type,
            surrounding_code=surrounding_content,
            tag_name=context_info.get('tag_name', ''),
            attribute_name=context_info.get('attribute_name', ''),
            quote_char=context_info.get('quote_char', ''),
            filters_detected=filters,
            encoding_detected=encoding,
            position=marker_pos
        )
        
        return injection_point
    
    def _determine_context_type(
        self,
        html_content: str,
        marker_pos: int,
        marker: str
    ) -> ContextType:
        """Determine context type using specialized detectors"""
        
        # Check JavaScript context first (most specific)
        if self.js_detector.is_in_script_tag(html_content, marker_pos):
            return self.js_detector.detect_js_context(html_content, marker_pos, marker)
        
        # Check CSS context
        css_context = self.css_detector.detect_css_context(html_content, marker_pos, marker)
        if css_context != ContextType.UNKNOWN:
            return css_context
        
        # Check HTML context
        return self.html_detector.detect_html_context(html_content, marker_pos, marker)
    
    def _extract_context_info(
        self,
        html_content: str,
        marker_pos: int,
        marker: str,
        context_type: ContextType
    ) -> Dict[str, Any]:
        """Extract context-specific information"""
        context_info = {}
        
        if context_type in [ContextType.HTML_CONTENT, ContextType.HTML_ATTRIBUTE, ContextType.HTML_COMMENT]:
            # HTML context information
            context_info['tag_name'] = self.html_detector.extract_tag_name(html_content, marker_pos)
            context_info['attribute_name'] = self.html_detector.extract_attribute_name(
                html_content, marker_pos, marker
            )
            context_info['quote_char'] = self.html_detector.detect_quote_character(
                html_content, marker_pos, marker
            )
            
        elif context_type in [ContextType.JAVASCRIPT, ContextType.JS_STRING, ContextType.JS_OBJECT]:
            # JavaScript context information
            context_info['quote_char'] = self.js_detector.detect_js_quote_character(
                html_content, marker_pos, marker
            )
            js_details = self.js_detector.analyze_js_context_details(
                html_content, marker_pos, marker
            )
            context_info.update(js_details)
            
        elif context_type == ContextType.CSS_STYLE:
            # CSS context information
            css_details = self.css_detector.analyze_css_context_details(
                html_content, marker_pos, marker
            )
            context_info.update(css_details)
        
        return context_info
    
    def _get_surrounding_content(
        self,
        html_content: str,
        marker_pos: int,
        marker: str,
        radius: int = 200
    ) -> str:
        """Get surrounding content around marker"""
        start = max(0, marker_pos - radius)
        end = min(len(html_content), marker_pos + len(marker) + radius)
        
        return html_content[start:end]
    
    def _determine_primary_context(self, injection_points: List[InjectionPoint]) -> ContextType:
        """Determine primary context from injection points"""
        if not injection_points:
            return ContextType.UNKNOWN
        
        # Priority order for context types
        priority_order = [
            ContextType.JAVASCRIPT,
            ContextType.JS_STRING,
            ContextType.JS_OBJECT,
            ContextType.HTML_CONTENT,
            ContextType.HTML_ATTRIBUTE,
            ContextType.CSS_STYLE,
            ContextType.HTML_COMMENT,
            ContextType.JSON_VALUE,
            ContextType.URL_PARAMETER,
            ContextType.XML_CONTENT,
            ContextType.UNKNOWN
        ]
        
        # Find highest priority context
        found_contexts = {ip.context_type for ip in injection_points}

        for context_type in priority_order:
            if context_type in found_contexts:
                # Group JS sub-contexts under the main JAVASCRIPT context
                if context_type in [ContextType.JS_STRING, ContextType.JS_OBJECT]:
                    return ContextType.JAVASCRIPT
                return context_type
        
        return injection_points[0].context_type
    
    def _generate_payload_recommendations(self, injection_points: List[InjectionPoint]) -> List[str]:
        """Generate payload recommendations based on injection points"""
        recommendations = []
        
        for injection_point in injection_points:
            context_type = injection_point.context_type
            
            if context_type == ContextType.HTML_CONTENT:
                recommendations.extend([
                    "Use standard HTML tags: <script>alert(1)</script>",
                    "Try event handlers: <img src=x onerror=alert(1)>",
                    "Consider SVG payloads: <svg onload=alert(1)>"
                ])
            
            elif context_type == ContextType.HTML_ATTRIBUTE:
                recommendations.extend([
                    f"Break out with quote: {injection_point.quote_char}><script>alert(1)</script>",
                    "Use event handlers within attributes",
                    "Try javascript: protocol"
                ])
            
            elif context_type in [ContextType.JAVASCRIPT, ContextType.JS_STRING]:
                js_recommendations = self.js_detector.get_js_payload_recommendations(
                    {'quote_char': injection_point.quote_char},
                    injection_point.quote_char
                )
                recommendations.extend(js_recommendations)
            
            elif context_type == ContextType.CSS_STYLE:
                css_recommendations = self.css_detector.get_css_payload_recommendations({})
                recommendations.extend(css_recommendations)
        
        # Remove duplicates
        return list(set(recommendations))
    
    def _generate_bypass_recommendations(self, injection_points: List[InjectionPoint]) -> List[str]:
        """Generate bypass recommendations based on detected filters"""
        bypass_recommendations = []
        
        all_filters = []
        for injection_point in injection_points:
            all_filters.extend(injection_point.filters_detected)
        
        if all_filters:
            filter_recommendations = self.filter_detector.get_filter_recommendations(all_filters)
            bypass_recommendations.extend(filter_recommendations)
        
        return list(set(bypass_recommendations))
    
    def _create_empty_result(self, param_name: str, param_value: str) -> ContextAnalysisResult:
        """Create empty result when no injection points found"""
        return ContextAnalysisResult(
            parameter_name=param_name,
            parameter_value=param_value,
            injection_points=[],
            primary_context=ContextType.UNKNOWN,
            payload_recommendations=["No injection points found - parameter may be filtered"],
            bypass_recommendations=["Try alternative parameter names or values"]
        )
    
    def _update_statistics(self, injection_points: List[InjectionPoint]):
        """Update analysis statistics"""
        for injection_point in injection_points:
            context_type = injection_point.context_type
            if context_type.value in self.context_stats:
                self.context_stats[context_type.value] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        return {
            'total_analyses': self.analysis_count,
            'context_distribution': self.context_stats.copy(),
            'cached_analyses': len(self.analyzed_contexts)
        }
    
    def reset_statistics(self):
        """Reset analysis statistics"""
        self.analysis_count = 0
        self.context_stats = {context.value: 0 for context in ContextType}
        self.analyzed_contexts.clear()
        logger.info("Context analysis statistics reset")
    
    def analyze_multiple_parameters(
        self,
        parameters: Dict[str, str],
        html_response: str
    ) -> Dict[str, ContextAnalysisResult]:
        """
        Analyze multiple parameters efficiently.
        
        Args:
            parameters: Dictionary of parameter names to values
            html_response: HTML response content
            
        Returns:
            Dictionary of parameter names to analysis results
        """
        results = {}
        
        logger.info(f"Analyzing {len(parameters)} parameters")
        
        for param_name, param_value in parameters.items():
            try:
                result = self.analyze_context(param_name, param_value, html_response)
                results[param_name] = result
                
            except Exception as e:
                logger.error(f"Error analyzing parameter {param_name}: {e}")
                results[param_name] = self._create_empty_result(param_name, param_value)
        
        logger.info(f"Batch analysis completed: {len(results)} results")
        return results