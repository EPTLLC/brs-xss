#!/usr/bin/env python3

"""
BRS-XSS Request Auto Detector

Automatically detects appropriate request configuration based on URL and data.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, Any, Optional
from .request_types import RequestConfig, RequestMethod

from ..utils.logger import Logger

logger = Logger("core.request_auto_detector")


class RequestAutoDetector:
    """
    Auto-detects appropriate request configuration based on URL and data.
    
    Analyzes:
    - URL patterns (API endpoints, forms)
    - Content types
    - Sample data structure
    """
    
    def __init__(self):
        """Initialize auto detector"""
        self.api_indicators = ['/api/', '/rest/', '/graphql', '.json', '/v1/', '/v2/']
        self.form_indicators = ['/form', '/submit', '/post', '/create', '/update', '/login', '/register']
        
        logger.debug("Request auto detector initialized")
    
    def auto_detect_request_type(
        self,
        url: str,
        sample_data: Optional[Dict[str, Any]] = None
    ) -> RequestConfig:
        """
        Auto-detect appropriate request configuration.
        
        Args:
            url: Target URL
            sample_data: Sample data to analyze
            
        Returns:
            Suggested request configuration
        """
        
        url_lower = url.lower()
        
        # Check for API endpoints
        if any(indicator in url_lower for indicator in self.api_indicators):
            logger.debug(f"Detected API endpoint: {url}")
            return RequestConfig(
                method=RequestMethod.POST,
                content_type="application/json"
            )
        
        # Check for form endpoints
        if any(indicator in url_lower for indicator in self.form_indicators):
            logger.debug(f"Detected form endpoint: {url}")
            return RequestConfig(
                method=RequestMethod.POST,
                content_type="application/x-www-form-urlencoded"
            )
        
        # Analyze sample data if provided
        if sample_data:
            if self._looks_like_json_data(sample_data):
                return RequestConfig(
                    method=RequestMethod.POST,
                    content_type="application/json"
                )
        
        # Default to GET
        logger.debug(f"Using default GET method for: {url}")
        return RequestConfig(method=RequestMethod.GET)
    
    def _looks_like_json_data(self, data: Dict[str, Any]) -> bool:
        """Check if data structure suggests JSON API"""
        
        # Check for nested structures
        has_nested = any(isinstance(v, (dict, list)) for v in data.values())
        
        # Check for typical API field names
        api_fields = ['id', 'uuid', 'created_at', 'updated_at', 'data', 'payload', 'params']
        has_api_fields = any(field in data for field in api_fields)
        
        return has_nested or has_api_fields
    
    def suggest_content_type(self, data: Any) -> str:
        """Suggest content type based on data"""
        
        if isinstance(data, dict):
            return "application/json"
        elif isinstance(data, str) and data.startswith('{'):
            return "application/json"
        elif isinstance(data, bytes):
            return "application/octet-stream"
        else:
            return "application/x-www-form-urlencoded"
    
    def detect_injection_points(self, url: str, data: Optional[Dict[str, Any]] = None) -> list:
        """Detect potential injection points"""
        
        injection_points = []
        
        # URL parameters
        if '?' in url:
            injection_points.append("url_parameters")
        
        # Form data
        if data:
            injection_points.append("form_data")
            
            # JSON fields
            if isinstance(data, dict):
                injection_points.append("json_fields")
        
        # Common header injection points
        injection_points.extend(["user_agent", "referer", "x_forwarded_for"])
        
        return injection_points