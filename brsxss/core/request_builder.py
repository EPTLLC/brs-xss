#!/usr/bin/env python3

"""
BRS-XSS Universal Request Builder

Main request builder for XSS testing with various HTTP methods.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

import json
from typing import Dict, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from .request_types import RequestConfig, TestRequest, RequestMethod, PayloadLocation
from .request_auto_detector import RequestAutoDetector
from ..utils.logger import Logger

logger = Logger("core.request_builder")


class UniversalRequestBuilder:
    """
    Universal request builder for different types of XSS injection testing.
    
    Supports:
    - GET parameters
    - POST form data  
    - JSON body injection
    - Header injection
    - Cookie injection
    """
    
    def __init__(self):
        """Initialize request builder"""
        self.auto_detector = RequestAutoDetector()
        self.default_headers = {
            'User-Agent': 'BRS-XSS Scanner v1.0',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
    
    def build_request(
        self,
        base_url: str,
        param_name: str,
        payload: str,
        request_config: Optional[RequestConfig] = None,
        original_params: Optional[Dict[str, Any]] = None
    ) -> TestRequest:
        """Build universal test request with payload injection"""
        
        config = request_config or RequestConfig()
        original_params = original_params or {}
        
        headers = self.default_headers.copy()
        if config.headers:
            headers.update(config.headers)
        
        if config.method == RequestMethod.GET:
            return self._build_get_request(base_url, param_name, payload, headers, original_params)
        elif config.method == RequestMethod.POST:
            if config.content_type == "application/json":
                return self._build_json_request(base_url, param_name, payload, headers, original_params)
            else:
                return self._build_form_request(base_url, param_name, payload, headers, original_params, config)
        else:
            return self._build_get_request(base_url, param_name, payload, headers, original_params)
    
    def _build_get_request(self, base_url: str, param_name: str, payload: str, 
                          headers: Dict[str, str], original_params: Dict[str, Any]) -> TestRequest:
        """Build GET request with URL parameter injection"""
        
        parsed_url = urlparse(base_url)
        query_params = parse_qs(parsed_url.query, keep_blank_values=True)
        
        flat_params = {}
        for key, values in query_params.items():
            flat_params[key] = values[0] if values else ""
        
        flat_params.update(original_params)
        flat_params[param_name] = payload
        
        new_query = urlencode(flat_params, doseq=True)
        test_url = urlunparse((
            parsed_url.scheme, parsed_url.netloc, parsed_url.path,
            parsed_url.params, new_query, parsed_url.fragment
        ))
        
        return TestRequest(
            method="GET", url=test_url, headers=headers,
            payload_location=PayloadLocation.URL_PARAM, injected_parameter=param_name
        )
    
    def _build_form_request(self, base_url: str, param_name: str, payload: str,
                           headers: Dict[str, str], original_params: Dict[str, Any], 
                           config: RequestConfig) -> TestRequest:
        """Build POST request with form data injection"""
        
        form_data = original_params.copy()
        form_data[param_name] = payload
        headers['Content-Type'] = config.content_type
        
        if config.content_type == "application/x-www-form-urlencoded":
            data = urlencode(form_data)
        else:
            data = form_data  # type: ignore[assignment]
        
        return TestRequest(
            method="POST", url=base_url, headers=headers, data=data,
            payload_location=PayloadLocation.FORM_DATA, injected_parameter=param_name
        )
    
    def _build_json_request(self, base_url: str, param_name: str, payload: str,
                           headers: Dict[str, str], original_params: Dict[str, Any]) -> TestRequest:
        """Build POST request with JSON injection"""
        
        json_data = original_params.copy() if original_params else {}
        self._set_nested_value(json_data, param_name, payload)
        headers['Content-Type'] = 'application/json'
        
        return TestRequest(
            method="POST", url=base_url, headers=headers, data=json.dumps(json_data),
            payload_location=PayloadLocation.JSON_VALUE, injected_parameter=param_name
        )
    
    def _set_nested_value(self, data: Dict[str, Any], param_path: str, value: Any) -> None:
        """Set value in nested dictionary using dot notation"""
        
        if '.' not in param_path:
            data[param_path] = value
            return
        
        keys = param_path.split('.')
        current = data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def build_header_injection_request(self, base_url: str, header_name: str, 
                                     payload: str, method: str = "GET") -> TestRequest:
        """Build request with header injection"""
        
        headers = self.default_headers.copy()
        headers[header_name] = payload
        
        return TestRequest(
            method=method, url=base_url, headers=headers,
            payload_location=PayloadLocation.HEADER, injected_parameter=header_name
        )
    
    def build_cookie_injection_request(self, base_url: str, cookie_name: str,
                                     payload: str, method: str = "GET") -> TestRequest:
        """Build request with cookie injection"""
        
        headers = self.default_headers.copy()
        headers['Cookie'] = f"{cookie_name}={payload}"
        
        return TestRequest(
            method=method, url=base_url, headers=headers,
            payload_location=PayloadLocation.COOKIE, injected_parameter=cookie_name
        )
    
    def auto_detect_request_type(self, url: str, sample_data: Optional[Dict[str, Any]] = None) -> RequestConfig:
        """Auto-detect appropriate request configuration"""
        return self.auto_detector.auto_detect_request_type(url, sample_data)
    
    def clone_request_with_payload(self, original_request: TestRequest, new_payload: str) -> TestRequest:
        """Clone existing request with different payload"""
        
        return TestRequest(
            method=original_request.method,
            url=original_request.url.replace(
                original_request.url.split('=')[-1].split('&')[0], new_payload
            ),
            headers=original_request.headers.copy(),
            data=original_request.data,
            payload_location=original_request.payload_location,
            injected_parameter=original_request.injected_parameter
        )