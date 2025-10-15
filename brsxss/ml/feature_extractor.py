#!/usr/bin/env python3

"""
BRS-XSS Feature Extractor

Feature extraction for machine learning models.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, Any


class FeatureExtractor:
    """Feature extractor for ML"""
    
    @staticmethod
    def extract_context_features(html_content: str, marker_position: int) -> Dict[str, Any]:
        """
        Extract context features.
        
        Args:
            html_content: HTML content
            marker_position: Marker position
            
        Returns:
            Feature dictionary
        """
        features = {}
        
        # Surrounding context (50 chars before and after)
        start_pos = max(0, marker_position - 50)
        end_pos = min(len(html_content), marker_position + 50)
        surrounding_text = html_content[start_pos:end_pos].lower()
        
        # HTML structure features
        features['has_script_tag'] = '<script' in surrounding_text
        features['has_img_tag'] = '<img' in surrounding_text
        features['has_input_tag'] = '<input' in surrounding_text
        features['has_form_tag'] = '<form' in surrounding_text
        features['has_div_tag'] = '<div' in surrounding_text
        
        # Attribute features
        features['in_href_attr'] = 'href=' in surrounding_text
        features['in_src_attr'] = 'src=' in surrounding_text
        features['in_onclick_attr'] = 'onclick=' in surrounding_text
        features['in_onload_attr'] = 'onload=' in surrounding_text
        features['in_onerror_attr'] = 'onerror=' in surrounding_text
        
        # JavaScript features
        features['in_javascript'] = any(js_keyword in surrounding_text for js_keyword in [
            'function', 'var ', 'let ', 'const ', 'document.', 'window.', 'alert('
        ])
        
        # CSS features
        features['in_css'] = any(css_keyword in surrounding_text for css_keyword in [
            'style=', 'background:', 'color:', 'font-', '{', '}'
        ])
        
        # Comment features
        features['in_html_comment'] = '<!--' in surrounding_text
        features['in_js_comment'] = '//' in surrounding_text or '/*' in surrounding_text
        
        # Quotes and brackets
        features['has_single_quote'] = "'" in surrounding_text
        features['has_double_quote'] = '"' in surrounding_text
        features['has_brackets'] = any(bracket in surrounding_text for bracket in ['(', ')', '[', ']', '{', '}'])
        
        # Special characters
        features['has_angle_brackets'] = '<' in surrounding_text or '>' in surrounding_text
        features['has_equals'] = '=' in surrounding_text
        features['has_semicolon'] = ';' in surrounding_text
        
        return features
    
    @staticmethod
    def extract_payload_features(payload: str) -> Dict[str, Any]:
        """
        Extract payload features.
        
        Args:
            payload: Payload to analyze
            
        Returns:
            Feature dictionary
        """
        features = {}
        payload_lower = payload.lower()
        
        # Basic characteristics
        features['length'] = len(payload)
        features['word_count'] = len(payload.split())
        features['char_diversity'] = len(set(payload)) / len(payload) if payload else 0  # type: ignore[assignment]
        
        # HTML tags
        features['has_script_tag'] = '<script' in payload_lower
        features['has_img_tag'] = '<img' in payload_lower
        features['has_svg_tag'] = '<svg' in payload_lower
        features['has_iframe_tag'] = '<iframe' in payload_lower
        features['has_object_tag'] = '<object' in payload_lower
        
        # JavaScript functions
        js_functions = ['alert', 'confirm', 'prompt', 'eval', 'settimeout', 'setinterval']
        for func in js_functions:
            features[f'has_{func}'] = func in payload_lower
        
        # Event handlers
        event_handlers = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus']
        for event in event_handlers:
            features[f'has_{event}'] = event in payload_lower
        
        # Protocols
        features['has_javascript_protocol'] = 'javascript:' in payload_lower
        features['has_data_protocol'] = 'data:' in payload_lower
        features['has_vbscript_protocol'] = 'vbscript:' in payload_lower
        
        # Encoding
        features['has_url_encoding'] = '%' in payload
        features['has_html_entities'] = '&' in payload and ';' in payload
        features['has_unicode_escape'] = '\\u' in payload
        features['has_hex_escape'] = '\\x' in payload
        
        # Obfuscation
        features['has_string_concat'] = '+' in payload and ('"' in payload or "'" in payload)
        features['has_char_codes'] = 'fromcharcode' in payload_lower
        features['has_eval_usage'] = 'eval(' in payload_lower
        
        # Special characters
        special_chars = ['<', '>', '"', "'", '(', ')', '{', '}', '[', ']', ';', '=']
        for char in special_chars:
            features[f'has_{char.replace("<", "lt").replace(">", "gt")}'] = char in payload
        
        return features
    
    @staticmethod
    def extract_waf_features(response_headers: Dict[str, str], response_content: str, status_code: int) -> Dict[str, Any]:
        """
        Extract features for WAF classification.
        
        Args:
            response_headers: HTTP headers
            response_content: Response content
            status_code: Status code
            
        Returns:
            Feature dictionary
        """
        features = {}
        
        # Headers (normalized)
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        
        # Status code
        features['status_code'] = status_code
        features['is_error_status'] = status_code >= 400
        features['is_forbidden'] = status_code == 403
        features['is_not_acceptable'] = status_code == 406
        
        # WAF-specific headers
        waf_headers = [
            'server', 'x-powered-by', 'x-waf', 'x-sucuri-id', 'cf-ray',
            'x-akamai-request-id', 'x-iinfo', 'incap_ses'
        ]
        
        for header in waf_headers:
            features[f'has_header_{header.replace("-", "_")}'] = header in headers_lower
        
        # Content analysis
        content_lower = response_content.lower()
        
        # WAF signatures in content
        waf_signatures = [
            'cloudflare', 'incapsula', 'sucuri', 'akamai', 'barracuda',
            'access denied', 'blocked', 'forbidden', 'unauthorized',
            'security violation', 'suspicious activity', 'malicious request'
        ]
        
        for signature in waf_signatures:
            features[f'content_has_{signature.replace(" ", "_")}'] = signature in content_lower
        
        # Response size
        features['content_length'] = len(response_content)
        features['is_empty_response'] = len(response_content) == 0
        features['is_short_response'] = len(response_content) < 100
        
        return features