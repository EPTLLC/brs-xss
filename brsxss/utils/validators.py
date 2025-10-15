#!/usr/bin/env python3

"""
BRS-XSS Validators

Input validation and parameter analysis utilities.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import os
import re
import urllib.parse
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path

from .logger import Logger
logger = Logger("utils.validators")


@dataclass
class ValidationResult:
    """Validation result"""
    valid: bool
    errors: List[str]
    warnings: List[str]
    normalized_value: Optional[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


class URLValidator:
    """URL validation and normalization"""
    
    @staticmethod
    def validate_url(url: str) -> ValidationResult:
        """Validate URL format and structure"""
        errors: List[str] = []
        warnings: List[str] = []
        normalized_url = url.strip()
        
        if not url:
            errors.append("URL cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        # Check for protocol
        if not re.match(r'^https?://', normalized_url, re.IGNORECASE):
            if not normalized_url.startswith('//'):
                normalized_url = 'http://' + normalized_url
                warnings.append("Added default HTTP protocol")
        
        try:
            parsed = urllib.parse.urlparse(normalized_url)
            
            # Validate scheme
            if parsed.scheme not in ['http', 'https']:
                errors.append(f"Unsupported protocol: {parsed.scheme}")
            
            # Validate hostname
            if not parsed.netloc:
                errors.append("Missing hostname")
            elif not re.match(r'^[a-zA-Z0-9.-]+$', parsed.netloc.split(':')[0]):
                errors.append("Invalid hostname format")
            
            # Check for localhost/private IPs
            hostname = parsed.netloc.split(':')[0].lower()
            if hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
                warnings.append("Localhost URL detected")
            elif re.match(r'^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.', hostname):
                warnings.append("Private IP address detected")
            
            # Normalize URL
            normalized_url = urllib.parse.urlunparse(parsed)
            
        except Exception as e:
            errors.append(f"URL parsing error: {e}")
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            normalized_value=normalized_url if len(errors) == 0 else None
        )
    
    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        """Extract domain from URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.netloc.split(':')[0].lower()
        except Exception:
            return None
    
    @staticmethod
    def is_same_domain(url1: str, url2: str) -> bool:
        """Check if URLs belong to same domain"""
        domain1 = URLValidator.extract_domain(url1)
        domain2 = URLValidator.extract_domain(url2)
        return bool(domain1 and domain2 and domain1 == domain2)


class ParameterValidator:
    """Parameter validation and analysis"""
    
    @staticmethod
    def validate_parameter_name(name: str) -> ValidationResult:
        """Validate parameter name"""
        errors: List[str] = []
        warnings: List[str] = []
        
        if not name:
            errors.append("Parameter name cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        # Check for valid characters
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_-]*$', name):
            if re.search(r'[<>"\']', name):
                errors.append("Parameter name contains dangerous characters")
            else:
                warnings.append("Parameter name contains unusual characters")
        
        # Check length
        if len(name) > 100:
            warnings.append("Parameter name is very long")
        
        # Check for common patterns
        sensitive_patterns = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'token',
            'auth', 'session', 'cookie', 'csrf'
        ]
        
        if any(pattern in name.lower() for pattern in sensitive_patterns):
            warnings.append("Parameter name suggests sensitive data")
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            normalized_value=name
        )
    
    @staticmethod
    def analyze_parameter_value(value: str) -> Dict[str, Any]:
        """Analyze parameter value characteristics"""
        type_hints: List[str] = []
        encoding_detected: List[str] = []
        special_chars_list: List[str] = []
        patterns: List[str] = []
        
        analysis: Dict[str, Any] = {
            'length': len(value),
            'type_hints': type_hints,
            'encoding_detected': encoding_detected,
            'special_chars': special_chars_list,
            'patterns': patterns
        }
        
        # Type detection
        if value.isdigit():
            type_hints.append('integer')
        elif re.match(r'^\d+\.\d+$', value):
            type_hints.append('float')
        elif value.lower() in ['true', 'false', '1', '0']:
            type_hints.append('boolean')
        elif re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            type_hints.append('email')
        elif re.match(r'^https?://', value):
            type_hints.append('url')
        elif re.match(r'^\d{4}-\d{2}-\d{2}', value):
            type_hints.append('date')
        
        # Encoding detection
        if '%' in value and re.search(r'%[0-9a-fA-F]{2}', value):
            encoding_detected.append('url_encoded')
        if '&lt;' in value or '&gt;' in value or '&quot;' in value:
            encoding_detected.append('html_entities')
        if '\\u' in value and re.search(r'\\u[0-9a-fA-F]{4}', value):
            encoding_detected.append('unicode_escaped')
        
        # Special characters
        special_chars = set(re.findall(r'[<>"\'\(\)\{\}\[\];,&|]', value))
        special_chars_list.extend(list(special_chars))
        
        # Pattern detection
        if re.search(r'<[^>]*>', value):
            patterns.append('html_tags')
        if re.search(r'javascript:', value, re.IGNORECASE):
            patterns.append('javascript_protocol')
        if re.search(r'(alert|prompt|confirm)\s*\(', value, re.IGNORECASE):
            patterns.append('javascript_functions')
        if re.search(r'(script|iframe|object|embed)', value, re.IGNORECASE):
            patterns.append('dangerous_tags')
        
        return analysis
    
    @staticmethod
    def is_testable_parameter(name: str, value: str) -> bool:
        """Check if parameter is suitable for XSS testing"""
        # Skip binary/file parameters
        if any(keyword in name.lower() for keyword in ['file', 'upload', 'binary', 'image']):
            return False
        
        # Skip very long values (likely not injectable)
        if len(value) > 1000:
            return False
        
        # Skip numeric-only parameters unless they're in dangerous contexts
        if value.isdigit() and not any(keyword in name.lower() for keyword in ['id', 'page', 'limit']):
            return False
        
        # Skip authentication parameters
        if any(keyword in name.lower() for keyword in ['password', 'token', 'csrf', 'auth']):
            return False
        
        return True


class PayloadValidator:
    """Payload validation and safety checks"""
    
    @staticmethod
    def validate_payload(payload: str) -> ValidationResult:
        """Validate XSS payload"""
        errors: List[str] = []
        warnings: List[str] = []
        
        if not payload:
            errors.append("Payload cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        # Check length
        if len(payload) > 10000:
            errors.append("Payload too long (max 10000 characters)")
        elif len(payload) > 1000:
            warnings.append("Payload is very long")
        
        # Check for dangerous patterns
        dangerous_patterns = [
            r'(document\.cookie)',
            r'(localStorage|sessionStorage)',
            r'(fetch|XMLHttpRequest)',
            r'(eval\s*\()',
            r'(Function\s*\()',
            r'(setTimeout|setInterval)'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                warnings.append(f"Payload contains potentially dangerous pattern: {pattern}")
        
        # Check encoding
        if len(payload.encode('utf-8')) != len(payload):
            warnings.append("Payload contains non-ASCII characters")
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            normalized_value=payload
        )
    
    @staticmethod
    def sanitize_payload_for_logging(payload: str) -> str:
        """Sanitize payload for safe logging"""
        # Truncate if too long
        if len(payload) > 200:
            payload = payload[:200] + "..."
        
        # Remove dangerous tags and reduce special chars
        sanitized = re.sub(r'(?is)<\s*script[^>]*>.*?<\s*/\s*script\s*>', '<removed>', payload)
        sanitized = re.sub(r'(?is)<\s*iframe[^>]*>.*?<\s*/\s*iframe\s*>', '<removed>', sanitized)
        sanitized = re.sub(r'(?is)<\s*img[^>]*>', '<img>', sanitized)
        sanitized = re.sub(r'[^\w\s\-_.:,;()\[\]{}="\']', '?', sanitized)
        
        return sanitized


class ConfigValidator:
    """Configuration validation"""
    
    @staticmethod
    def validate_scan_config(config: Dict[str, Any]) -> ValidationResult:
        """Validate scan configuration"""
        errors: List[str] = []
        warnings: List[str] = []
        
        # Check required fields
        required_fields = ['target_url']
        for field in required_fields:
            if field not in config:
                errors.append(f"Missing required field: {field}")
        
        # Validate URL
        if 'target_url' in config:
            url_result = URLValidator.validate_url(config['target_url'])
            if not url_result.valid:
                errors.extend([f"Target URL: {err}" for err in url_result.errors])
            warnings.extend([f"Target URL: {warn}" for warn in url_result.warnings])
        
        # Validate numeric settings
        numeric_fields = {
            'max_depth': (1, 10),
            'max_urls': (1, 10000),
            'max_concurrent': (1, 50),
            'timeout': (1, 300)
        }
        
        for field, (min_val, max_val) in numeric_fields.items():
            if field in config:
                value = config[field]
                if not isinstance(value, int) or value < min_val or value > max_val:
                    errors.append(f"{field} must be between {min_val} and {max_val}")
        
        # Validate string settings
        if 'user_agent' in config and len(config['user_agent']) > 200:
            warnings.append("User agent is very long")
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )


class FileValidator:
    """File and path validation"""
    
    @staticmethod
    def validate_output_path(path: str) -> ValidationResult:
        """Validate output file path"""
        errors: List[str] = []
        warnings: List[str] = []
        
        if not path:
            errors.append("Output path cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        try:
            path_obj = Path(path)
            
            # Check if parent directory exists or can be created
            parent_dir = path_obj.parent
            if not parent_dir.exists():
                try:
                    parent_dir.mkdir(parents=True, exist_ok=True)
                    warnings.append("Created parent directories")
                except Exception as e:
                    errors.append(f"Cannot create parent directory: {e}")
            
            # Check write permissions
            if parent_dir.exists() and not os.access(parent_dir, os.W_OK):
                errors.append("No write permission for output directory")
            
            # Check file extension
            valid_extensions = ['.html', '.json', '.xml', '.csv', '.txt', '.sarif']
            if path_obj.suffix.lower() not in valid_extensions:
                warnings.append(f"Unusual file extension: {path_obj.suffix}")
            
            # Check if file already exists
            if path_obj.exists():
                warnings.append("Output file already exists (will be overwritten)")
            
        except Exception as e:
            errors.append(f"Invalid path: {e}")
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            normalized_value=str(Path(path).resolve())
        )


class InputSanitizer:
    """Input sanitization utilities"""
    
    @staticmethod
    def sanitize_for_shell(input_str: str) -> str:
        """Sanitize input for shell command usage"""
        # Remove dangerous characters
        sanitized = re.sub(r'[;&|`$(){}[\]<>"]', '', input_str)
        return sanitized.strip()
    
    @staticmethod
    def sanitize_for_filename(input_str: str) -> str:
        """Sanitize input for filename usage"""
        # Replace dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', input_str)
        # Remove leading/trailing dots and spaces
        sanitized = sanitized.strip('. ')
        # Limit length
        if len(sanitized) > 200:
            sanitized = sanitized[:200]
        return sanitized
    
    @staticmethod
    def sanitize_for_display(input_str: str) -> str:
        """Sanitize input for safe display"""
        # Escape HTML characters
        sanitized = input_str.replace('&', '&amp;')
        sanitized = sanitized.replace('<', '&lt;')
        sanitized = sanitized.replace('>', '&gt;')
        sanitized = sanitized.replace('"', '&quot;')
        sanitized = sanitized.replace("'", '&#x27;')
        return sanitized

