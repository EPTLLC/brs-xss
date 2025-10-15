#!/usr/bin/env python3

"""
BRS-XSS Extracted Form

Data structure for extracted HTML forms with security analysis.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional
from dataclasses import dataclass, field

from .form_field_types import FormField


@dataclass
class ExtractedForm:
    """Extracted HTML form"""
    action: str
    method: str = "GET"
    encoding: str = "application/x-www-form-urlencoded"
    fields: List[FormField] = field(default_factory=list)
    
    # Metadata
    form_id: Optional[str] = None
    form_class: Optional[str] = None
    form_name: Optional[str] = None
    
    # Security analysis
    has_csrf_token: bool = False
    csrf_field_name: Optional[str] = None
    has_file_upload: bool = False
    uses_https: bool = False
    
    # Context
    source_url: str = ""
    
    def __post_init__(self):
        if self.fields is None:
            self.fields = []
        
        # Automatic form analysis
        self._analyze_form()
    
    def _analyze_form(self):
        """Analyze form security features"""
        # Check HTTPS usage
        self.uses_https = self.action.startswith('https://')
        
        # Look for CSRF tokens
        csrf_patterns = ['csrf', 'token', '_token', 'authenticity_token', 'xsrf']
        
        for field in self.fields:
            # Check for file uploads
            if field.is_file_upload:
                self.has_file_upload = True
            
            # Check for CSRF tokens
            field_name_lower = field.name.lower()
            if any(pattern in field_name_lower for pattern in csrf_patterns):
                self.has_csrf_token = True
                self.csrf_field_name = field.name
    
    @property
    def testable_fields(self) -> List[FormField]:
        """Fields that can be tested"""
        return [field for field in self.fields if field.is_testable]
    
    @property
    def parameter_count(self) -> int:
        """Number of parameters"""
        return len(self.fields)
    
    @property
    def is_login_form(self) -> bool:
        """Login form detection"""
        field_names = [field.name.lower() for field in self.fields]
        
        login_indicators = [
            ('user', 'pass'), ('email', 'pass'), ('login', 'pass'),
            ('username', 'password'), ('email', 'password')
        ]
        
        for user_field, pass_field in login_indicators:
            if any(user_field in name for name in field_names) and \
               any(pass_field in name for name in field_names):
                return True
        
        return False
    
    @property
    def is_search_form(self) -> bool:
        """Search form detection"""
        field_names = [field.name.lower() for field in self.fields]
        search_indicators = ['search', 'query', 'q', 'keyword', 'term']
        
        return any(indicator in ' '.join(field_names) for indicator in search_indicators)