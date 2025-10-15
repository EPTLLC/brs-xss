#!/usr/bin/env python3

"""
BRS-XSS Form Extractor

HTML form extraction engine with BeautifulSoup and regex fallback.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from urllib.parse import urljoin
from typing import Dict, List, Optional, Any

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

from .form_field_types import FieldType, FormField
from .extracted_form import ExtractedForm
from ..utils.logger import Logger

logger = Logger("crawler.form_extractor")


class FormExtractor:
    """
    HTML form extractor for BRS-XSS.
    
    Functions:
    - BeautifulSoup parsing with regex fallback
    - field analysis
    - Automatic form type detection
    - CSRF token detection
    - Security analysis
    """
    
    def __init__(self):
        """Initialize extractor"""
        self.use_beautifulsoup = BS4_AVAILABLE
        
        if not self.use_beautifulsoup:
            logger.warning("BeautifulSoup unavailable, using regex fallback")
    
    def extract_forms(self, html_content: str, base_url: str = "") -> List[ExtractedForm]:
        """
        Main form extraction method.
        
        Args:
            html_content: HTML content
            base_url: Base URL for relative links
            
        Returns:
            List of extracted forms
        """
        if self.use_beautifulsoup:
            return self._extract_with_beautifulsoup(html_content, base_url)
        else:
            return self._extract_with_regex(html_content, base_url)
    
    def _extract_with_beautifulsoup(self, html_content: str, base_url: str) -> List[ExtractedForm]:
        """Extract forms with BeautifulSoup"""
        forms = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            form_tags = soup.find_all('form')
            
            for form_tag in form_tags:
                form = self._parse_form_tag(form_tag, base_url)
                if form:
                    forms.append(form)
        
        except Exception as e:
            logger.error(f"BeautifulSoup parsing error: {e}")
            # Fallback to regex
            return self._extract_with_regex(html_content, base_url)
        
        logger.debug(f"Extracted {len(forms)} forms with BeautifulSoup")
        return forms
    
    def _parse_form_tag(self, form_tag: Any, base_url: str) -> Optional[ExtractedForm]:
        """Parse single form tag"""
        
        # Extract form attributes
        action = form_tag.get('action', '')
        method = form_tag.get('method', 'GET').upper()
        encoding = form_tag.get('enctype', 'application/x-www-form-urlencoded')
        
        # Absolute URL for action
        if action and base_url:
            action = urljoin(base_url, action)
        elif not action and base_url:
            action = base_url
        
        # Create form
        form = ExtractedForm(
            action=action,
            method=method,
            encoding=encoding,
            source_url=base_url,
            form_id=form_tag.get('id'),
            form_class=form_tag.get('class'),
            form_name=form_tag.get('name')
        )
        
        # Extract fields
        form.fields = self._extract_form_fields(form_tag)
        
        return form
    
    def _extract_form_fields(self, form_tag: Any) -> List[FormField]:
        """Extract form fields"""
        fields = []
        
        # Input fields
        input_tags = form_tag.find_all('input')
        for input_tag in input_tags:
            field = self._parse_input_field(input_tag)
            if field:
                fields.append(field)
        
        # Textarea fields
        textarea_tags = form_tag.find_all('textarea')
        for textarea_tag in textarea_tags:
            field = self._parse_textarea_field(textarea_tag)
            if field:
                fields.append(field)
        
        # Select fields
        select_tags = form_tag.find_all('select')
        for select_tag in select_tags:
            field = self._parse_select_field(select_tag)
            if field:
                fields.append(field)
        
        return fields
    
    def _parse_input_field(self, input_tag: Any) -> Optional[FormField]:
        """Parse input field"""
        
        name = input_tag.get('name')
        if not name:
            return None
        
        input_type = input_tag.get('type', 'text').lower()
        
        try:
            field_type = FieldType(input_type)
        except ValueError:
            field_type = FieldType.TEXT  # Default fallback
        
        field = FormField(
            name=name,
            field_type=field_type,
            value=input_tag.get('value', ''),
            placeholder=input_tag.get('placeholder', ''),
            required=input_tag.has_attr('required'),
            readonly=input_tag.has_attr('readonly'),
            disabled=input_tag.has_attr('disabled'),
            autocomplete=input_tag.get('autocomplete')
        )
        
        # Additional attributes
        if input_tag.get('maxlength'):
            try:
                field.max_length = int(input_tag.get('maxlength'))
            except ValueError:
                pass
        
        if input_tag.get('minlength'):
            try:
                field.min_length = int(input_tag.get('minlength'))
            except ValueError:
                pass
        
        field.pattern = input_tag.get('pattern')
        
        return field
    
    def _parse_textarea_field(self, textarea_tag: Any) -> Optional[FormField]:
        """Parse textarea field"""
        
        name = textarea_tag.get('name')
        if not name:
            return None
        
        field = FormField(
            name=name,
            field_type=FieldType.TEXTAREA,
            value=textarea_tag.get_text() or '',
            placeholder=textarea_tag.get('placeholder', ''),
            required=textarea_tag.has_attr('required'),
            readonly=textarea_tag.has_attr('readonly'),
            disabled=textarea_tag.has_attr('disabled')
        )
        
        return field
    
    def _parse_select_field(self, select_tag: Any) -> Optional[FormField]:
        """Parse select field"""
        
        name = select_tag.get('name')
        if not name:
            return None
        
        # Extract options
        options = []
        option_tags = select_tag.find_all('option')
        
        for option_tag in option_tags:
            value = option_tag.get('value', '')
            text = option_tag.get_text().strip()
            options.append((value, text))
        
        field = FormField(
            name=name,
            field_type=FieldType.SELECT,
            required=select_tag.has_attr('required'),
            disabled=select_tag.has_attr('disabled'),
            options=options
        )
        
        return field
    
    def _extract_with_regex(self, html_content: str, base_url: str) -> List[ExtractedForm]:
        """Fallback form extraction with regex"""
        forms = []
        
        # Pattern for finding forms
        form_pattern = r'<form[^>]*>(.*?)</form>'
        
        for form_match in re.finditer(form_pattern, html_content, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            form_content = form_match.group(1)
            
            # Extract form attributes
            action = self._extract_form_attribute(form_html, 'action')
            method = self._extract_form_attribute(form_html, 'method') or 'GET'
            encoding = self._extract_form_attribute(form_html, 'enctype') or 'application/x-www-form-urlencoded'
            
            # Absolute URL
            if action and base_url:
                action = urljoin(base_url, action)
            elif not action and base_url:
                action = base_url
            
            # Create form
            form = ExtractedForm(
                action=action,  # type: ignore[arg-type]
                method=method.upper(),
                encoding=encoding,
                source_url=base_url
            )
            
            # Extract fields with regex
            form.fields = self._extract_fields_with_regex(form_content)
            
            forms.append(form)
        
        logger.debug(f"Extracted {len(forms)} forms with regex")
        return forms
    
    def _extract_form_attribute(self, form_html: str, attr_name: str) -> Optional[str]:
        """Extract form attribute with regex"""
        pattern = rf'{attr_name}\s*=\s*["\']([^"\']*)["\']'
        match = re.search(pattern, form_html, re.IGNORECASE)
        return match.group(1) if match else None
    
    def _extract_fields_with_regex(self, form_content: str) -> List[FormField]:
        """Extract fields with regex"""
        fields = []
        
        # Input fields
        input_pattern = r'<input[^>]*>'
        for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
            input_html = input_match.group(0)
            field = self._parse_input_with_regex(input_html)
            if field:
                fields.append(field)
        
        # Textarea fields
        textarea_pattern = r'<textarea[^>]*>(.*?)</textarea>'
        for textarea_match in re.finditer(textarea_pattern, form_content, re.DOTALL | re.IGNORECASE):
            textarea_html = textarea_match.group(0)
            textarea_content = textarea_match.group(1)
            field = self._parse_textarea_with_regex(textarea_html, textarea_content)
            if field:
                fields.append(field)
        
        # Select fields (simplified)
        select_pattern = r'<select[^>]*name\s*=\s*["\']([^"\']*)["\'][^>]*>'
        for select_match in re.finditer(select_pattern, form_content, re.IGNORECASE):
            name = select_match.group(1)
            field = FormField(name=name, field_type=FieldType.SELECT)
            fields.append(field)
        
        return fields
    
    def _parse_input_with_regex(self, input_html: str) -> Optional[FormField]:
        """Parse input field with regex"""
        
        # Extract name
        name_match = re.search(r'name\s*=\s*["\']([^"\']*)["\']', input_html, re.IGNORECASE)
        if not name_match:
            return None
        
        name = name_match.group(1)
        
        # Extract type
        type_match = re.search(r'type\s*=\s*["\']([^"\']*)["\']', input_html, re.IGNORECASE)
        input_type = type_match.group(1).lower() if type_match else 'text'
        
        try:
            field_type = FieldType(input_type)
        except ValueError:
            field_type = FieldType.TEXT
        
        # Extract value
        value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', input_html, re.IGNORECASE)
        value = value_match.group(1) if value_match else ''
        
        field = FormField(
            name=name,
            field_type=field_type,
            value=value,
            required='required' in input_html.lower()
        )
        
        return field
    
    def _parse_textarea_with_regex(self, textarea_html: str, content: str) -> Optional[FormField]:
        """Parse textarea field with regex"""
        
        name_match = re.search(r'name\s*=\s*["\']([^"\']*)["\']', textarea_html, re.IGNORECASE)
        if not name_match:
            return None
        
        name = name_match.group(1)
        
        field = FormField(
            name=name,
            field_type=FieldType.TEXTAREA,
            value=content.strip(),
            required='required' in textarea_html.lower()
        )
        
        return field
    
    def get_extraction_stats(self) -> Dict[str, Any]:
        """Extraction statistics"""
        return {
            'parser_used': 'BeautifulSoup' if self.use_beautifulsoup else 'Regex',
            'beautifulsoup_available': BS4_AVAILABLE,
            'supported_field_types': [field_type.value for field_type in FieldType]
        }