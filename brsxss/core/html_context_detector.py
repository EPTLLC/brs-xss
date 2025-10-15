#!/usr/bin/env python3

"""
BRS-XSS HTML Context Detector

Specialized detector for HTML contexts.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from .context_types import ContextType
from ..utils.logger import Logger

logger = Logger("core.html_context_detector")


class HTMLContextDetector:
    """Detects and analyzes HTML contexts for XSS injections"""
    
    def __init__(self):
        """Initialize HTML context detector"""
        self.html_patterns = {
            'html_content': r'>\s*{}\s*<',
            'html_attribute': r'(\w+)\s*=\s*["\']?[^"\']*{}[^"\']*["\']?',
            'html_comment': r'<!--[^>]*{}[^>]*-->',
            'tag_name': r'<\s*{}\s*[^>]*>',
            'style_attr': r'style\s*=\s*["\'][^"\']*{}[^"\']*["\']'
        }
    
    def detect_html_context(self, html_content: str, marker_pos: int, marker: str) -> ContextType:
        """
        Detect HTML context type at marker position.
        
        Args:
            html_content: HTML content
            marker_pos: Position of marker in content
            marker: Marker string
            
        Returns:
            Detected context type
        """
        # Check for HTML comment
        if self._is_in_html_comment(html_content, marker_pos):
            return ContextType.HTML_COMMENT
        
        # Check for HTML attribute
        if self._is_in_html_attribute(html_content, marker_pos, marker):
            return ContextType.HTML_ATTRIBUTE
        
        # Default to HTML content
        return ContextType.HTML_CONTENT
    
    def extract_tag_name(self, html_content: str, marker_pos: int) -> str:
        """Extract tag name containing the marker"""
        # Look backwards for opening tag
        search_start = max(0, marker_pos - 1000)
        before_marker = html_content[search_start:marker_pos]
        
        # Find last opening tag
        tag_match = re.search(r'<\s*(\w+)[^>]*$', before_marker)
        if tag_match:
            return tag_match.group(1).lower()
        
        # Look forward for closing tag
        search_end = min(len(html_content), marker_pos + 1000)
        after_marker = html_content[marker_pos:search_end]
        
        closing_tag_match = re.search(r'</\s*(\w+)\s*>', after_marker)
        if closing_tag_match:
            return closing_tag_match.group(1).lower()
        
        return ""
    
    def extract_attribute_name(self, html_content: str, marker_pos: int, marker: str) -> str:
        """Extract attribute name containing the marker"""
        if not self._is_in_html_attribute(html_content, marker_pos, marker):
            return ""
        
        # Look backwards for attribute pattern
        search_start = max(0, marker_pos - 200)
        context = html_content[search_start:marker_pos + len(marker) + 50]
        
        # Find marker in context
        marker_in_context = context.find(marker)
        if marker_in_context == -1:
            return ""
        
        # Look for attribute pattern before marker
        before_marker = context[:marker_in_context]
        attr_match = re.search(r'(\w+)\s*=\s*["\']?[^"\']*$', before_marker)
        
        if attr_match:
            return attr_match.group(1).lower()
        
        return ""
    
    def detect_quote_character(self, html_content: str, marker_pos: int, marker: str) -> str:
        """Detect quote character used around marker"""
        # Get context around marker
        start = max(0, marker_pos - 100)
        end = min(len(html_content), marker_pos + len(marker) + 100)
        context = html_content[start:end]
        
        # Find marker in context
        marker_in_context = context.find(marker)
        if marker_in_context == -1:
            return ""
        
        # Look for quotes around marker
        before_marker = context[:marker_in_context]
        after_marker = context[marker_in_context + len(marker):]
        
        # Check for quotes
        if '"' in before_marker and '"' in after_marker:
            # Check if marker is between the same quotes
            last_quote_before = before_marker.rfind('"')
            first_quote_after = after_marker.find('"')
            
            if last_quote_before != -1 and first_quote_after != -1:
                return '"'
        
        if "'" in before_marker and "'" in after_marker:
            # Check if marker is between the same quotes
            last_quote_before = before_marker.rfind("'")
            first_quote_after = after_marker.find("'")
            
            if last_quote_before != -1 and first_quote_after != -1:
                return "'"
        
        return ""
    
    def _is_in_html_comment(self, html_content: str, pos: int) -> bool:
        """Check if position is inside HTML comment"""
        # Find nearest comment start before position
        comment_start = html_content.rfind('<!--', 0, pos)
        if comment_start == -1:
            return False
        
        # Find comment end after start
        comment_end = html_content.find('-->', comment_start)
        
        # Check if position is between start and end
        return comment_end == -1 or pos < comment_end
    
    def _is_in_html_attribute(self, html_content: str, pos: int, marker: str) -> bool:
        """Check if position is inside HTML attribute"""
        # Get context around position
        start = max(0, pos - 200)
        end = min(len(html_content), pos + len(marker) + 200)
        context = html_content[start:end]
        
        # Find marker in context
        marker_in_context = context.find(marker)
        if marker_in_context == -1:
            return False
        
        # Look for attribute pattern
        attr_pattern = r'(\w+)\s*=\s*["\']?[^"\'<>]*' + re.escape(marker) + r'[^"\'<>]*["\']?'
        
        return bool(re.search(attr_pattern, context, re.IGNORECASE))
    
    def get_surrounding_content(self, html_content: str, marker_pos: int, marker: str, radius: int = 200) -> str:
        """Get surrounding content around marker"""
        start = max(0, marker_pos - radius)
        end = min(len(html_content), marker_pos + len(marker) + radius)
        
        return html_content[start:end]
    
    def analyze_tag_context(self, html_content: str, marker_pos: int) -> dict:
        """Analyze tag context around marker"""
        tag_name = self.extract_tag_name(html_content, marker_pos)
        
        context_info = {
            'tag_name': tag_name,
            'is_void_element': tag_name in [
                'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 
                'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'
            ],
            'is_script_tag': tag_name == 'script',
            'is_style_tag': tag_name == 'style',
            'is_form_element': tag_name in ['form', 'input', 'textarea', 'select', 'button'],
            'is_media_element': tag_name in ['img', 'video', 'audio', 'embed', 'object']
        }
        
        # Check for dangerous attributes
        if tag_name:
            dangerous_attrs = self._find_dangerous_attributes(html_content, marker_pos)
            context_info['dangerous_attributes'] = dangerous_attrs
        
        return context_info
    
    def _find_dangerous_attributes(self, html_content: str, marker_pos: int) -> list:
        """Find dangerous attributes in the current tag"""
        dangerous_attrs: "List[str]" = []  # type: ignore[name-defined]
        
        # Get tag content
        tag_start = html_content.rfind('<', 0, marker_pos)
        if tag_start == -1:
            return dangerous_attrs
        
        tag_end = html_content.find('>', tag_start)
        if tag_end == -1:
            return dangerous_attrs
        
        tag_content = html_content[tag_start:tag_end + 1]
        
        # Check for dangerous attributes
        dangerous_patterns = [
            r'\bon\w+\s*=',  # Event handlers
            r'\bsrc\s*=',    # Source attributes
            r'\bhref\s*=',   # Links
            r'\baction\s*=', # Form actions
            r'\bstyle\s*=',  # Inline styles
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, tag_content, re.IGNORECASE):
                match = re.search(pattern, tag_content, re.IGNORECASE)
                if match:
                    attr_name = match.group().split('=')[0].strip()
                    dangerous_attrs.append(attr_name)
        
        return dangerous_attrs