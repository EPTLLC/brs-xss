#!/usr/bin/env python3

"""
BRS-XSS CSS Context Detector

Specialized detector for CSS contexts.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from typing import Dict, Any, List, Optional
from .context_types import ContextType
from ..utils.logger import Logger

logger = Logger("core.css_context_detector")


class CSSContextDetector:
    """Detects and analyzes CSS contexts for XSS injections"""
    
    def __init__(self):
        """Initialize CSS context detector"""
        self.css_patterns = {
            'style_tag': r'<style[^>]*>.*?{}.*?</style>',
            'style_attr': r'style\s*=\s*["\'][^"\']*{}[^"\']*["\']',
            'css_property': r'[\w-]+\s*:\s*[^;]*{}[^;]*',
            'css_value': r':\s*[^;]*{}[^;]*;',
            'css_url': r'url\s*\(\s*[^)]*{}[^)]*\)',
            'css_import': r'@import\s+[^;]*{}[^;]*'
        }
    
    def is_in_style_tag(self, html_content: str, pos: int) -> bool:
        """Check if position is inside style tag"""
        # Find nearest style tag before position
        style_start = html_content.rfind('<style', 0, pos)
        if style_start == -1:
            return False
        
        # Find end of opening style tag
        style_tag_end = html_content.find('>', style_start)
        if style_tag_end == -1 or style_tag_end >= pos:
            return False
        
        # Find closing style tag
        style_end = html_content.find('</style>', pos)
        
        # Position should be after opening tag and before closing tag
        return style_tag_end < pos and (style_end == -1 or style_end > pos)
    
    def is_in_style_attribute(self, html_content: str, pos: int, marker: str) -> bool:
        """Check if position is inside style attribute"""
        # Get context around position
        start = max(0, pos - 200)
        end = min(len(html_content), pos + len(marker) + 200)
        context = html_content[start:end]
        
        # Look for style attribute pattern
        style_pattern = r'style\s*=\s*["\'][^"\']*' + re.escape(marker) + r'[^"\']*["\']'
        
        return bool(re.search(style_pattern, context, re.IGNORECASE))
    
    def detect_css_context(self, html_content: str, marker_pos: int, marker: str) -> ContextType:
        """
        Detect CSS context type at marker position.
        
        Args:
            html_content: HTML content
            marker_pos: Position of marker in content
            marker: Marker string
            
        Returns:
            Detected CSS context type
        """
        if self.is_in_style_tag(html_content, marker_pos) or \
           self.is_in_style_attribute(html_content, marker_pos, marker):
            return ContextType.CSS_STYLE
        
        return ContextType.UNKNOWN
    
    def analyze_css_context_details(self, html_content: str, marker_pos: int, marker: str) -> Dict[str, Any]:
        """Analyze detailed CSS context information"""
        context_details = {
            'is_in_style_tag': False,
            'is_in_style_attribute': False,
            'is_in_css_property': False,
            'is_in_css_value': False,
            'is_in_css_url': False,
            'is_in_css_import': False,
            'css_property_name': '',
            'surrounding_css': '',
            'css_syntax_valid': True
        }
        
        # Basic context detection
        context_details['is_in_style_tag'] = self.is_in_style_tag(html_content, marker_pos)
        context_details['is_in_style_attribute'] = self.is_in_style_attribute(
            html_content, marker_pos, marker
        )
        
        if not (context_details['is_in_style_tag'] or context_details['is_in_style_attribute']):
            return context_details
        
        # Get CSS context around marker
        css_context = self._extract_css_context(html_content, marker_pos, marker)
        context_details['surrounding_css'] = css_context
        
        # Analyze CSS syntax details
        marker_in_css = css_context.find(marker)
        if marker_in_css != -1:
            # Check if in property name or value
            before_marker = css_context[:marker_in_css]
            
            # Check for property pattern
            if ':' not in before_marker.split(';')[-1]:
                context_details['is_in_css_property'] = True
                context_details['css_property_name'] = self._extract_property_name(before_marker)
            else:
                context_details['is_in_css_value'] = True
                context_details['css_property_name'] = self._extract_property_name_from_value(before_marker)
            
            # Check for URL function
            if 'url(' in before_marker and ')' not in before_marker[before_marker.rfind('url('):]:
                context_details['is_in_css_url'] = True
            
            # Check for @import
            if '@import' in before_marker:
                context_details['is_in_css_import'] = True
            
            # Validate CSS syntax
            context_details['css_syntax_valid'] = self._validate_css_syntax(css_context)
        
        return context_details
    
    def _extract_css_context(self, html_content: str, marker_pos: int, marker: str) -> str:
        """Extract CSS context around marker"""
        if self.is_in_style_tag(html_content, marker_pos):
            # Find style tag boundaries
            style_start = html_content.rfind('<style', 0, marker_pos)
            style_tag_end = html_content.find('>', style_start) + 1
            style_end = html_content.find('</style>', marker_pos)
            
            if style_end == -1:
                style_end = len(html_content)
            
            return html_content[style_tag_end:style_end]
        
        elif self.is_in_style_attribute(html_content, marker_pos, marker):
            # Extract style attribute value
            start = max(0, marker_pos - 200)
            end = min(len(html_content), marker_pos + len(marker) + 200)
            context = html_content[start:end]
            
            # Find style attribute
            style_match = re.search(r'style\s*=\s*["\']([^"\']*)', context, re.IGNORECASE)
            if style_match:
                return style_match.group(1)
        
        return ""
    
    def _extract_property_name(self, before_marker: str) -> str:
        """Extract CSS property name from text before marker"""
        # Get the current CSS rule
        current_rule = before_marker.split(';')[-1].strip()
        
        # Extract property name (before colon)
        if ':' in current_rule:
            return current_rule.split(':')[0].strip()
        else:
            # Might be in property name itself
            property_match = re.search(r'([\w-]+)\s*$', current_rule)
            if property_match:
                return property_match.group(1)
        
        return ""
    
    def _extract_property_name_from_value(self, before_marker: str) -> str:
        """Extract CSS property name when marker is in value"""
        # Get the current CSS rule
        current_rule = before_marker.split(';')[-1].strip()
        
        # Extract property name (before colon)
        if ':' in current_rule:
            return current_rule.split(':')[0].strip()
        
        return ""
    
    def _validate_css_syntax(self, css_content: str) -> bool:
        """Basic CSS syntax validation"""
        try:
            # Count braces
            open_braces = css_content.count('{')
            close_braces = css_content.count('}')
            
            # Count parentheses
            open_parens = css_content.count('(')
            close_parens = css_content.count(')')
            
            # Count quotes
            single_quotes = css_content.count("'")
            double_quotes = css_content.count('"')
            
            # Basic balance check
            return (abs(open_braces - close_braces) <= 1 and
                    abs(open_parens - close_parens) <= 1 and
                    single_quotes % 2 == 0 and
                    double_quotes % 2 == 0)
        
        except Exception:
            return False
    
    def get_css_payload_recommendations(self, context_details: Dict[str, Any]) -> List[str]:
        """Get CSS-specific payload recommendations"""
        recommendations = []
        
        if context_details.get('is_in_css_url'):
            recommendations.extend([
                "Use javascript: protocol in URL",
                "Try data: URLs with JavaScript",
                "Use expression() for IE compatibility",
                "Try CSS import with JavaScript URL"
            ])
        
        elif context_details.get('is_in_css_property'):
            recommendations.extend([
                "Complete property and add malicious value",
                "Use expression() property for IE",
                "Try behavior property for IE",
                "Add new CSS rules"
            ])
        
        elif context_details.get('is_in_css_value'):
            property_name = context_details.get('css_property_name', '').lower()
            
            if property_name in ['background', 'background-image']:
                recommendations.extend([
                    "Use url() with javascript: protocol",
                    "Try expression() for dynamic evaluation"
                ])
            
            elif property_name == 'content':
                recommendations.extend([
                    "Close value and add new CSS rules",
                    "Use attr() function for dynamic content"
                ])
            
            else:
                recommendations.extend([
                    "Close current value and add malicious CSS",
                    "Use expression() for code execution",
                    "Try CSS injection techniques"
                ])
        
        # General CSS recommendations
        recommendations.extend([
            "Use expression() for Internet Explorer",
            "Try -moz-binding for Firefox",
            "Use behavior property for IE",
            "Consider CSS import injection"
        ])
        
        return recommendations
    
    def detect_css_filter_bypasses(self, css_content: str) -> List[str]:
        """Detect potential CSS filter bypasses"""
        bypasses = []
        
        # Common CSS filter bypass techniques
        bypass_patterns = [
            (r'\\65 xpression', 'Unicode escaping for expression'),
            (r'\\000065 xpression', 'Null byte Unicode escaping'),
            (r'expr\\65 ssion', 'Character escaping'),
            (r'/\*\*/ *expression', 'Comment insertion'),
            (r'e\x78pression', 'Hex escaping'),
            (r'EXPRESSION', 'Case variation'),
            (r'@import.*javascript:', 'Import with JavaScript'),
            (r'url\(.*javascript:', 'URL with JavaScript protocol')
        ]
        
        for pattern, description in bypass_patterns:
            if re.search(pattern, css_content, re.IGNORECASE):
                bypasses.append(description)
        
        return bypasses