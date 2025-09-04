#!/usr/bin/env python3

"""
BRS-XSS JavaScript Context Detector

Specialized detector for JavaScript contexts.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 11:25:00 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from typing import Dict, Any
from .context_types import ContextType
from ..utils.logger import Logger

logger = Logger("core.javascript_context_detector")


class JavaScriptContextDetector:
    """Detects and analyzes JavaScript contexts for XSS injections"""
    
    def __init__(self):
        """Initialize JavaScript context detector"""
        self.js_patterns = {
            'string_single': r"'[^']*{}[^']*'",
            'string_double': r'"[^"]*{}[^"]*"',
            'template_literal': r'`[^`]*{}[^`]*`',
            'object_property': r'{\s*[^}]*:\s*[^,}]*{}[^,}]*',
            'function_call': r'\w+\([^)]*{}[^)]*\)',
            'assignment': r'\w+\s*=\s*[^;]*{}[^;]*'
        }
    
    def is_in_script_tag(self, html_content: str, pos: int) -> bool:
        """Check if position is inside script tag"""
        # Find nearest script tag before position
        script_start = html_content.rfind('<script', 0, pos)
        if script_start == -1:
            return False
        
        # Find end of opening script tag
        script_tag_end = html_content.find('>', script_start)
        if script_tag_end == -1 or script_tag_end >= pos:
            return False
        
        # Find closing script tag
        script_end = html_content.find('</script>', pos)
        
        # Position should be after opening tag and before closing tag (or end of content)
        return script_tag_end < pos and (script_end == -1 or script_end > pos)
    
    def detect_js_context(self, html_content: str, marker_pos: int, marker: str) -> ContextType:
        """
        Detect JavaScript context type at marker position.
        
        Args:
            html_content: HTML content
            marker_pos: Position of marker in content
            marker: Marker string
            
        Returns:
            Detected JavaScript context type
        """
        if not self.is_in_script_tag(html_content, marker_pos):
            return ContextType.UNKNOWN
        
        # Check for string context
        if self._is_in_js_string(html_content, marker_pos, marker):
            return ContextType.JS_STRING
        
        # Check for object context
        if self._is_in_js_object(html_content, marker_pos, marker):
            return ContextType.JS_OBJECT
        
        # Default to JavaScript context
        return ContextType.JAVASCRIPT
    
    def _is_in_js_string(self, html_content: str, pos: int, marker: str) -> bool:
        """Check if position is inside JavaScript string"""
        # Get context around position
        start = max(0, pos - 100)
        end = min(len(html_content), pos + len(marker) + 100)
        context = html_content[start:end]
        
        # Find marker in context
        marker_in_context = context.find(marker)
        if marker_in_context == -1:
            return False
        
        # Count quotes before marker (excluding escaped quotes)
        before_marker = context[:marker_in_context]
        
        # Count unescaped single quotes
        single_quotes = 0
        i = 0
        while i < len(before_marker):
            if before_marker[i] == "'" and (i == 0 or before_marker[i-1] != '\\'):
                single_quotes += 1
            i += 1
        
        # Count unescaped double quotes
        double_quotes = 0
        i = 0
        while i < len(before_marker):
            if before_marker[i] == '"' and (i == 0 or before_marker[i-1] != '\\'):
                double_quotes += 1
            i += 1
        
        # If odd number of quotes, we're inside a string
        return (single_quotes % 2 == 1) or (double_quotes % 2 == 1)
    
    def _is_in_js_object(self, html_content: str, pos: int, marker: str) -> bool:
        """Check if position is inside JavaScript object"""
        # Get context around position
        start = max(0, pos - 200)
        end = min(len(html_content), pos + len(marker) + 200)
        context = html_content[start:end]
        
        # Find marker in context
        marker_in_context = context.find(marker)
        if marker_in_context == -1:
            return False
        
        # Look for object patterns
        before_marker = context[:marker_in_context]
        context[marker_in_context + len(marker):]
        
        # Check for object property pattern: key: value
        obj_property_pattern = r'[\w"\']+\s*:\s*[^,}]*$'
        if re.search(obj_property_pattern, before_marker):
            return True
        
        # Check for object literal brackets
        open_braces = before_marker.count('{') - before_marker.count('}')
        
        return open_braces > 0
    
    def detect_js_quote_character(self, html_content: str, marker_pos: int, marker: str) -> str:
        """Detect quote character used in JavaScript string"""
        if not self._is_in_js_string(html_content, marker_pos, marker):
            return ""
        
        # Get context around marker
        start = max(0, marker_pos - 50)
        end = min(len(html_content), marker_pos + len(marker) + 50)
        context = html_content[start:end]
        
        # Find marker in context
        marker_in_context = context.find(marker)
        if marker_in_context == -1:
            return ""
        
        before_marker = context[:marker_in_context]
        
        # Find last unescaped quote
        last_single = -1
        last_double = -1
        
        # Find last single quote
        for i in range(len(before_marker) - 1, -1, -1):
            if before_marker[i] == "'" and (i == 0 or before_marker[i-1] != '\\'):
                last_single = i
                break
        
        # Find last double quote
        for i in range(len(before_marker) - 1, -1, -1):
            if before_marker[i] == '"' and (i == 0 or before_marker[i-1] != '\\'):
                last_double = i
                break
        
        # Return the most recent quote
        if last_single > last_double:
            return "'"
        elif last_double > last_single:
            return '"'
        
        return ""
    
    def analyze_js_context_details(self, html_content: str, marker_pos: int, marker: str) -> Dict[str, Any]:
        """Analyze detailed JavaScript context information"""
        context_details = {
            'is_in_function': False,
            'is_in_event_handler': False,
            'is_in_variable_assignment': False,
            'is_in_function_call': False,
            'is_in_conditional': False,
            'surrounding_variables': [],
            'function_scope': None
        }
        
        # Get larger context for analysis
        start = max(0, marker_pos - 500)
        end = min(len(html_content), marker_pos + len(marker) + 500)
        context = html_content[start:end]
        
        # Find marker position in context
        marker_in_context = context.find(marker)
        if marker_in_context == -1:
            return context_details
        
        before_marker = context[:marker_in_context]
        context[marker_in_context + len(marker):]
        
        # Check for function context
        if re.search(r'function\s+\w*\s*\([^)]*\)\s*{[^}]*$', before_marker):
            context_details['is_in_function'] = True
        
        # Check for event handler
        if re.search(r'\bon\w+\s*=\s*["\']?[^"\']*$', before_marker):
            context_details['is_in_event_handler'] = True
        
        # Check for variable assignment
        if re.search(r'\b\w+\s*=\s*[^;]*$', before_marker):
            context_details['is_in_variable_assignment'] = True
        
        # Check for function call
        if re.search(r'\w+\s*\([^)]*$', before_marker):
            context_details['is_in_function_call'] = True
        
        # Check for conditional statements
        if re.search(r'\b(if|while|for)\s*\([^)]*$', before_marker):
            context_details['is_in_conditional'] = True
        
        # Extract variable names
        var_pattern = r'\b(var|let|const)\s+(\w+)'
        variables = re.findall(var_pattern, before_marker)
        context_details['surrounding_variables'] = [var[1] for var in variables]
        
        return context_details
    
    def get_js_payload_recommendations(self, context_details: Dict[str, Any], quote_char: str = "") -> list:
        """Get JavaScript-specific payload recommendations"""
        recommendations = []
        
        if context_details.get('is_in_function_call'):
            recommendations.extend([
                "Close function call and start new statement",
                "Use comma operator to execute additional code",
                "Try parameter injection techniques"
            ])
        
        if context_details.get('is_in_variable_assignment'):
            recommendations.extend([
                "Use comma operator for code execution",
                "Try constructor injection",
                "Use expression evaluation"
            ])
        
        if context_details.get('is_in_event_handler'):
            recommendations.extend([
                "Close attribute and add new event handler",
                "Use JavaScript protocol",
                "Try inline execution"
            ])
        
        if quote_char:
            recommendations.append(f"Break out of string using {quote_char} character")
        
        # General JavaScript recommendations
        recommendations.extend([
            "Use eval() for dynamic code execution",
            "Try constructor.constructor() for code execution",
            "Use setTimeout/setInterval for delayed execution",
            "Consider string concatenation techniques"
        ])
        
        return recommendations