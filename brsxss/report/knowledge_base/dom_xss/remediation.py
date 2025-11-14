#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

DOM-based XSS - Remediation
"""

REMEDIATION = """
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

