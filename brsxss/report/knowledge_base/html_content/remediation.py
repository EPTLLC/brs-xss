#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

HTML Content Context - Remediation
"""

REMEDIATION = """
DEFENSE-IN-DEPTH STRATEGY:

1. HTML ENTITY ENCODING:
   
   Encode all special characters before output:
   - & → &amp;
   - < → &lt;
   - > → &gt;
   - " → &quot;
   - ' → &#x27; or &apos;
   
   Python:
   import html
   safe_output = html.escape(user_input)
   
   PHP:
   $safe = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
   
   JavaScript:
   function escapeHTML(text) {
     const div = document.createElement('div');
     div.textContent = text;
     return div.innerHTML;
   }

2. CONTENT SECURITY POLICY (CSP):
   
   Strict CSP prevents inline scripts and eval:
   Content-Security-Policy: 
     default-src 'self';
     script-src 'self' 'nonce-{random}';
     object-src 'none';
     base-uri 'none';
     form-action 'self';
   
   Use nonces for trusted scripts:
   <script nonce="{random}">/* trusted script */</script>

3. SAFE DOM MANIPULATION:
   
   SAFE (Use these):
   - textContent
   - innerText
   - setAttribute()
   - createTextNode()
   
   DANGEROUS (Avoid):
   - innerHTML
   - outerHTML
   - document.write()
   - insertAdjacentHTML()
   
   Example:
   // BAD:
   element.innerHTML = userInput;
   
   // GOOD:
   element.textContent = userInput;

4. MODERN FRAMEWORK PROTECTION:
   
   React (Safe by default):
   function Component({ userInput }) {
     return <div>{userInput}</div>; // Auto-escaped
   }
   
   // DANGEROUS:
   <div dangerouslySetInnerHTML={{__html: userInput}} />
   
   Vue (Safe by default):
   <template>
     <div>{{ userInput }}</div> <!-- Auto-escaped -->
   </template>
   
   // DANGEROUS:
   <div v-html="userInput"></div>
   
   Angular (Safe by default):
   <div>{{ userInput }}</div> <!-- Auto-escaped -->
   
   // DANGEROUS:
   <div [innerHTML]="userInput"></div>

5. HTML SANITIZATION:
   
   When rich HTML is required, use battle-tested libraries:
   
   JavaScript (DOMPurify):
   import DOMPurify from 'dompurify';
   const clean = DOMPurify.sanitize(dirty);
   
   Python (Bleach):
   import bleach
   clean = bleach.clean(
     dirty,
     tags=['b', 'i', 'u', 'em', 'strong', 'a'],
     attributes={'a': ['href', 'title']},
     protocols=['http', 'https', 'mailto']
   )
   
   Java (OWASP Java HTML Sanitizer):
   PolicyFactory policy = new HtmlPolicyBuilder()
     .allowElements("b", "i", "u")
     .allowAttributes("href").onElements("a")
     .allowStandardUrlProtocols()
     .toFactory();
   String safeHTML = policy.sanitize(untrustedHTML);

6. TRUSTED TYPES API (Modern Browsers):
   
   Enforce at policy level:
   Content-Security-Policy: require-trusted-types-for 'script'
   
   JavaScript:
   const policy = trustedTypes.createPolicy('myPolicy', {
     createHTML: (string) => {
       // Sanitize here
       return DOMPurify.sanitize(string);
     }
   });
   
   element.innerHTML = policy.createHTML(userInput);

7. INPUT VALIDATION:
   
   Whitelist approach:
   - Define what is allowed
   - Reject everything else
   
   Example for username:
   const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,20}$/;
   if (!USERNAME_REGEX.test(username)) {
     throw new Error('Invalid username');
   }

8. HTTPONLY & SECURE COOKIES:
   
   Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
   
   HttpOnly: Prevents JavaScript access to cookie
   Secure: Only sent over HTTPS
   SameSite: Prevents CSRF

9. X-XSS-PROTECTION HEADER:
   
   X-XSS-Protection: 1; mode=block
   
   Note: Deprecated in modern browsers that support CSP

10. X-CONTENT-TYPE-OPTIONS:
    
    X-Content-Type-Options: nosniff
    
    Prevents MIME-sniffing attacks

SECURITY CHECKLIST:

[ ] All user input is HTML entity encoded before output
[ ] CSP is implemented with nonce or hash
[ ] Using framework auto-escaping (not bypassed)
[ ] No innerHTML/document.write with user data
[ ] HTML sanitization library if rich content needed
[ ] HTTPOnly flag on all session cookies
[ ] Secure flag on cookies (HTTPS only)
[ ] SameSite attribute on cookies
[ ] Input validation with whitelist
[ ] Regular security testing (automated + manual)
[ ] Security code review for all user input handling
[ ] Trusted Types API enabled (if browser support available)
[ ] WAF as additional layer (not primary defense)
[ ] Security headers configured (CSP, X-Content-Type-Options)
[ ] Developer security training completed

TESTING PAYLOADS:

Basic detection:
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

Filter bypass:
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror=alert`1`>
<svg/onload=alert(1)>

Encoding:
&lt;script&gt;alert(1)&lt;/script&gt;
\\x3cscript\\x3ealert(1)\\x3c/script\\x3e

OWASP REFERENCES:
- OWASP Top 10: A03:2021 - Injection
- CWE-79: Improper Neutralization of Input During Web Page Generation
- OWASP XSS Prevention Cheat Sheet
- OWASP Testing Guide: Testing for Reflected XSS
- OWASP Testing Guide: Testing for Stored XSS
"""

