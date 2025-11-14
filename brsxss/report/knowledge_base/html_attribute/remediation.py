#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

HTML Attribute Context - Remediation
"""

REMEDIATION = """
DEFENSE-IN-DEPTH STRATEGY:

1. ATTRIBUTE-SPECIFIC ENCODING:
   
   For general attributes (value, title, alt, etc.):
   - Encode: & < > " '
   - To: &amp; &lt; &gt; &quot; &#x27;
   
   Python:
   import html
   safe = html.escape(user_input, quote=True)
   
   PHP:
   $safe = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
   
   JavaScript:
   function escapeAttr(text) {
     return text
       .replace(/&/g, '&amp;')
       .replace(/</g, '&lt;')
       .replace(/>/g, '&gt;')
       .replace(/"/g, '&quot;')
       .replace(/'/g, '&#x27;');
   }

2. ALWAYS USE QUOTES:
   
   BAD (Unquoted):
   <input value=<?php echo $user_input ?>>
   
   GOOD (Double quoted):
   <input value="<?php echo htmlspecialchars($user_input, ENT_QUOTES) ?>">
   
   PREFER DOUBLE QUOTES over single quotes (consistency)

3. URL ATTRIBUTE VALIDATION:
   
   For href, src, action, formaction:
   
   Whitelist protocols:
   allowed = ['http://', 'https://', 'mailto:', 'tel:']
   
   Python:
   from urllib.parse import urlparse
   
   def is_safe_url(url):
       if not url:
           return False
       parsed = urlparse(url)
       return parsed.scheme in ['http', 'https', 'mailto', 'tel']
   
   if not is_safe_url(user_url):
       raise ValueError('Invalid URL')
   
   JavaScript:
   function isSafeURL(url) {
       try {
           const parsed = new URL(url, window.location.href);
           return ['http:', 'https:', 'mailto:', 'tel:'].includes(parsed.protocol);
       } catch {
           return false;
       }
   }

4. NEVER PLACE USER INPUT IN EVENT HANDLERS:
   
   BAD:
   <div onclick="<?php echo $user_input ?>">
   <button onclick="doSomething('<?php echo $user_input ?>')">
   
   GOOD:
   Use data attributes + addEventListener:
   <button id="myBtn" data-value="<?php echo htmlspecialchars($user_input) ?>">
   
   <script>
   document.getElementById('myBtn').addEventListener('click', function() {
       const value = this.dataset.value; // Safe
       doSomething(value);
   });
   </script>

5. CONTENT SECURITY POLICY:
   
   Restrict inline event handlers:
   Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'
   
   This blocks all inline event handlers (onclick, onload, etc.)

6. FRAMEWORK AUTO-ESCAPING:
   
   React (Safe for attributes):
   <input value={userInput} /> {/* Auto-escaped */}
   <a href={userHref}>{/* React validates URL */}</a>
   
   Vue:
   <input :value="userInput"> <!-- Auto-escaped -->
   <a :href="userHref"> <!-- Sanitized -->
   
   Angular:
   <input [value]="userInput"> <!-- Auto-escaped -->
   <a [href]="userHref"> <!-- Sanitized by DomSanitizer -->
   
   DANGEROUS:
   <div [attr.onclick]="userInput"> <!-- Don't do this -->

7. VALIDATE INPUT BEFORE OUTPUT:
   
   For expected formats:
   
   Email:
   /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/
   
   Phone:
   /^\\+?[0-9\\s\\-\\(\\)]{10,20}$/
   
   Username:
   /^[a-zA-Z0-9_-]{3,20}$/
   
   URL (basic):
   /^https?:\\/\\/.+/

8. USE SAFE APIS:
   
   Setting attributes safely:
   
   GOOD:
   element.setAttribute('title', userInput); // Auto-escaped
   element.dataset.value = userInput; // Safe
   element.value = userInput; // Safe for form inputs
   
   BAD:
   element.innerHTML = '<div title="' + userInput + '">'; // Dangerous
   element.outerHTML = userInput; // Dangerous

9. SANITIZE URLS:
   
   For href/src attributes:
   
   import { URL } from 'url';
   
   function sanitizeURL(url) {
       try {
           const parsed = new URL(url);
           if (!['http:', 'https:', 'mailto:', 'tel:'].includes(parsed.protocol)) {
               return '#'; // Safe fallback
           }
           return url;
       } catch {
           return '#'; // Invalid URL
       }
   }

10. HTTPONLY COOKIES:
    
    Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict
    
    Prevents JavaScript access even if XSS exists

SECURITY CHECKLIST:

[ ] All attributes use proper HTML encoding
[ ] All attributes are quoted (prefer double quotes)
[ ] URL attributes validated against protocol whitelist
[ ] No user input in event handler attributes
[ ] No user input in style attributes
[ ] Use data-* attributes + JavaScript instead of inline handlers
[ ] CSP configured to block inline event handlers
[ ] Framework auto-escaping enabled (not bypassed)
[ ] Input validation for expected formats
[ ] URL sanitization for href/src/action
[ ] HTTPOnly flag on session cookies
[ ] Regular security testing
[ ] Code review for all attribute usage
[ ] Use setAttribute() API, not string concatenation

TESTING PAYLOADS:

Basic breakout (double quotes):
" onfocus=alert(1) autofocus x="

Basic breakout (single quotes):
' onfocus=alert(1) autofocus x='

Unquoted:
x onfocus=alert(1) autofocus

URL injection:
javascript:alert(1)
data:text/html,<script>alert(1)</script>

Tag closing:
"><script>alert(1)</script><x x="

Encoding bypass:
&#34; onfocus=alert(1) autofocus x=&#34;

OWASP REFERENCES:
- OWASP XSS Prevention Cheat Sheet: Rule #2
- CWE-79: Improper Neutralization of Input During Web Page Generation
- OWASP Testing Guide: Testing for Reflected XSS
- HTML5 Security Cheatsheet: https://html5sec.org
"""

