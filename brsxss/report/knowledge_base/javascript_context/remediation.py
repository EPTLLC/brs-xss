#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

JavaScript Context - Remediation
"""

REMEDIATION = """
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

