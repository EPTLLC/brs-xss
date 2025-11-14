#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

JavaScript Object Context - Remediation
"""

REMEDIATION = """
DEFENSE-IN-DEPTH STRATEGY:

1. NEVER PLACE UNTRUSTED INPUT IN OBJECT LITERALS:
   
   BAD:
   <script>
   var config = {adminMode: <?php echo $user_input ?>};
   </script>
   
   GOOD - Use JSON with validation:
   <script>
   var config = JSON.parse('<?php echo json_encode($config, JSON_HEX_TAG) ?>');
   </script>

2. SAFE JSON SERIALIZATION:
   
   Python:
   import json
   <script>
   var config = {{ config_dict | tojson | safe }};
   </script>
   
   PHP with flags:
   $json = json_encode($data, 
       JSON_HEX_TAG | 
       JSON_HEX_AMP | 
       JSON_HEX_APOS | 
       JSON_HEX_QUOT | 
       JSON_THROW_ON_ERROR
   );
   <script>var config = <?php echo $json ?>;</script>
   
   Node.js:
   const serialize = require('serialize-javascript');
   const safeData = serialize(data, {isJSON: true});

3. PROTOTYPE POLLUTION PROTECTION:
   
   Use Object.create(null) for maps:
   const safeMap = Object.create(null);
   safeMap.key = value; // No prototype chain
   
   Freeze Object.prototype:
   Object.freeze(Object.prototype);
   Object.freeze(Object);
   
   Validate keys before assignment:
   function safeAssign(target, source) {
       for (let key in source) {
           if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
               continue; // Skip dangerous keys
           }
           if (source.hasOwnProperty(key)) {
               target[key] = source[key];
           }
       }
   }
   
   Use Map instead of objects:
   const config = new Map();
   config.set(userKey, userValue); // No prototype pollution

4. SECURE MERGE/EXTEND:
   
   Safe merge implementation:
   function safeMerge(target, source) {
       if (typeof source !== 'object' || source === null) {
           return target;
       }
       
       for (let key in source) {
           // Reject dangerous keys
           if (['__proto__', 'constructor', 'prototype'].includes(key)) {
               continue;
           }
           
           if (source.hasOwnProperty(key)) {
               if (typeof source[key] === 'object' && source[key] !== null) {
                   target[key] = safeMerge(target[key] || {}, source[key]);
               } else {
                   target[key] = source[key];
               }
           }
       }
       return target;
   }
   
   Or use libraries with patches:
   - lodash >= 4.17.21
   - jQuery >= 3.5.0
   - hoek >= 9.0.0

5. JSON.PARSE WITH REVIVER:
   
   Block dangerous keys:
   function safeReviver(key, value) {
       const blocked = ['__proto__', 'constructor', 'prototype'];
       if (blocked.includes(key)) {
           return undefined; // Remove dangerous keys
       }
       return value;
   }
   
   const obj = JSON.parse(userInput, safeReviver);

6. VALIDATE OBJECT STRUCTURE:
   
   Use JSON Schema:
   const Ajv = require('ajv');
   const ajv = new Ajv();
   
   const schema = {
       type: 'object',
       properties: {
           username: {type: 'string', pattern: '^[a-zA-Z0-9_-]+$'},
           age: {type: 'integer', minimum: 0, maximum: 150}
       },
       required: ['username', 'age'],
       additionalProperties: false // Reject unknown properties
   };
   
   const validate = ajv.compile(schema);
   if (!validate(userInput)) {
       throw new Error('Invalid data structure');
   }

7. CONTENT SECURITY POLICY:
   
   Block inline scripts and eval:
   Content-Security-Policy: 
     default-src 'self';
     script-src 'self' 'nonce-RANDOM';
     object-src 'none';
   
   Prevents execution even if object pollution succeeds

8. USE TYPESCRIPT FOR TYPE SAFETY:
   
   interface Config {
       readonly apiKey: string;
       readonly timeout: number;
   }
   
   function processConfig(config: Config) {
       // TypeScript ensures only expected properties
   }

9. PREVENT PROPERTY ACCESS:
   
   Use hasOwnProperty:
   if (obj.hasOwnProperty(key)) {
       value = obj[key]; // Safe
   }
   
   Or Object.hasOwn (modern):
   if (Object.hasOwn(obj, key)) {
       value = obj[key];
   }

10. FRAMEWORK-SPECIFIC PROTECTION:
    
    Update vulnerable libraries:
    npm audit fix
    npm update lodash jquery hoek minimist
    
    Use safe alternatives:
    - Instead of _.merge: use _.mergeWith with guard
    - Instead of $.extend: use Object.assign with validation
    - Instead of minimist: use yargs with schema

SECURITY CHECKLIST:

[ ] No user input directly in object literals
[ ] JSON serialization uses proper encoding flags
[ ] Object.create(null) used for user-controlled maps
[ ] Prototype pollution protection implemented
[ ] Dangerous keys (__proto__, constructor) filtered
[ ] Libraries updated (lodash, jQuery, etc.)
[ ] JSON Schema validation for structure
[ ] TypeScript for type safety (if applicable)
[ ] hasOwnProperty checks before property access
[ ] Map used instead of objects for user data
[ ] CSP configured to block inline scripts
[ ] Regular security audits (npm audit, Snyk)
[ ] Code review for all object manipulation
[ ] Penetration testing for prototype pollution

TESTING PAYLOADS:

Property injection:
true, exploit: alert(1), real: false

Prototype pollution:
{"__proto__": {"polluted": true}}
{"constructor": {"prototype": {"polluted": true}}}

String breakout:
', admin: true, real: '

Getter injection:
{get value(){alert(1); return 1}}

Breakout:
null}; alert(1); var x = {value: null

Computed property:
alert(1)

TOOLS FOR DETECTION:
- ppmap: Prototype Pollution scanner
- npm audit: Detects vulnerable dependencies
- Snyk: Security scanning
- ESLint security plugins
- SonarQube: Static analysis

CVE REFERENCES:
- CVE-2019-10744: lodash prototype pollution
- CVE-2019-11358: jQuery prototype pollution
- CVE-2020-7598: minimist prototype pollution
- CVE-2018-3721: hoek prototype pollution
- CVE-2021-23337: lodash command injection

OWASP REFERENCES:
- OWASP Prototype Pollution
- CWE-1321: Improperly Controlled Modification of Object Prototype
- CWE-79: Cross-site Scripting (XSS)
"""

