#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Modified
Telegram: https://t.me/easyprotech

Knowledge Base: JSON Value Context
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in JSON Context",
    
    "description": """
User input is embedded within JSON data that is later parsed and rendered by JavaScript. While JSON 
itself is safe, improper handling after parsing can lead to XSS. Common in REST APIs, AJAX responses, 
and modern SPA applications.

SEVERITY: HIGH
Very common in modern web applications. Often overlooked by developers.
""",

    "attack_vector": """
JSON PARSED THEN RENDERED UNSAFELY:
{\"name\": \"<img src=x onerror=alert(1)>\"}
If rendered via innerHTML

JSON IN SCRIPT TAG:
<script>var data = {\"value\": \"USER_INPUT\"}</script>
Payload: \"}; alert(1); var x={\"

JSON HIJACKING:
Attacker includes JSON in their page and accesses via <script src=...>

JSONP CALLBACK:
callback({\"data\": \"USER_INPUT\"})
Payload: \"}); alert(1); callback({\"data\": \"

UNICODE ESCAPES:
{\"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\"}

PROTOTYPE POLLUTION:
{\"__proto__\": {\"polluted\": true}}
""",

    "remediation": """
DEFENSE:

1. VALIDATE JSON STRUCTURE SERVER-SIDE
2. Use proper Content-Type: application/json
3. Parse with JSON.parse(), never eval()
4. Sanitize data AFTER parsing before DOM manipulation
5. Use textContent, not innerHTML for JSON values
6. Implement CSP
7. Validate and sanitize after parsing
8. Use CORS instead of JSONP

PHP:
json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

JavaScript:
const data = JSON.parse(response);
element.textContent = data.value; // Safe

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- OWASP JSON Security Cheat Sheet
"""
}
