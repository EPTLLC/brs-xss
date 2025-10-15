#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Modified
Telegram: https://t.me/easyprotech

Knowledge Base: PostMessage XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting via PostMessage API",
    
    "description": """
The postMessage API enables cross-origin communication between windows. Vulnerabilities occur when 
applications receive postMessage data without validating the origin or sanitizing content before using 
it in dangerous contexts. Increasingly common in modern web applications using micro-frontends and 
third-party integrations.

SEVERITY: HIGH
Common in OAuth flows, embedded widgets, and cross-origin integrations.
""",

    "attack_vector": """
MISSING ORIGIN VALIDATION:
window.addEventListener('message', function(e) {
    element.innerHTML = e.data; // No origin check
});
Attacker sends: targetWindow.postMessage('<img src=x onerror=alert(1)>', '*');

WEAK ORIGIN CHECK:
if(e.origin.includes('trusted.com')) // Allows subtrusted.com or trusted.com.evil.com

USING DATA IN DANGEROUS SINKS:
eval(e.data)
document.write(e.data)
location.href = e.data
new Function(e.data)

REGEX BYPASS:
/^https?:\\/\\/trusted\\.com/.test(e.origin) // Can be bypassed

WILDCARD ORIGINS:
targetWindow.postMessage(data, '*') // Any origin can receive

JSON PARSING WITHOUT VALIDATION:
const obj = JSON.parse(e.data);
element.innerHTML = obj.html; // Unsafe

OAUTH TOKEN THEFT:
parent.postMessage(accessToken, '*'); // Leaks to any origin
""",

    "remediation": """
DEFENSE:

1. ALWAYS VALIDATE ORIGIN
   window.addEventListener('message', function(e) {
       if (e.origin !== 'https://trusted.com') {
           return; // Reject
       }
       processMessage(e.data);
   });

2. USE EXACT COMPARISON
   Never use: .includes(), .indexOf(), regex
   Always use: === for origin check

3. SANITIZE MESSAGE CONTENT
   Treat postMessage data as untrusted user input

4. NEVER USE IN DANGEROUS SINKS
   No: eval(), Function(), innerHTML, location.href

5. SPECIFY EXACT TARGET ORIGIN
   targetWindow.postMessage(data, 'https://exact-origin.com');
   Never: '*'

6. VALIDATE MESSAGE STRUCTURE
   Check message type, validate JSON schema

7. IMPLEMENT RATE LIMITING

8. USE CSP

9. MESSAGE SIGNING/ENCRYPTION
   For sensitive data

Example:
window.addEventListener('message', function(e) {
    // Validate origin
    if (e.origin !== 'https://trusted.com') {
        return;
    }
    
    // Validate message structure
    if (typeof e.data !== 'object' || !e.data.type) {
        return;
    }
    
    // Whitelist allowed message types
    const allowedTypes = ['update', 'refresh'];
    if (!allowedTypes.includes(e.data.type)) {
        return;
    }
    
    // Sanitize before use
    const sanitizedData = DOMPurify.sanitize(e.data.content);
    processMessage(sanitizedData);
});

TOOLS:
- Browser DevTools for monitoring postMessage
- Burp Suite for intercepting messages
- DOM Invader

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-940: Improper Verification of Source
- Web Messaging Security
"""
}
