#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

URL/URI Context - Remediation
"""

REMEDIATION = """
DEFENSE-IN-DEPTH STRATEGY:

1. STRICT URL VALIDATION:
   
   Protocol whitelist (most restrictive):
   allowed_protocols = ['http://', 'https://']
   
   Python:
   from urllib.parse import urlparse
   
   def is_safe_url(url):
       if not url:
           return False
       
       # Block javascript:, data:, etc.
       dangerous = ['javascript:', 'data:', 'vbscript:', 'file:', 'about:', 'blob:']
       url_lower = url.lower().replace(' ', '').replace('\\t', '').replace('\\n', '')
       
       for danger in dangerous:
           if danger in url_lower:
               return False
       
       # Validate structure
       try:
           parsed = urlparse(url)
           return parsed.scheme in ['http', 'https', 'mailto', 'tel']
       except:
           return False
   
   PHP:
   function isSafeURL($url) {
       $url = strtolower(preg_replace('/\\s+/', '', $url));
       
       $dangerous = ['javascript:', 'data:', 'vbscript:', 'file:', 'about:', 'blob:'];
       foreach ($dangerous as $danger) {
           if (strpos($url, $danger) !== false) {
               return false;
           }
       }
       
       $parsed = parse_url($url);
       return isset($parsed['scheme']) && 
              in_array($parsed['scheme'], ['http', 'https', 'mailto', 'tel']);
   }
   
   JavaScript:
   function isSafeURL(url) {
       try {
           const parsed = new URL(url, window.location.href);
           return ['http:', 'https:', 'mailto:', 'tel:'].includes(parsed.protocol);
       } catch {
           return false;
       }
   }

2. URL PARSING, NOT REGEX:
   
   BAD (Regex bypass possible):
   if (preg_match('/^https?:\\/\\//', $url)) { /* allowed */ }
   
   GOOD (Use URL parser):
   $parsed = parse_url($url);
   if ($parsed['scheme'] === 'https') { /* allowed */ }

3. ENCODE URL OUTPUT:
   
   HTML attribute context:
   <a href="<?php echo htmlspecialchars($url, ENT_QUOTES, 'UTF-8') ?>">
   
   JavaScript context:
   <script>
   var url = <?php echo json_encode($url) ?>;
   </script>

4. REL ATTRIBUTE PROTECTION:
   
   External links:
   <a href="<?php echo $url ?>" rel="noopener noreferrer">
   
   Prevents window.opener attacks

5. CONTENT SECURITY POLICY:
   
   Restrict protocols:
   Content-Security-Policy: 
     default-src 'self';
     script-src 'self';
     img-src 'self' https:;
     form-action 'self';
     frame-ancestors 'none';
     base-uri 'none';

6. DISABLE JAVASCRIPT PROTOCOL:
   
   Some frameworks:
   - React: Blocks javascript: by default in href
   - Angular: DomSanitizer blocks unsafe URLs
   - Vue: Auto-sanitizes href bindings

7. VALIDATE REDIRECT URLS:
   
   Whitelist domains:
   $allowed_domains = ['trusted.com', 'app.trusted.com'];
   $parsed = parse_url($redirect_url);
   
   if (!in_array($parsed['host'], $allowed_domains)) {
       die('Invalid redirect');
   }
   
   Or use allowlist pattern:
   if (!preg_match('/^https:\\/\\/([a-z]+\\.)?trusted\\.com\\//', $url)) {
       die('Invalid URL');
   }

8. REFERRER POLICY:
   
   Prevent referrer leakage:
   Referrer-Policy: no-referrer
   Referrer-Policy: strict-origin-when-cross-origin
   
   HTML:
   <meta name="referrer" content="no-referrer">

9. SUBRESOURCE INTEGRITY:
   
   For external scripts:
   <script src="https://cdn.example.com/lib.js"
           integrity="sha384-hash"
           crossorigin="anonymous">
   </script>

10. FRAMEWORK-SPECIFIC PROTECTION:
    
    React:
    <a href={userURL}>  {/* Auto-sanitized */}
    
    Vue:
    <a :href="userURL">  <!-- Sanitized -->
    
    Angular:
    import { DomSanitizer } from '@angular/platform-browser';
    
    constructor(private sanitizer: DomSanitizer) {}
    
    getSafeURL(url: string) {
        return this.sanitizer.sanitize(SecurityContext.URL, url);
    }

SECURITY CHECKLIST:

[ ] URL validation with protocol whitelist
[ ] URL parser used (not regex)
[ ] Dangerous protocols blocked (javascript:, data:, vbscript:)
[ ] URL encoding applied in output
[ ] rel="noopener noreferrer" on external links
[ ] CSP configured with form-action, base-uri
[ ] Redirect URLs validated against domain whitelist
[ ] Referrer-Policy header configured
[ ] SRI used for external resources
[ ] Framework auto-sanitization enabled
[ ] No user input in <base> tags
[ ] Meta refresh validated
[ ] Deep links validated in mobile apps
[ ] Regular security testing
[ ] Code review for all URL handling

TESTING PAYLOADS:

JavaScript protocol:
javascript:alert(1)
JaVaScRiPt:alert(1)
java\\tscript:alert(1)
jav&#x09;ascript:alert(1)

Data URI:
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

Encoding bypass:
javascript:%61lert(1)
j%61vascript:alert(1)

Protocol alternatives:
vbscript:msgbox(1)
file:///etc/passwd

Open redirect:
//evil.com
https://trusted.com@evil.com

TOOLS:
- URL Parser Test: https://url.spec.whatwg.org/
- CSP Evaluator: https://csp-evaluator.withgoogle.com/
- Burp Suite: URL fuzzing
- OWASP ZAP: Spider and scanner

OWASP REFERENCES:
- OWASP XSS Prevention Cheat Sheet: Rule #5
- OWASP Unvalidated Redirects and Forwards
- CWE-79: Cross-site Scripting
- CWE-601: URL Redirection to Untrusted Site
"""

