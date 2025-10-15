#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Modified
Telegram: https://t.me/easyprotech

Knowledge Base: Markdown Context XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Markdown Rendering",
    
    "description": """
Many web applications allow users to input Markdown for rich text formatting. However, Markdown parsers 
often support raw HTML and JavaScript execution vectors. Different implementations have varying security 
properties. Improperly configured renderers can lead to stored XSS in comments, documentation, and wikis.

SEVERITY: HIGH
Very common in GitHub-style applications, forums, wikis, and comment systems.
""",

    "attack_vector": """
RAW HTML IN MARKDOWN:
[Click me](javascript:alert(1))
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

IMAGE TAGS WITH JAVASCRIPT:
![alt](javascript:alert(1))

IFRAME INJECTION:
<iframe src=javascript:alert(1)>

DATA URLS:
[link](data:text/html,<script>alert(1)</script>)

AUTOLINK ABUSE:
<javascript:alert(1)>

REFERENCE-STYLE LINKS:
[link][1]
[1]: javascript:alert(1)

HTML INJECTION IN CODE BLOCKS:
If parser doesn't properly escape

MUTATION XSS:
Payloads that look safe but become dangerous after parsing
""",

    "remediation": """
DEFENSE:

1. USE MARKDOWN PARSERS WITH SAFE DEFAULTS
   - markdown-it with html: false
   - marked with sanitize: true
   - CommonMark with HTML disabled

2. HTML SANITIZATION AFTER RENDERING
   Use DOMPurify, Bleach, or OWASP Java HTML Sanitizer

3. WHITELIST SAFE TAGS AND ATTRIBUTES
   Allow: <b>, <i>, <em>, <strong>, <a href>, <img src>
   Block: <script>, <iframe>, <object>, <embed>

4. URL PROTOCOL WHITELISTING
   Only allow: http://, https://, mailto:
   Block: javascript:, data:, vbscript:

5. USE REL ATTRIBUTES
   rel='nofollow noopener noreferrer' on all links

6. IMPLEMENT CSP

7. VALIDATE ON BOTH CLIENT AND SERVER

JavaScript (DOMPurify):
import DOMPurify from 'dompurify';
import marked from 'marked';
const html = marked(markdown);
const clean = DOMPurify.sanitize(html);

Python (Bleach):
import bleach
import markdown
html = markdown.markdown(text)
clean = bleach.clean(html,
    tags=['b', 'i', 'u', 'em', 'strong', 'a'],
    attributes={'a': ['href', 'title']},
    protocols=['http', 'https', 'mailto']
)

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- OWASP Markdown Security
"""
}
