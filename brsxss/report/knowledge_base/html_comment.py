#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Modified
Telegram: https://t.me/easyprotech

Knowledge Base: HTML Comment Context
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in HTML Comment",
    
    "description": """
User input is reflected inside an HTML comment. While browsers don't execute scripts within comments, 
attackers can break out using comment terminators or exploit edge cases in HTML parsers. This is 
particularly dangerous in server-side templates, debugging information, or conditional comments.

SEVERITY: MEDIUM
Can lead to XSS if comment breakout is possible. Common in debugging code left in production.
""",

    "attack_vector": """
BASIC BREAKOUT:
<!-- USER_INPUT -->
Payload: --> <script>alert(1)</script> <!--
Result: <!-- --> <script>alert(1)</script> <!-- -->

IE CONDITIONAL COMMENTS:
<!--[if IE]><script>alert(1)</script><![endif]-->

POLYGLOT:
--!><svg/onload=alert(1)>

COMMENT CONFUSION:
Some parsers incorrectly handle --!> as terminator

SERVER-SIDE TEMPLATE COMMENTS:
May be evaluated before HTML rendering

NESTED COMMENTS:
Legacy parsers may have issues with nested comment structures
""",

    "remediation": """
DEFENSE:

1. NEVER PUT USER INPUT IN HTML COMMENTS
2. Remove or encode: --, -->, <
3. Use data attributes instead of comments for metadata
4. Strip comments in production builds
5. Implement CSP
6. Use structured logging instead of HTML comments

BEST PRACTICES:
- Use data-* attributes for metadata
- Use <script type="application/json"> for data
- Remove comments via build tools
- Validate that comments don't contain [if, [endif]

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- OWASP XSS Prevention Cheat Sheet
"""
}
