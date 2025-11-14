#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

HTML Content Context - Description
"""

TITLE = "Cross-Site Scripting (XSS) in HTML Content"

METADATA = {
    "severity": "critical",
    "cvss_score": 8.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "html", "reflected", "stored", "injection"],
}

DESCRIPTION = """
User input is reflected directly into the HTML body without proper sanitization. This is the most 
straightforward and dangerous XSS vector, allowing injection of arbitrary HTML elements, scripts, 
and interactive content. It's the primary target for stored/persistent XSS attacks and can lead to 
complete account takeover, credential theft, and malware distribution.

VULNERABILITY CONTEXT:
When user-controlled data is inserted between HTML tags without encoding, attackers can inject 
their own HTML markup including script tags, event handlers, iframes, and other active content.
This is common in:
- Comment systems
- User profiles (bio, username display)
- Blog posts and articles
- Forum threads
- Chat messages
- Product reviews
- Wiki pages
- Email web clients
- CMS content
- Search result pages

SEVERITY: CRITICAL
This vulnerability consistently ranks in OWASP Top 10 and is the foundation for most XSS attacks.
"""

